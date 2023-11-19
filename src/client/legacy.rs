//! hyper-util legacy client support.
use crate::client::cache::{SessionCache, SessionKey};
use crate::SslStream;
use http::uri::Scheme;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use once_cell::sync::OnceCell;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{
    self, ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslMethod,
    SslSessionCacheMode,
};
use openssl::x509::X509VerifyResult;
use parking_lot::Mutex;
use pin_project::pin_project;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};
use tower_layer::Layer;
use tower_service::Service;

type ConfigureCallback =
    dyn Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send;

fn key_index() -> Result<Index<Ssl, SessionKey>, ErrorStack> {
    static IDX: OnceCell<Index<Ssl, SessionKey>> = OnceCell::new();
    IDX.get_or_try_init(Ssl::new_ex_index).copied()
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Arc<Mutex<SessionCache>>,
    callback: Option<Arc<ConfigureCallback>>,
}

/// A [`Layer`] which wraps services in an `HttpsConnector`.
pub struct HttpsLayer {
    inner: Inner,
}

impl HttpsLayer {
    /// Creates a new `HttpsLayer` with default settings.
    ///
    /// ALPN is configured to support both HTTP/1.1 and HTTP/2.
    pub fn new() -> Result<Self, ErrorStack> {
        let mut ssl = SslConnector::builder(SslMethod::tls())?;

        #[cfg(ossl102)]
        ssl.set_alpn_protos(b"\x02h2\x08http/1.1")?;

        Self::with_connector(ssl)
    }

    /// Creates a new `HttpsLayer`.
    ///
    /// The session cache configuration of `ssl` will be overwritten.
    pub fn with_connector(mut ssl: SslConnectorBuilder) -> Result<Self, ErrorStack> {
        let cache = Arc::new(Mutex::new(SessionCache::new()));

        ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        ssl.set_new_session_callback({
            let cache = cache.clone();
            move |ssl, session| {
                if let Some(key) = key_index().ok().and_then(|idx| ssl.ex_data(idx)) {
                    cache.lock().insert(key.clone(), session);
                }
            }
        });

        ssl.set_remove_session_callback({
            let cache = cache.clone();
            move |_, session| cache.lock().remove(session)
        });

        Ok(HttpsLayer {
            inner: Inner {
                ssl: ssl.build(),
                cache,
                callback: None,
            },
        })
    }

    /// Registers a callback which can customize the configuration of each connection.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<S> Layer<S> for HttpsLayer {
    type Service = HttpsConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpsConnector {
            http: inner,
            inner: self.inner.clone(),
        }
    }
}

/// A Connector using OpenSSL supporting `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

impl HttpsConnector<HttpConnector> {
    /// Creates a new `HttpsConnector` using default settings.
    ///
    /// The Hyper [`HttpConnector`] is used to perform the TCP socket connection. ALPN is configured to support both
    /// HTTP/1.1 and HTTP/2.
    pub fn new() -> Result<Self, ErrorStack> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        HttpsLayer::new().map(|l| l.layer(http))
    }
}

impl<S> HttpsConnector<S> {
    /// Creates a new `HttpsConnector`.
    ///
    /// The session cache configuration of `ssl` will be overwritten.
    pub fn with_connector(http: S, ssl: SslConnectorBuilder) -> Result<Self, ErrorStack> {
        HttpsLayer::with_connector(ssl).map(|l| l.layer(http))
    }

    /// Registers a callback which can customize the configuration of each connection.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri>,
    S::Future: 'static + Send,
    S::Error: Into<Box<dyn Error + Sync + Send>>,
    S::Response: Read + Write + Unpin + Connection + Send,
{
    type Response = MaybeHttpsStream<S::Response>;
    type Error = Box<dyn Error + Sync + Send>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let tls_setup = if req.scheme() == Some(&Scheme::HTTPS) {
            Some((self.inner.clone(), req.clone()))
        } else {
            None
        };

        let connect = self.http.call(req);

        Box::pin(async move {
            let conn = connect.await.map_err(Into::into)?;

            let Some((inner, uri)) = tls_setup else {
                return Ok(MaybeHttpsStream::Http(conn))
            };

            let Some(host) = uri.host() else {
                return Err("URI missing host".into());
            };

            let mut config = inner.ssl.configure()?;

            if let Some(callback) = &inner.callback {
                callback(&mut config, &uri)?;
            }

            let key = SessionKey {
                host: host.to_string(),
                port: uri.port_u16().unwrap_or(443),
            };

            if let Some(session) = inner.cache.lock().get(&key) {
                unsafe {
                    config.set_session(&session)?;
                }
            }

            let idx = key_index()?;
            config.set_ex_data(idx, key);

            let ssl = config.into_ssl(host)?;

            let mut stream = SslStream::new(ssl, conn)?;

            match Pin::new(&mut stream).connect().await {
                Ok(()) => Ok(MaybeHttpsStream::Https(stream)),
                Err(error) => Err(Box::new(ConnectError {
                    error,
                    verify_result: stream.ssl().verify_result(),
                }) as _),
            }
        })
    }
}

#[derive(Debug)]
struct ConnectError {
    error: ssl::Error,
    verify_result: X509VerifyResult,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, fmt)?;

        if self.verify_result != X509VerifyResult::OK {
            fmt.write_str(": ")?;
            fmt::Display::fmt(&self.verify_result, fmt)?;
        }

        Ok(())
    }
}

impl Error for ConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// A stream which may be wrapped with TLS.
#[pin_project(project = MaybeHttpsStreamProj)]
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(#[pin] T),
    /// A TLS-wrapped HTTP stream.
    Https(#[pin] SslStream<T>),
}

impl<T> Read for MaybeHttpsStream<T>
where
    T: Read + Write,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project() {
            MaybeHttpsStreamProj::Http(s) => s.poll_read(cx, buf),
            MaybeHttpsStreamProj::Https(s) => s.poll_read(cx, buf),
        }
    }
}

impl<T> Write for MaybeHttpsStream<T>
where
    T: Read + Write,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            MaybeHttpsStreamProj::Http(s) => s.poll_write(cx, buf),
            MaybeHttpsStreamProj::Https(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            MaybeHttpsStreamProj::Http(s) => s.poll_flush(cx),
            MaybeHttpsStreamProj::Https(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            MaybeHttpsStreamProj::Http(s) => s.poll_shutdown(cx),
            MaybeHttpsStreamProj::Https(s) => s.poll_shutdown(cx),
        }
    }
}

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => {
                let mut connected = s.get_ref().connected();
                #[cfg(ossl102)]
                if s.ssl().selected_alpn_protocol() == Some(b"h2") {
                    connected = connected.negotiated_h2();
                }
                connected
            }
        }
    }
}
