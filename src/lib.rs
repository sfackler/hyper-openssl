//! Hyper SSL support via OpenSSL.
#![feature(async_await)]
#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/hyper-openssl/0.7")]

use antidote::Mutex;
use bytes::{Buf, BufMut};
use hyper::client::connect::{Connect, Connected, Destination};
#[cfg(feature = "runtime")]
use hyper::client::HttpConnector;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{
    ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslMethod, SslSessionCacheMode,
};
use std::error::Error;
use std::fmt::Debug;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream;

use cache::{SessionCache, SessionKey};
use std::future::Future;
use std::pin::Pin;
use std::task::{Poll, Context};

mod cache;
#[cfg(test)]
mod test;

lazy_static::lazy_static! {
    // The unwrap here isn't great but this only fails on OOM
    static ref KEY_INDEX: Index<Ssl, SessionKey> = Ssl::new_ex_index().unwrap();
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Arc<Mutex<SessionCache>>,
    callback: Option<
        Arc<dyn Fn(&mut ConnectConfiguration, &Destination) -> Result<(), ErrorStack> + Sync + Send>,
    >,
}

impl Inner {
    fn setup_ssl(&self, destination: &Destination) -> Result<ConnectConfiguration, ErrorStack> {
        let mut conf = self.ssl.configure()?;

        if let Some(ref callback) = self.callback {
            callback(&mut conf, destination)?;
        }

        let key = SessionKey {
            host: destination.host().to_string(),
            port: destination.port().unwrap_or(443),
        };

        if let Some(session) = self.cache.lock().get(&key) {
            unsafe {
                conf.set_session(&session)?;
            }
        }

        conf.set_ex_data(*KEY_INDEX, key);

        Ok(conf)
    }
}

/// A Connector using OpenSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

#[cfg(feature = "runtime")]
impl HttpsConnector<HttpConnector> {
    /// Creates a a new `HttpsConnector` using default settings.
    ///
    /// The Hyper `HttpConnector` is used to perform the TCP socket connection. ALPN is configured to support both
    /// HTTP/2 and HTTP/1.1.
    ///
    /// Requires the `runtime` Cargo feature.
    pub fn new(threads: usize) -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let mut http = HttpConnector::new(threads);
        http.enforce_http(false);
        let mut ssl = SslConnector::builder(SslMethod::tls())?;
        // avoid unused_mut warnings when building against OpenSSL 1.0.1
        ssl = ssl;

        // FIXME reenable when h2 is updated
        /*
        #[cfg(ossl102)]
        ssl.set_alpn_protos(b"\x02h2\x08http/1.1")?;
        */

        HttpsConnector::with_connector(http, ssl)
    }
}

impl<T> HttpsConnector<T>
where
    T: Connect,
    T::Transport: Debug + Sync + Send,
{
    /// Creates a new `HttpsConnector`.
    ///
    /// The session cache configuration of `ssl` will be overwritten.
    pub fn with_connector(
        http: T,
        mut ssl: SslConnectorBuilder,
    ) -> Result<HttpsConnector<T>, ErrorStack> {
        let cache = Arc::new(Mutex::new(SessionCache::new()));

        ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        ssl.set_new_session_callback({
            let cache = cache.clone();
            move |ssl, session| {
                if let Some(key) = ssl.ex_data(*KEY_INDEX) {
                    cache.lock().insert(key.clone(), session);
                }
            }
        });

        ssl.set_remove_session_callback({
            let cache = cache.clone();
            move |_, session| cache.lock().remove(session)
        });

        Ok(HttpsConnector {
            http,
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
        F: Fn(&mut ConnectConfiguration, &Destination) -> Result<(), ErrorStack>
            + 'static
            + Sync
            + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<T> Connect for HttpsConnector<T>
where
    T: Connect,
    T::Transport: Debug + Sync,
    T::Future: 'static,
{
    type Transport = MaybeHttpsStream<T::Transport>;
    type Error = Box<dyn Error + Sync + Send>;
    type Future =
        Pin<Box<dyn Future<Output = Result<(Self::Transport, Connected), Self::Error>> + Send>>;

    fn connect(&self, destination: Destination) -> Self::Future {
        let tls_setup = if destination.scheme() == "https" {
            Some((self.inner.clone(), destination.clone()))
        } else {
            None
        };

        let connect = self.http.connect(destination);

        let f = async {
            let (conn, mut connected) = connect.await.map_err(Into::into)?;

            let (inner, destination) = match tls_setup {
                Some((inner, destination)) => (inner, destination),
                None => return Ok((MaybeHttpsStream::Http(conn), connected)),
            };

            let config = inner.setup_ssl(&destination)?;
            let stream = tokio_openssl::connect(config, destination.host(), conn).await?;

            // Avoid unused_mut warnings on OpenSSL 1.0.1
            connected = connected;
            #[cfg(ossl102)]
            {
                if let Some(b"h2") = stream.ssl().selected_alpn_protocol() {
                    connected = connected.negotiated_h2();
                }
            }

            Ok((MaybeHttpsStream::Https(stream), connected))
        };

        Box::pin(f)
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match &*self {
            MaybeHttpsStream::Http(s) => s.prepare_uninitialized_buffer(buf),
            MaybeHttpsStream::Https(s) => s.prepare_uninitialized_buffer(buf),
        }
    }

    fn poll_read(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read(ctx, buf),
        }
    }

    fn poll_read_buf<B>(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut B) -> Poll<io::Result<usize>>
    where
        B: BufMut,
    {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read_buf(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read_buf(ctx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write(ctx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_flush(ctx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_shutdown(ctx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_shutdown(ctx),
        }
    }

    fn poll_write_buf<B>(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut B) -> Poll<io::Result<usize>>
    where
        B: Buf,
    {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write_buf(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write_buf(ctx, buf),
        }
    }
}
