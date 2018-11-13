//! Hyper SSL support via OpenSSL.
#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/hyper-openssl/0.6")]

extern crate antidote;
extern crate bytes;
extern crate futures;
extern crate hyper;
extern crate linked_hash_set;
pub extern crate openssl;
extern crate tokio_io;
extern crate tokio_openssl;

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
extern crate tokio;

use antidote::Mutex;
use bytes::{Buf, BufMut};
use futures::{Async, Future, Poll};
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
use std::io::{self, Read, Write};
use std::mem;
use std::sync::Arc;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_openssl::{ConnectAsync, ConnectConfigurationExt, SslStream};

use cache::{SessionCache, SessionKey};

mod cache;
#[cfg(test)]
mod test;

lazy_static! {
    // The unwrap here isn't great but this only fails on OOM
    static ref KEY_INDEX: Index<Ssl, SessionKey> = Ssl::new_ex_index().unwrap();
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    session_cache: Arc<Mutex<SessionCache>>,
    callback: Option<
        Arc<Fn(&mut ConnectConfiguration, &Destination) -> Result<(), ErrorStack> + Sync + Send>,
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

        if let Some(session) = self.session_cache.lock().get(&key) {
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

        #[cfg(ossl102)]
        ssl.set_alpn_protos(b"\x02h2\x08http/1.1")?;

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
        let session_cache = Arc::new(Mutex::new(SessionCache::new()));

        ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        let cache = session_cache.clone();
        ssl.set_new_session_callback(move |ssl, session| {
            if let Some(key) = ssl.ex_data(*KEY_INDEX) {
                cache.lock().insert(key.clone(), session);
            }
        });

        let cache = session_cache.clone();
        ssl.set_remove_session_callback(move |_, session| cache.lock().remove(session));

        Ok(HttpsConnector {
            http,
            inner: Inner {
                ssl: ssl.build(),
                session_cache,
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
    T::Transport: Debug + Sync + Send,
{
    type Transport = MaybeHttpsStream<T::Transport>;
    type Error = Box<Error + Sync + Send>;
    type Future = ConnectFuture<T>;

    fn connect(&self, destination: Destination) -> ConnectFuture<T> {
        let tls_setup = if destination.scheme() == "https" {
            Some((self.inner.clone(), destination.clone()))
        } else {
            None
        };

        let conn = self.http.connect(destination);

        ConnectFuture(ConnectState::InnerConnect { conn, tls_setup })
    }
}

enum ConnectState<T>
where
    T: Connect,
{
    InnerConnect {
        conn: T::Future,
        tls_setup: Option<(Inner, Destination)>,
    },
    Handshake {
        handshake: ConnectAsync<T::Transport>,
        connected: Connected,
    },
    Terminal,
}

/// A future connecting to a remote HTTP server.
pub struct ConnectFuture<T>(ConnectState<T>)
where
    T: Connect;

impl<T> Future for ConnectFuture<T>
where
    T: Connect,
    T::Transport: Debug + Sync + Send,
{
    type Item = (MaybeHttpsStream<T::Transport>, Connected);
    type Error = Box<Error + Sync + Send>;

    fn poll(
        &mut self,
    ) -> Poll<(MaybeHttpsStream<T::Transport>, Connected), Box<Error + Sync + Send>> {
        loop {
            match mem::replace(&mut self.0, ConnectState::Terminal) {
                ConnectState::InnerConnect {
                    mut conn,
                    tls_setup,
                } => match conn.poll() {
                    Ok(Async::Ready((stream, connected))) => match tls_setup {
                        Some((inner, destination)) => {
                            let ssl = inner.setup_ssl(&destination)?;
                            let handshake = ssl.connect_async(destination.host(), stream);
                            self.0 = ConnectState::Handshake {
                                handshake,
                                connected,
                            };
                        }
                        None => {
                            return Ok(Async::Ready((MaybeHttpsStream::Http(stream), connected)))
                        }
                    },
                    Ok(Async::NotReady) => {
                        self.0 = ConnectState::InnerConnect { conn, tls_setup };
                        return Ok(Async::NotReady);
                    }
                    Err(e) => return Err(e.into()),
                },
                ConnectState::Handshake {
                    mut handshake,
                    mut connected,
                } => match handshake.poll() {
                    Ok(Async::Ready(stream)) => {
                        // avoid unused_mut warnings on OpenSSL 1.0.1
                        connected = connected;

                        #[cfg(ossl102)]
                        {
                            if let Some(b"h2") = stream.get_ref().ssl().selected_alpn_protocol() {
                                connected = connected.negotiated_h2();
                            }
                        }
                        return Ok(Async::Ready((MaybeHttpsStream::Https(stream), connected)));
                    }
                    Ok(Async::NotReady) => {
                        self.0 = ConnectState::Handshake {
                            handshake,
                            connected,
                        };
                        return Ok(Async::NotReady);
                    }
                    Err(e) => return Err(e.into()),
                },
                ConnectState::Terminal => panic!("future polled after completion"),
            };
        }
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

impl<T> Read for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.read(buf),
            MaybeHttpsStream::Https(ref mut s) => s.read(buf),
        }
    }
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match *self {
            MaybeHttpsStream::Http(ref s) => s.prepare_uninitialized_buffer(buf),
            MaybeHttpsStream::Https(ref s) => s.prepare_uninitialized_buffer(buf),
        }
    }

    fn read_buf<B>(&mut self, buf: &mut B) -> Poll<usize, io::Error>
    where
        B: BufMut,
    {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.read_buf(buf),
            MaybeHttpsStream::Https(ref mut s) => s.read_buf(buf),
        }
    }
}

impl<T> Write for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.write(buf),
            MaybeHttpsStream::Https(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.flush(),
            MaybeHttpsStream::Https(ref mut s) => s.flush(),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.shutdown(),
            MaybeHttpsStream::Https(ref mut s) => s.shutdown(),
        }
    }

    fn write_buf<B>(&mut self, buf: &mut B) -> Poll<usize, io::Error>
    where
        B: Buf,
    {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => s.write_buf(buf),
            MaybeHttpsStream::Https(ref mut s) => s.write_buf(buf),
        }
    }
}
