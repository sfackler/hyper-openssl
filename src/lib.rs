//! Hyper SSL support via OpenSSL.
#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/hyper-openssl/0.4")]

extern crate antidote;
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
use std::io::{self, Read, Write};
use std::mem;
use std::sync::Arc;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_openssl::{ConnectAsync, ConnectConfigurationExt, SslStream};

use cache::{SessionCache, SessionKey};

mod cache;

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

/// An Connector using OpenSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

#[cfg(feature = "runtime")]
impl HttpsConnector<HttpConnector> {
    /// Creates a a new `HttpsConnector` using default settings.
    ///
    /// The Hyper `HttpConnector` is used to perform the TCP socket connection.
    ///
    /// Requires the `runtime` Cargo feature.
    pub fn new(threads: usize) -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let mut http = HttpConnector::new(threads);
        http.enforce_http(false);
        let ssl = SslConnector::builder(SslMethod::tls())?;
        HttpsConnector::with_connector(http, ssl)
    }
}

impl<T> HttpsConnector<T>
where
    T: Connect,
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
    ///
    /// It is provided with a reference to the `ConnectConfiguration` as well as the URI.
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

        ConnectFuture(ConnectState::InnerConnect {
            conn,
            tls_setup,
        })
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
{
    type Item = (MaybeHttpsStream<T::Transport>, Connected);
    type Error = Box<Error + Sync + Send>;

    fn poll(
        &mut self,
    ) -> Poll<(MaybeHttpsStream<T::Transport>, Connected), Box<Error + Sync + Send>> {
        loop {
            match mem::replace(&mut self.0, ConnectState::Terminal) {
                ConnectState::InnerConnect { mut conn, tls_setup } => match conn.poll() {
                    Ok(Async::Ready((stream, connected))) => match tls_setup {
                        Some((inner, destination)) => {
                            let ssl = inner.setup_ssl(&destination)?;
                            let handshake = ssl.connect_async(destination.host(), stream);
                            self.0 = ConnectState::Handshake { handshake, connected };
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
                ConnectState::Handshake { mut handshake, connected } => match handshake.poll() {
                    Ok(Async::Ready(stream)) => {
                        return Ok(Async::Ready((MaybeHttpsStream::Https(stream), connected)))
                    }
                    Ok(Async::NotReady) => {
                        self.0 = ConnectState::Handshake { handshake, connected };
                        return Ok(Async::NotReady);
                    }
                    Err(e) => return Err(e.into()),
                },
                ConnectState::Terminal => panic!("future polled after completion"),
            };
        }
    }
}

/// A stream which may be wrapped with SSL.
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
}

#[cfg(test)]
mod test {
    use futures::stream::Stream;
    use hyper::client::HttpConnector;
    use hyper::{Body, Client};
    use openssl::ssl::{SslContext, SslFiletype, SslMethod};
    use std::net::TcpListener;
    use std::thread;
    use tokio::runtime::current_thread::Runtime;

    use super::*;

    #[test]
    #[cfg(feature = "runtime")]
    fn google() {
        let ssl = HttpsConnector::new(4).unwrap();
        let client = Client::builder().keep_alive(false).build::<_, Body>(ssl);

        let mut runtime = Runtime::new().unwrap();

        let f = client
            .get("https://www.google.com".parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.into_body().for_each(|_| Ok(()))
            });
        runtime.block_on(f).unwrap();

        let f = client
            .get("https://www.google.com".parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.into_body().for_each(|_| Ok(()))
            });
        runtime.block_on(f).unwrap();

        let f = client
            .get("https://www.google.com".parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.into_body().for_each(|_| Ok(()))
            });
        runtime.block_on(f).unwrap();
    }

    #[test]
    fn localhost() {
        let listener = TcpListener::bind("127.0.0.1:15410").unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_session_id_context(b"test").unwrap();
        ctx.set_certificate_chain_file("test/cert.pem").unwrap();
        ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        let ctx = ctx.build();

        let thread = thread::spawn(move || {
            let stream = listener.accept().unwrap().0;
            let ssl = Ssl::new(&ctx).unwrap();
            let mut stream = ssl.accept(stream).unwrap();
            stream.read_exact(&mut [0]).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.shutdown().unwrap();
            drop(stream);

            let stream = listener.accept().unwrap().0;
            let ssl = Ssl::new(&ctx).unwrap();
            let mut stream = ssl.accept(stream).unwrap();
            stream.read_exact(&mut [0]).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.shutdown().unwrap();
            drop(stream);

            let stream = listener.accept().unwrap().0;
            let ssl = Ssl::new(&ctx).unwrap();
            let mut stream = ssl.accept(stream).unwrap();
            stream.read_exact(&mut [0]).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.shutdown().unwrap();
            drop(stream);
        });

        let mut connector = HttpConnector::new(1);
        connector.enforce_http(false);
        let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
        ssl.set_ca_file("test/cert.pem").unwrap();

        #[cfg(ossl111)]
        {
            use std::fs::File;
            use std::io::Write;

            let file = File::create("target/keyfile.log").unwrap();
            ssl.set_keylog_callback(move |_, line| {
                let _ = writeln!(&file, "{}", line);
            });
        }

        let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
        let client = Client::builder().build::<_, Body>(ssl);

        let mut runtime = Runtime::new().unwrap();

        let f = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.into_body().for_each(|_| Ok(()))
            });
        runtime.block_on(f).unwrap();

        let f = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.into_body().for_each(|_| Ok(()))
            });
        runtime.block_on(f).unwrap();

        let f = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.into_body().for_each(|_| Ok(()))
            });
        runtime.block_on(f).unwrap();

        thread.join().unwrap();
    }
}
