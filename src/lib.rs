//! Hyper SSL support via OpenSSL.
//!
//! # Usage
//!
//! On the client side:
//!
//! ```
//! extern crate hyper;
//! extern crate hyper_openssl;
//! extern crate tokio_core;
//!
//! use hyper::Client;
//! use hyper_openssl::HttpsConnector;
//! use tokio_core::reactor::Core;
//!
//! fn main() {
//!     let mut core = Core::new().unwrap();
//!
//!     let client = Client::configure()
//!         .connector(HttpsConnector::new(4, &core.handle()).unwrap())
//!         .build(&core.handle());
//!
//!     let res = core.run(client.get("https://hyper.rs".parse().unwrap())).unwrap();
//!     assert!(res.status().is_success());
//! }
//! ```
#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/hyper-openssl/0.4")]

extern crate antidote;
extern crate futures;
extern crate hyper;
extern crate linked_hash_set;
pub extern crate openssl;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;
extern crate tokio_service;

#[macro_use]
extern crate lazy_static;

use antidote::Mutex;
use futures::{Future, Poll};
use futures::future;
use hyper::client::{Connect, HttpConnector};
use hyper::Uri;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslMethod,
                   SslSessionCacheMode};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_openssl::{ConnectConfigurationExt, SslStream};
use tokio_service::Service;

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
    callback:
        Option<Arc<Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + Sync + Send>>,
}

impl Inner {
    fn connect<S>(
        self,
        uri: Uri,
        stream: S,
    ) -> Box<Future<Item = MaybeHttpsStream<S>, Error = io::Error>>
    where
        S: 'static + AsyncRead + AsyncWrite,
    {
        let host = match uri.host() {
            Some(host) => host,
            None => {
                return Box::new(future::err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid url, missing host",
                )))
            }
        };

        let mut conf = match self.ssl.configure() {
            Ok(conf) => conf,
            Err(e) => return Box::new(future::err(io::Error::new(io::ErrorKind::Other, e))),
        };

        if let Some(ref callback) = self.callback {
            if let Err(e) = callback(&mut conf, &uri) {
                return Box::new(future::err(io::Error::new(io::ErrorKind::Other, e)));
            }
        }

        let key = SessionKey {
            host: host.to_owned(),
            port: uri.port().unwrap_or(443),
        };

        if let Some(session) = self.session_cache.lock().get(&key) {
            if let Err(e) = unsafe { conf.set_session(&session) } {
                return Box::new(future::err(io::Error::new(io::ErrorKind::Other, e)));
            }
        }

        conf.set_ex_data(*KEY_INDEX, key);

        let f = conf.connect_async(host, stream)
            .map(MaybeHttpsStream::Https)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        Box::new(f)
    }
}

/// An Connector using OpenSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

impl HttpsConnector<HttpConnector> {
    /// Creates a new `HttpsConnector` with default settings and using the
    /// standard Hyper `HttpConnector`.
    pub fn new(
        threads: usize,
        handle: &Handle,
    ) -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let mut http = HttpConnector::new(threads, handle);
        http.enforce_http(false);
        let ssl = SslConnector::builder(SslMethod::tls())?;
        Ok(HttpsConnector::with_connector(http, ssl))
    }
}

impl<T> HttpsConnector<T>
where
    T: Connect,
{
    /// Creates a new `HttpsConnector`.
    ///
    /// The session cache configuration of `ssl` will be overwritten.
    pub fn with_connector(http: T, mut ssl: SslConnectorBuilder) -> HttpsConnector<T> {
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

        HttpsConnector {
            http,
            inner: Inner {
                ssl: ssl.build(),
                session_cache,
                callback: None,
            },
        }
    }

    /// Registers a callback which can customize the configuration of each connection.
    ///
    /// It is provided with a reference to the `ConnectConfiguration` as well as the URI.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<T> Service for HttpsConnector<T>
where
    T: Connect,
{
    type Request = Uri;
    type Response = MaybeHttpsStream<T::Output>;
    type Error = io::Error;
    type Future = ConnectFuture<T>;

    fn call(&self, uri: Uri) -> ConnectFuture<T> {
        let f = self.http.connect(uri.clone());

        let f = if uri.scheme() == Some("https") {
            let inner = self.inner.clone();
            Box::new(f.and_then(move |s| inner.connect(uri, s))) as Box<_>
        } else {
            Box::new(f.map(|s| MaybeHttpsStream::Http(s))) as Box<_>
        };

        ConnectFuture {
            f: f,
            _p: PhantomData,
        }
    }
}

/// A future connecting to a remote HTTP server.
pub struct ConnectFuture<T>
where
    T: Connect,
{
    f: Box<Future<Item = MaybeHttpsStream<T::Output>, Error = io::Error>>,
    _p: PhantomData<T>,
}

impl<T> Future for ConnectFuture<T>
where
    T: Connect,
{
    type Item = MaybeHttpsStream<T::Output>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<MaybeHttpsStream<T::Output>, io::Error> {
        self.f.poll()
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
    use hyper::Client;
    use tokio_core::reactor::Core;
    use std::net::TcpListener;
    use std::thread;
    use openssl::ssl::{SslContext, SslFiletype};

    use super::*;

    #[test]
    fn google() {
        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let ssl = HttpsConnector::new(1, &handle).unwrap();
        let client = Client::configure()
            .connector(ssl)
            .keep_alive(false)
            .build(&handle);

        let f = client
            .get("https://www.google.com".parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.body().for_each(|_| Ok(()))
            });
        core.run(f).unwrap();

        let f = client
            .get("https://www.google.com".parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.body().for_each(|_| Ok(()))
            });
        core.run(f).unwrap();

        let f = client
            .get("https://www.google.com".parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.body().for_each(|_| Ok(()))
            });
        core.run(f).unwrap();
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
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.shutdown().unwrap();
            drop(stream);

            let stream = listener.accept().unwrap().0;
            let ssl = Ssl::new(&ctx).unwrap();
            let mut stream = ssl.accept(stream).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.shutdown().unwrap();
            drop(stream);

            let stream = listener.accept().unwrap().0;
            let ssl = Ssl::new(&ctx).unwrap();
            let mut stream = ssl.accept(stream).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.shutdown().unwrap();
            drop(stream);
        });

        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let mut connector = HttpConnector::new(1, &handle);
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

        let ssl = HttpsConnector::with_connector(connector, ssl);
        let client = Client::configure()
            .connector(ssl)
            .keep_alive(false)
            .build(&handle);

        let f = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.body().for_each(|_| Ok(()))
            });
        core.run(f).unwrap();

        let f = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.body().for_each(|_| Ok(()))
            });
        core.run(f).unwrap();

        let f = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.body().for_each(|_| Ok(()))
            });
        core.run(f).unwrap();

        thread.join().unwrap();
    }
}
