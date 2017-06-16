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
#![doc(html_root_url="https://docs.rs/hyper-openssl/0.3.0")]

extern crate antidote;
extern crate futures;
extern crate hyper;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;
extern crate tokio_service;
pub extern crate openssl;

use antidote::Mutex;
use futures::{Future, Poll};
use futures::future;
use hyper::Uri;
use hyper::client::{Connect, HttpConnector};
use openssl::ssl::{SslMethod, SslConnector, SslConnectorBuilder, SslSession, SslRef};
use openssl::error::ErrorStack;
use std::collections::HashMap;
use std::sync::Arc;
use std::marker::PhantomData;
use std::io::{self, Read, Write};
use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_openssl::{ConnectConfigurationExt, SslStream};
use tokio_service::Service;

#[derive(PartialEq, Eq, Hash)]
struct SessionKey {
    host: String,
    port: u16,
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    disable_verification: bool,
    session_cache: Arc<Mutex<HashMap<SessionKey, SslSession>>>,
    ssl_callback: Option<Arc<Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + Sync + Send>>,
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

        if let Some(ref callback) = self.ssl_callback {
            if let Err(e) = callback(conf.ssl_mut(), &uri) {
                return Box::new(future::err(io::Error::new(io::ErrorKind::Other, e)));
            }
        }

        let key = SessionKey {
            host: host.to_owned(),
            port: uri.port().unwrap_or(443),
        };
        if let Some(session) = self.session_cache.lock().get(&key) {
            if let Err(e) = unsafe { conf.ssl_mut().set_session(session) } {
                return Box::new(future::err(io::Error::new(io::ErrorKind::Other, e)));
            }
        }

        let f = if self.disable_verification {
            conf.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication_async(stream)
        } else {
            conf.connect_async(host, stream)
        };

        let f = f.map(move |s| {
            if !s.get_ref().ssl().session_reused() {
                self.session_cache.lock().insert(
                    key,
                    s.get_ref()
                        .ssl()
                        .session()
                        .expect("BUG")
                        .to_owned(),
                );
            }
            MaybeHttpsStream::Https(s)
        }).map_err(|e| io::Error::new(io::ErrorKind::Other, e));

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
        let ssl = SslConnectorBuilder::new(SslMethod::tls())?.build();
        Ok(HttpsConnector::with_connector(http, ssl))
    }
}

impl<T> HttpsConnector<T>
where
    T: Connect,
{
    /// Creates a new `HttpsConnector`.
    pub fn with_connector(http: T, ssl: SslConnector) -> HttpsConnector<T> {
        HttpsConnector {
            http,
            inner: Inner {
                ssl,
                disable_verification: false,
                session_cache: Arc::new(Mutex::new(HashMap::new())),
                ssl_callback: None,
            },
        }
    }

    /// If set, the
    /// `SslConnector::danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication`
    /// method will be used to connect.
    ///
    /// If certificate verification has been disabled in the `SslConnector`, verification must be
    /// additionally disabled here for that setting to take effect.
    pub fn danger_disable_hostname_verification(&mut self, disable_verification: bool) {
        self.inner.disable_verification = disable_verification;
    }

    /// Registers a callback which can customize the `Ssl` of each connection.
    ///
    /// It is provided with a reference to the `SslRef` as well as the URI.
    pub fn ssl_callback<F>(&mut self, callback: F)
        where F: Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send
    {
        self.inner.ssl_callback = Some(Arc::new(callback));
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

    use super::*;

    #[test]
    fn google() {
        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let ssl = HttpsConnector::new(1, &handle).unwrap();
        let client = Client::configure().connector(ssl).build(&handle);

        let f = client.get("https://www.google.com".parse().unwrap()).and_then(
            |resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.body().fold(vec![], |mut buf, chunk| {
                    buf.extend_from_slice(&chunk);
                    Ok::<_, hyper::Error>(buf)
                })
            },
        );
        let body = core.run(f).unwrap();
        println!("{}", String::from_utf8_lossy(&body));
    }
}
