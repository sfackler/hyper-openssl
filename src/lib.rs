//! Hyper SSL support via OpenSSL.
//!
//! # Usage
//!
//! On the client side:
//!
//! ```
//! extern crate hyper;
//! extern crate hyper_openssl;
//!
//! use hyper::Client;
//! use hyper::net::HttpsConnector;
//! use hyper_openssl::OpensslClient;
//! use std::io::Read;
//!
//! fn main() {
//!     let ssl = OpensslClient::new().unwrap();
//!     let connector = HttpsConnector::new(ssl);
//!     let client = Client::with_connector(connector);
//!
//!     let mut resp = client.get("https://google.com").send().unwrap();
//!     let mut body = vec![];
//!     resp.read_to_end(&mut body).unwrap();
//!     println!("{}", String::from_utf8_lossy(&body));
//! }
//! ```
//!
//! Or on the server side:
//!
//! ```no_run
//! extern crate hyper;
//! extern crate hyper_openssl;
//!
//! use hyper::Server;
//! use hyper_openssl::OpensslServer;
//!
//! fn main() {
//!     let ssl = OpensslServer::from_files("private_key.pem", "certificate_chain.pem").unwrap();
//!     let server = Server::https("0.0.0.0:8443", ssl).unwrap();
//! }
//! ```
#![warn(missing_docs)]
#![doc(html_root_url="https://docs.rs/hyper-openssl/0.2.4")]

extern crate antidote;
extern crate hyper;
pub extern crate openssl;

use antidote::Mutex;
use hyper::net::{SslClient, SslServer, NetworkStream};
use openssl::error::ErrorStack;
use openssl::ssl::{self, SslMethod, SslConnector, SslConnectorBuilder, SslAcceptor,
                   SslAcceptorBuilder, SslSession};
use openssl::x509::X509_FILETYPE_PEM;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::net::{SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(PartialEq, Eq, Hash)]
struct SessionKey {
    host: String,
    port: u16,
}

/// An `SslClient` implementation using OpenSSL.
#[derive(Clone)]
pub struct OpensslClient {
    connector: SslConnector,
    disable_verification: bool,
    session_cache: Arc<Mutex<HashMap<SessionKey, SslSession>>>,
}

impl OpensslClient {
    /// Creates a new `OpenSslClient` with default settings.
    pub fn new() -> Result<OpensslClient, ErrorStack> {
        let connector = try!(SslConnectorBuilder::new(SslMethod::tls())).build();
        Ok(OpensslClient::from(connector))
    }

    /// If set, the
    /// `SslConnector::danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication`
    /// method will be used to connect.
    ///
    /// If certificate verification has been disabled in the `SslConnector`, verification must be
    /// additionally disabled here for that setting to take effect.
    pub fn danger_disable_hostname_verification(&mut self, disable_verification: bool) {
        self.disable_verification = disable_verification;
    }
}

impl From<SslConnector> for OpensslClient {
    fn from(connector: SslConnector) -> OpensslClient {
        OpensslClient {
            connector: connector,
            disable_verification: false,
            session_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<T> SslClient<T> for OpensslClient
    where T: NetworkStream + Clone + Sync + Send + Debug
{
    type Stream = SslStream<T>;

    fn wrap_client(&self, mut stream: T, host: &str) -> hyper::Result<SslStream<T>> {
        let mut conf = try!(self.connector.configure().map_err(|e| hyper::Error::Ssl(Box::new(e))));
        let key = SessionKey {
            host: host.to_owned(),
            port: try!(stream.peer_addr()).port(),
        };
        if let Some(session) = self.session_cache.lock().get(&key) {
            unsafe {
                try!(conf.ssl_mut()
                    .set_session(session)
                    .map_err(|e| hyper::Error::Ssl(Box::new(e))));
            }
        }
        let stream = if self.disable_verification {
            conf.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
        } else {
            conf.connect(host, stream)
        };
        match stream {
            Ok(stream) => {
                if !stream.ssl().session_reused() {
                    let session = stream.ssl().session().unwrap().to_owned();
                    self.session_cache.lock().insert(key, session);
                }
                Ok(SslStream(Arc::new(Mutex::new(InnerStream(stream)))))
            }
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

/// An `SslServer` implementation using OpenSSL.
#[derive(Clone)]
pub struct OpensslServer(SslAcceptor);

impl OpensslServer {
    /// Constructs an `OpensslServer` with a reasonable default configuration.
    ///
    /// This currently corresponds to the Intermediate profile of the
    /// [Mozilla Server Side TLS recommendations][mozilla], but is subject to change. It should be
    /// compatible with everything but the very oldest clients (notably Internet Explorer 6 on
    /// Windows XP and Java 6).
    ///
    /// The `key` file should contain the server's PEM-formatted private key, and the `certs` file
    /// should contain a sequence of PEM-formatted certificates, starting with the leaf certificate
    /// corresponding to the private key, followed by a chain of intermediate certificates to a
    /// trusted root.
    ///
    /// [mozilla]: https://wiki.mozilla.org/Security/Server_Side_TLS
    pub fn from_files<P, Q>(key: P, certs: Q) -> Result<OpensslServer, ErrorStack>
        where P: AsRef<Path>,
              Q: AsRef<Path>
    {
        let mut ssl = try!(SslAcceptorBuilder::mozilla_intermediate_raw(SslMethod::tls()));
        try!(ssl.builder_mut().set_private_key_file(key, X509_FILETYPE_PEM));
        try!(ssl.builder_mut().set_certificate_chain_file(certs));
        try!(ssl.builder_mut().check_private_key());
        Ok(OpensslServer(ssl.build()))
    }
}

impl From<SslAcceptor> for OpensslServer {
    fn from(acceptor: SslAcceptor) -> OpensslServer {
        OpensslServer(acceptor)
    }
}

impl<T> SslServer<T> for OpensslServer
    where T: NetworkStream + Clone + Sync + Send + Debug
{
    type Stream = SslStream<T>;

    fn wrap_server(&self, stream: T) -> hyper::Result<SslStream<T>> {
        match self.0.accept(stream) {
            Ok(stream) => Ok(SslStream(Arc::new(Mutex::new(InnerStream(stream))))),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

#[derive(Debug)]
struct InnerStream<T: Read + Write>(ssl::SslStream<T>);

impl<T: Read + Write> Drop for InnerStream<T> {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

/// A Hyper SSL stream.
#[derive(Debug, Clone)]
pub struct SslStream<T: Read + Write>(Arc<Mutex<InnerStream<T>>>);

impl<T: Read + Write> Read for SslStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().0.read(buf)
    }
}

impl<T: Read + Write> Write for SslStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().0.flush()
    }
}

impl<T: NetworkStream> NetworkStream for SslStream<T> {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.0.lock().0.get_mut().peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().0.get_ref().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().0.get_ref().set_write_timeout(dur)
    }
}

#[cfg(test)]
mod test {
    use hyper::{Client, Server};
    use hyper::server::{Request, Response, Fresh};
    use hyper::net::HttpsConnector;
    use openssl::ssl::{SslMethod, SslConnectorBuilder};
    use std::io::Read;
    use std::mem;

    use {OpensslClient, OpensslServer};

    #[test]
    fn google() {
        let ssl = OpensslClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let mut resp = client.get("https://google.com").send().unwrap();
        assert!(resp.status.is_success());
        let mut body = vec![];
        resp.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn server() {
        let ssl = OpensslServer::from_files("test/key.pem", "test/cert.pem").unwrap();
        let server = Server::https("127.0.0.1:0", ssl).unwrap();

        let listening =
            server.handle(|_: Request, resp: Response<Fresh>| resp.send(b"hello").unwrap())
                .unwrap();
        let port = listening.socket.port();
        mem::forget(listening);

        let mut connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
        connector.builder_mut().set_ca_file("test/cert.pem").unwrap();
        let ssl = OpensslClient::from(connector.build());
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let mut resp = client.get(&format!("https://localhost:{}", port))
            .send()
            .unwrap();
        let mut body = vec![];
        resp.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"hello");
        drop(resp);

        let mut resp = client.get(&format!("https://localhost:{}", port))
            .send()
            .unwrap();
        let mut body = vec![];
        resp.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"hello");
    }
}
