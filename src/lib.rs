extern crate antidote;
extern crate hyper;
extern crate openssl;

use antidote::Mutex;
use hyper::net::{SslClient, SslServer, NetworkStream};
use openssl::error::ErrorStack;
use openssl::ssl::{self, SslMethod, SslConnector, SslConnectorBuilder, SslAcceptor};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::fmt::Debug;

pub struct OpensslClient(SslConnector);

impl OpensslClient {
    pub fn new() -> Result<OpensslClient, ErrorStack> {
        let connector = try!(SslConnectorBuilder::new(SslMethod::tls())).build();
        Ok(OpensslClient(connector))
    }
}

impl From<SslConnector> for OpensslClient {
    fn from(connector: SslConnector) -> OpensslClient {
        OpensslClient(connector)
    }
}

impl<T> SslClient<T> for OpensslClient
    where T: NetworkStream + Clone + Sync + Send + Debug
{
    type Stream = SslStream<T>;

    fn wrap_client(&self, stream: T, host: &str) -> hyper::Result<SslStream<T>> {
        match self.0.connect(host, stream) {
            Ok(stream) => Ok(SslStream(Arc::new(Mutex::new(stream)))),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

#[derive(Clone)]
pub struct OpensslServer(Arc<SslAcceptor>);

impl From<SslAcceptor> for OpensslServer {
    fn from(acceptor: SslAcceptor) -> OpensslServer {
        OpensslServer(Arc::new(acceptor))
    }
}

impl<T> SslServer<T> for OpensslServer
    where T: NetworkStream + Clone + Sync + Send + Debug
{
    type Stream = SslStream<T>;

    fn wrap_server(&self, stream: T) -> hyper::Result<SslStream<T>> {
        match self.0.accept(stream) {
            Ok(stream) => Ok(SslStream(Arc::new(Mutex::new(stream)))),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

#[derive(Clone)]
pub struct SslStream<T>(Arc<Mutex<ssl::SslStream<T>>>);

impl<T: Read + Write> Read for SslStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buf)
    }
}

impl<T: Read + Write> Write for SslStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().flush()
    }
}

impl<T: NetworkStream> NetworkStream for SslStream<T> {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.0.lock().get_mut().peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().get_ref().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().get_ref().set_write_timeout(dur)
    }
}

#[cfg(test)]
mod test {
    use hyper::{Client, Server};
    use hyper::server::{Request, Response, Fresh};
    use hyper::net::HttpsConnector;
    use openssl::ssl::{SslMethod, SslAcceptorBuilder, SslConnectorBuilder};
    use openssl::pkey::PKey;
    use openssl::x509::X509;
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
        let cert = include_bytes!("../test/cert.pem");
        let key = include_bytes!("../test/key.pem");

        let cert = X509::from_pem(cert).unwrap();
        let key = PKey::private_key_from_pem(key).unwrap();

        let acceptor = SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(),
                                                                &key,
                                                                &cert,
                                                                None::<X509>)
            .unwrap()
            .build();
        let ssl = OpensslServer::from(acceptor);
        let server = Server::https("0.0.0.0:0", ssl).unwrap();

        let listening = server.handle(|_: Request, resp: Response<Fresh>| {
            resp.send(b"hello").unwrap()
        }).unwrap();
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
    }
}
