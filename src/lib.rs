extern crate antidote;
extern crate hyper;
extern crate openssl;

use antidote::Mutex;
use hyper::net::{SslClient, NetworkStream};
use openssl::error::ErrorStack;
use openssl::ssl::{self, SslMethod, SslConnector, SslConnectorBuilder};
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
    use hyper::Client;
    use hyper::net::HttpsConnector;
    use std::io::Read;

    use OpensslClient;

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
}
