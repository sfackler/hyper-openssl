use std::pin::Pin;

use hyper::{client::conn::http1, header::HOST, Request};
use hyper_util::rt::TokioIo;
use openssl::ssl::{SslConnector, SslMethod};
use tokio::net::TcpStream;

use crate::SslStream;

#[tokio::test]
async fn google() {
    let stream = TcpStream::connect("google.com:443").await.unwrap();
    let stream = TokioIo::new(stream);

    let ssl = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap()
        .into_ssl("google.com")
        .unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();
    Pin::new(&mut stream).connect().await.unwrap();

    let (mut tx, conn) = http1::handshake(stream).await.unwrap();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            panic!("Connection failed: {:?}", err);
        }
    });

    let req = Request::builder()
        .header(HOST, "google.com")
        .body(String::new())
        .unwrap();
    tx.send_request(req).await.unwrap();
}
