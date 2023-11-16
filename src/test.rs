use std::{io, pin::Pin};

use hyper::{client::conn::http1, header::HOST, server, service, Request, Response};
use hyper_util::rt::TokioIo;
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod};
use tokio::net::{TcpListener, TcpStream};

use crate::SslStream;

#[tokio::test]
async fn client_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("test/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let ssl = Ssl::new(acceptor.context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, TokioIo::new(stream)).unwrap();

        Pin::new(&mut stream).accept().await.unwrap();

        let service =
            service::service_fn(|_| async { Ok::<_, io::Error>(Response::new(String::new())) });

        server::conn::http1::Builder::new()
            .serve_connection(stream, service)
            .await
            .unwrap();
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let stream = TokioIo::new(stream);

    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_ca_file("test/cert.pem").unwrap();
    let ssl = builder
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
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
