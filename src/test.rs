use crate::SslStream;
use hyper::client::conn::http1;
use hyper::{server, service, Request, Response};
use hyper_util::rt::TokioIo;
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod};
use std::io;
use std::pin::Pin;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn raw_client_server() {
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

    let req = Request::builder().body(String::new()).unwrap();
    tx.send_request(req).await.unwrap();
}

#[tokio::test]
#[cfg(feature = "client-legacy")]
async fn legacy_client_server() {
    use crate::client::HttpsConnector;
    use hyper::body::Body;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::future;
    use std::pin::pin;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("test/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        for _ in 0..3 {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let stream = listener.accept().await.unwrap().0;
            let mut stream = SslStream::new(ssl, TokioIo::new(stream)).unwrap();

            Pin::new(&mut stream).accept().await.unwrap();

            let service =
                service::service_fn(|_| async { Ok::<_, io::Error>(Response::new(String::new())) });

            server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(stream, service)
                .await
                .unwrap();
        }
    });

    let mut connector = HttpConnector::new();
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
    let client = Client::builder(TokioExecutor::new()).build::<_, String>(ssl);

    for _ in 0..3 {
        let resp = client
            .get(format!("https://localhost:{port}").parse().unwrap())
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let mut body = pin!(resp.into_body());
        while future::poll_fn(|cx| body.as_mut().poll_frame(cx))
            .await
            .transpose()
            .unwrap()
            .is_some()
        {}
    }
}

#[tokio::test]
#[cfg(all(feature = "client-legacy", ossl102))]
async fn legacy_alpn_h2() {
    use crate::client::HttpsConnector;
    use hyper::body::Body;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use openssl::ssl::{self, AlpnError};
    use std::future;
    use std::pin::pin;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate_chain_file("test/cert.pem")
            .unwrap();
        acceptor
            .set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor.set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
        });
        let acceptor = acceptor.build();

        let stream = listener.accept().await.unwrap().0;
        let ssl = Ssl::new(acceptor.context()).unwrap();
        let mut stream = SslStream::new(ssl, TokioIo::new(stream)).unwrap();

        Pin::new(&mut stream).accept().await.unwrap();
        assert_eq!(stream.ssl().selected_alpn_protocol().unwrap(), b"h2");

        let service =
            service::service_fn(|_| async { Ok::<_, io::Error>(Response::new(String::new())) });

        server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(stream, service)
            .await
            .unwrap();
    };
    tokio::spawn(server);

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl.set_ca_file("test/cert.pem").unwrap();
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = Client::builder(TokioExecutor::new()).build::<_, String>(ssl);

    let resp = client
        .get(format!("https://localhost:{}", port).parse().unwrap())
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let mut body = pin!(resp.into_body());
    while future::poll_fn(|cx| body.as_mut().poll_frame(cx))
        .await
        .transpose()
        .unwrap()
        .is_some()
    {}
}
