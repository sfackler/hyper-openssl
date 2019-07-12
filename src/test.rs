use hyper::client::HttpConnector;
use futures::future;
use futures::stream::TryStreamExt;
use hyper::{service, Response};
use tokio::net::TcpListener;
use hyper::{Body, Client};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use hyper::server::conn::Http;

use super::*;

#[tokio::test]
#[cfg(feature = "runtime")]
async fn google() {
    let ssl = HttpsConnector::new(1).unwrap();
    let client = Client::builder().keep_alive(false).build::<_, Body>(ssl);

    for _ in 0..1 {
        let resp = client.get("https://www.google.com".parse().unwrap()).await.unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        resp.into_body().try_concat().await.unwrap();
    }
}

#[tokio::test]
async fn localhost() {
    let mut listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_session_id_context(b"test").unwrap();
        acceptor.set_private_key_file("test/key.pem", SslFiletype::PEM).unwrap();
        acceptor.set_certificate_chain_file("test/cert.pem").unwrap();
        let acceptor = acceptor.build();

        let stream = listener.accept().await.unwrap().0;
        let stream = tokio_openssl::accept(&acceptor, stream).await.unwrap();

        let service = service::service_fn(|_| future::ready(Ok::<_, io::Error>(Response::new(Body::empty()))));

        Http::new()
            .keep_alive(false)
            .serve_connection(stream, service)
            .await
            .unwrap();
    };
    tokio::spawn(server);

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

    for _ in 0..1 {
        let resp = client.get(format!("https://localhost:{}", port).parse().unwrap()).await.unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        resp.into_body().try_concat().await.unwrap();
    }
}

/*
#[test]
#[cfg(ossl102)]
fn alpn_h2() {
    use futures::future;
    use hyper::server::conn::Http;
    use hyper::service;
    use hyper::Response;
    use openssl::ssl::{self, AlpnError};
    use tokio::net::TcpListener;
    use tokio_openssl::SslAcceptorExt;

    let mut listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut ctx = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    ctx.set_certificate_chain_file("test/cert.pem").unwrap();
    ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    ctx.set_alpn_select_callback(|_, client| {
        ssl::select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
    });
    let ctx = ctx.build();

    let server = future::poll_fn(move || listener.poll_accept())
        .map_err(|e| panic!("tcp accept error: {}", e))
        .and_then(move |(stream, _)| ctx.accept_async(stream))
        .map_err(|e| panic!("tls accept error: {}", e))
        .and_then(|stream| {
            assert_eq!(
                stream.get_ref().ssl().selected_alpn_protocol().unwrap(),
                b"h2"
            );
            Http::new().http2_only(true).serve_connection(
                stream,
                service::service_fn_ok(|_| Response::new(Body::empty())),
            )
        })
        .map(|_| ())
        .map_err(|e| panic!("http error: {}", e));

    let mut runtime = Runtime::new().unwrap();
    runtime.spawn(server);

    let mut connector = HttpConnector::new(1);
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl.set_ca_file("test/cert.pem").unwrap();
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = Client::builder().build::<_, Body>(ssl);

    let f = client
        .get(format!("https://localhost:{}", port).parse().unwrap())
        .and_then(|resp| {
            assert!(resp.status().is_success(), "{}", resp.status());
            resp.into_body().for_each(|_| Ok(()))
        });
    runtime.block_on(f).unwrap();
    drop(client);

    runtime.run().unwrap();
}
*/
