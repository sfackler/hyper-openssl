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
