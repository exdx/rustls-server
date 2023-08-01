use std::{
    env::args,
    io::{self, Write},
    net::TcpStream,
    sync::Arc,
};

use rustls::{OwnedTrustAnchor, RootCertStore, ServerName};
use tracing::info;

/// cargo run --example client -- [PEER IP] [STAKING PORT]
/// cargo run --example client -- 8.8.8.8 443 (works)
/// cargo run --example client -- www.rust-lang.org 443 (works)
/// cargo run --example client -- 52.47.181.114 9651 (returns server cert but no peer cert)
fn main() -> io::Result<()> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .try_init();

    // get args

    let server = args().nth(1).expect("no server given");
    let port = args().nth(2).expect("no port given");
    let sock_addr = format!("{}:{}", server, port);

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // this creates the connection (or session)
    // ref. go/crypto/tls/Conn#clientHandshake
    // Does the TLS handshake
    let server_name: ServerName = ServerName::try_from(server.as_ref()).unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(sock_addr).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let _ = tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    );

    info!("retrieving peer certificates...");
    match conn.peer_certificates() {
        Some(peer_certs) => {
            println!("\n\n PEER CERTS:\n {:#?}\n\n", peer_certs);
        }
        None => {
            println!("no peer certs");
        }
    }

    Ok(())
}
