use std::{
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

// use hyper::{
//     server::conn::AddrIncoming,
//     service::{make_service_fn, service_fn},
//     Body, Response, Server,
// };
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use rcgen::CertificateParams;
use rustls::{server::AllowAnyAuthenticatedClient, RootCertStore, ServerConfig};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use crate::io::Error;

#[tokio::main]
async fn main() -> io::Result<()> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        // .is_test(true)
        .try_init();

    // Initialize the tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    let server_key_path = random_manager::tmp_path(10, None)?;
    let server_cert_path = random_manager::tmp_path(10, None)?;
    let server_cert_sna_params = CertificateParams::new(vec!["127.0.0.1".to_string()]);
    cert_manager::x509::generate_and_write_pem(
        Some(server_cert_sna_params),
        &server_key_path,
        &server_cert_path,
    )?;
    log::info!("server cert path: {}", server_cert_path);

    let ip_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let ip_port = 9649_u16;

    log::info!("[rustls] loading raw PEM files for inbound listener");
    let (private_key, certificate) = cert_manager::x509::load_pem_key_cert_to_der(
        server_key_path.as_ref(),
        server_cert_path.as_ref(),
    )?;

    let mut rts = RootCertStore::empty();
    rts.add(&certificate).unwrap();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        rts.add(&rustls::Certificate(cert.0)).unwrap();
    }

    // ref. https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html#method.with_single_cert
    // ref. https://github.com/rustls/hyper-rustls/blob/main/examples/server.rs
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(rts)))
        .with_single_cert(vec![certificate], private_key)
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("failed to create TLS server config '{}'", e),
            )
        })?;

    let addr = SocketAddr::new(ip_addr, ip_port);

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tcp_listener = TcpListener::bind(addr).await?;
    
    loop {
        let (stream, _) = tcp_listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(_tls_stream) => {
                    println!("TLS connection accepted");
                    // handle(tls_stream).await
                }
                Err(e) => eprintln!("Error accepting TLS connection: {:?}", e),
            }
        }).await?;
    }
}
