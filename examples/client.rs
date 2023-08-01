use std::{
    env::args,
    io::{self, Error, ErrorKind},
    net::IpAddr,
    sync::Arc,
};

use hyper_rustls::ConfigBuilderExt;
use rcgen::CertificateParams;
use rustls::{ClientConfig, ClientConnection, ServerName};
use tracing::info;

/// cargo run --example client -- [PEER IP] [STAKING PORT]
/// cargo run --example client -- 127.0.0.1 9649
fn main() -> io::Result<()> {
    // get args
    let peer_ip = args().nth(1).expect("no peer IP given");
    let peer_ip: IpAddr = peer_ip.parse().unwrap();

    let port = args().nth(2).expect("no port given");
    let _port: u16 = port.parse().unwrap();

    let client_key_path = random_manager::tmp_path(10, None)?;
    let client_cert_path = random_manager::tmp_path(10, None)?;
    let client_cert_sna_params = CertificateParams::new(vec!["127.0.0.1".to_string()]);
    cert_manager::x509::generate_and_write_pem(
        Some(client_cert_sna_params),
        &client_key_path,
        &client_cert_path,
    )?;
    log::info!("client cert path: {}", client_cert_path);

    let (private_key, certificate) = cert_manager::x509::load_pem_key_cert_to_der(
        client_key_path.as_ref(),
        client_cert_path.as_ref(),
    )?;

    // ref. https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html#method.with_client_auth_cert
    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots()
        .with_client_auth_cert(vec![certificate], private_key)
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to create TLS client config '{}'", e),
            )
        })?;

    let server_name = ServerName::try_from(peer_ip.to_string().as_str())
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{e}")))?;

    // this creates the connection (or session)
    // ref. go/crypto/tls/Conn#clientHandshake
    // Does the TLS handshake
    let client = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|e| Error::new(ErrorKind::Other, format!("client connection '{}'", e)))?;

    info!("retrieving peer certificates...");
    match client.peer_certificates() {
        Some(peer_certs) => {
            println!("peer certs: {:?}", peer_certs);
        }
        None => {
            println!("no peer certs");
        }
    }

    Ok(())
}
