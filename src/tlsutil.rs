//! Self-signed TLS 1.3 for `zsyncd`, and TOFU pinning on leaves.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use rustls::{
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::ClientConfig;

use crate::group::hex_encode;

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn cert_fingerprint(der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(der);
    h.finalize().into()
}

pub fn load_or_create_server(
    dir: &Path,
) -> Result<(ServerConfig, PathBuf, PathBuf)> {
    let cert_path = dir.join("tls.crt");
    let key_path = dir.join("tls.key");
    if !cert_path.exists() || !key_path.exists() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["zsyncd".into()])
                .context("generate self-signed certificate")?;
        fs::write(&cert_path, certified.cert.pem())
            .with_context(|| format!("write {}", cert_path.display()))?;
        fs::write(&key_path, certified.key_pair.serialize_pem())
            .with_context(|| format!("write {}", key_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                &key_path,
                fs::Permissions::from_mode(0o600),
            );
        }
    }
    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;
    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("tls server config")?;
    Ok((config, cert_path, key_path))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open {}", path.display()))?,
    );
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse {}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open {}", path.display()))?,
    );
    loop {
        match rustls_pemfile::read_one(&mut reader)
            .with_context(|| format!("parse {}", path.display()))?
        {
            Some(rustls_pemfile::Item::Pkcs8Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs8(k))
            }
            Some(rustls_pemfile::Item::Sec1Key(k)) => {
                return Ok(PrivateKeyDer::Sec1(k))
            }
            Some(rustls_pemfile::Item::Pkcs1Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs1(k))
            }
            None => bail!("no private key in {}", path.display()),
            _ => {}
        }
    }
}

#[derive(Debug)]
struct TofuVerifier {
    expected: Option<[u8; 32]>,
    observed: std::sync::Mutex<Option<[u8; 32]>>,
}

impl TofuVerifier {
    fn new(expected: Option<[u8; 32]>) -> Self {
        Self {
            expected,
            observed: std::sync::Mutex::new(None),
        }
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let got = cert_fingerprint(end_entity.as_ref());
        *self.observed.lock().unwrap() = Some(got);
        if let Some(want) = self.expected {
            if want != got {
                tracing::error!(
                    expected = %hex_encode(&want),
                    got = %hex_encode(&got),
                    "tls certificate pin mismatch"
                );
                return Err(
                    rustls::CertificateError::ApplicationVerificationFailure
                        .into(),
                );
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn pins_path(zsync_dir: &Path) -> PathBuf {
    zsync_dir.join("hub-pins.json")
}

pub fn load_pin(zsync_dir: &Path, hub: &str) -> Result<Option<[u8; 32]>> {
    let path = pins_path(zsync_dir);
    if !path.exists() {
        return Ok(None);
    }
    let map: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(&path)?)?;
    let Some(hex) = map.get(hub) else {
        return Ok(None);
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("corrupt pin for {hub}");
    }
    let mut pin = [0u8; 32];
    for i in 0..32 {
        pin[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(Some(pin))
}

pub fn save_pin(zsync_dir: &Path, hub: &str, pin: &[u8; 32]) -> Result<()> {
    let path = pins_path(zsync_dir);
    let mut map: BTreeMap<String, String> = if path.exists() {
        serde_json::from_slice(&fs::read(&path).unwrap_or_default())
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    map.insert(hub.to_string(), hex_encode(pin));
    fs::write(&path, serde_json::to_vec_pretty(&map)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn client_config(
    expected_pin: Option<[u8; 32]>,
) -> Result<(ClientConfig, Arc<TofuHandle>)> {
    let verifier = Arc::new(TofuVerifier::new(expected_pin));
    let handle = Arc::new(TofuHandle {
        inner: Arc::clone(&verifier),
    });
    let config = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
    ])
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    Ok((config, handle))
}

#[derive(Debug)]
pub struct TofuHandle {
    inner: Arc<TofuVerifier>,
}

impl TofuHandle {
    pub fn observed(&self) -> Option<[u8; 32]> {
        *self.inner.observed.lock().unwrap()
    }
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid tls server name {host}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_stable() {
        let a = cert_fingerprint(b"abc");
        let b = cert_fingerprint(b"abc");
        assert_eq!(a, b);
        assert_ne!(a, cert_fingerprint(b"abd"));
    }
}
