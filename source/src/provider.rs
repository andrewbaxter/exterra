use std::io::{BufRead, BufReader};
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{bail, Context as _, Result};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::DigitallySignedStruct;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::encoding::SchemaAttr;

// ── proto generated types ─────────────────────────────────────────────────────

pub mod proto5 {
    #![allow(dead_code)]
    tonic::include_proto!("tfplugin5");
}
pub mod proto6 {
    #![allow(dead_code)]
    tonic::include_proto!("tfplugin6");
}

use proto5::provider_client::ProviderClient as V5Client;
use proto6::provider_client::ProviderClient as V6Client;

// prost generates nested messages in lowercase snake_case modules:
//   message Foo { message Bar {} }  →  foo::Bar
use proto5::{
    apply_resource_change::Request as Apply5Req,
    configure::Request as Configure5Req,
    get_provider_schema::Request as GetSchema5Req,
    plan_resource_change::Request as Plan5Req,
};
use proto6::{
    apply_resource_change::Request as Apply6Req,
    configure_provider::Request as Configure6Req,
    get_provider_schema::Request as GetSchema6Req,
    plan_resource_change::Request as Plan6Req,
};

// ── TLS IO wrapper ────────────────────────────────────────────────────────────

/// Wraps a tokio-rustls TLS stream and implements the hyper `Connection` trait.
struct TlsIo<T>(tokio_rustls::client::TlsStream<T>);

impl<T: Unpin> hyper_util::client::legacy::connect::Connection for TlsIo<T> {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

// ── Handshake ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Addr {
    Tcp(String, u16),
    Unix(String),
}

struct Handshake {
    proto_version: u32,
    addr: Addr,
    server_cert_der: Vec<u8>,
}

fn parse_handshake(line: &str) -> Result<Handshake> {
    let parts: Vec<&str> = line.trim().split('|').collect();
    if parts.len() < 6 {
        bail!("unexpected handshake line (expected 6 '|'-delimited fields): {line:?}");
    }
    let proto_version: u32 = parts[1].parse().context("parsing app proto version")?;
    let addr = match parts[2] {
        "tcp" => {
            let (host, port) = parts[3]
                .rsplit_once(':')
                .context("no port in TCP address")?;
            Addr::Tcp(host.to_string(), port.parse()?)
        }
        "unix" => Addr::Unix(parts[3].to_string()),
        other => bail!("unsupported network type: {other}"),
    };
    // go-plugin encodes the cert with base64.RawStdEncoding (no padding).
    let server_cert_der = if parts[5].is_empty() {
        Vec::new()
    } else {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, parts[5])
            .context("base64-decoding server cert")?
    };
    Ok(Handshake { proto_version, addr, server_cert_der })
}

// ── Provider ──────────────────────────────────────────────────────────────────

pub struct Provider {
    inner: ProviderInner,
    _child: Child,
}

enum ProviderInner {
    V5(V5Client<Channel>),
    V6(V6Client<Channel>),
}

pub struct PlanResult {
    pub planned_state: Vec<u8>,
    pub planned_private: Vec<u8>,
    /// True when the provider requires destroy-then-recreate for this change.
    pub requires_replace: bool,
}

impl Provider {
    pub async fn launch(binary: &Path) -> Result<Self> {
        // Generate a client key-pair and self-signed cert for mTLS.
        let key_pair = KeyPair::generate()?;
        let cert = CertificateParams::default().self_signed(&key_pair)?;
        let client_cert_pem = cert.pem();
        let client_cert_der: Vec<u8> = cert.der().to_vec();
        let client_key_der: Vec<u8> = key_pair.serialize_der();

        let mut child = Command::new(binary)
            // go-plugin magic cookie.
            // terraform-plugin-go (used by the framework) uses a 64-char value;
            // terraform-plugin-sdk v2 uses only the first 40 chars.
            .env("TF_PLUGIN_MAGIC_COOKIE", "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2")
            .env("PLUGIN_PROTOCOL_VERSIONS", "6,5")
            .env("PLUGIN_CLIENT_CERT", &client_cert_pem)
            .env("PLUGIN_MIN_PORT", "10000")
            .env("PLUGIN_MAX_PORT", "25000")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("spawning {}", binary.display()))?;

        let stdout = child.stdout.take().expect("stdout was piped");
        let line = {
            let mut r = BufReader::new(stdout);
            let mut l = String::new();
            r.read_line(&mut l).context("reading provider handshake")?;
            l
        };

        let hs = parse_handshake(&line)?;
        let tls_cfg =
            build_tls_config(&hs.server_cert_der, &client_cert_der, &client_key_der)?;
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let channel = make_channel(&hs.addr, connector).await?;

        let inner = match hs.proto_version {
            6 => ProviderInner::V6(V6Client::new(channel)),
            _ => ProviderInner::V5(V5Client::new(channel)),
        };
        Ok(Provider { inner, _child: child })
    }

    // ── Schema ────────────────────────────────────────────────────────────────

    pub async fn get_resource_schema(&mut self, resource_type: &str) -> Result<Vec<SchemaAttr>> {
        match &mut self.inner {
            ProviderInner::V5(c) => {
                let resp = c
                    .get_schema(GetSchema5Req {})
                    .await?
                    .into_inner();
                check_diags5(&resp.diagnostics)?;
                let schema = resp
                    .resource_schemas
                    .get(resource_type)
                    .with_context(|| format!("no resource type {resource_type:?} in provider"))?;
                Ok(block_attrs5(schema.block.as_ref()))
            }
            ProviderInner::V6(c) => {
                let resp = c
                    .get_provider_schema(GetSchema6Req {})
                    .await?
                    .into_inner();
                check_diags6(&resp.diagnostics)?;
                let schema = resp
                    .resource_schemas
                    .get(resource_type)
                    .with_context(|| format!("no resource type {resource_type:?} in provider"))?;
                Ok(block_attrs6(schema.block.as_ref()))
            }
        }
    }

    // ── Configure ─────────────────────────────────────────────────────────────

    pub async fn configure(&mut self, config_mp: Vec<u8>) -> Result<()> {
        match &mut self.inner {
            ProviderInner::V5(c) => {
                let resp = c
                    .configure(Configure5Req {
                        terraform_version: "1.0.0".into(),
                        config: Some(dv5(config_mp)),
                        ..Default::default()
                    })
                    .await?
                    .into_inner();
                check_diags5(&resp.diagnostics)
            }
            ProviderInner::V6(c) => {
                let resp = c
                    .configure_provider(Configure6Req {
                        terraform_version: "1.0.0".into(),
                        config: Some(dv6(config_mp)),
                        ..Default::default()
                    })
                    .await?
                    .into_inner();
                check_diags6(&resp.diagnostics)
            }
        }
    }

    // ── Plan ──────────────────────────────────────────────────────────────────

    pub async fn plan(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        proposed_new_state: Vec<u8>,
        config: Vec<u8>,
        prior_private: Vec<u8>,
    ) -> Result<PlanResult> {
        match &mut self.inner {
            ProviderInner::V5(c) => {
                let resp = c
                    .plan_resource_change(Plan5Req {
                        type_name: resource_type.into(),
                        prior_state: Some(dv5(prior_state)),
                        proposed_new_state: Some(dv5(proposed_new_state)),
                        config: Some(dv5(config)),
                        prior_private,
                        ..Default::default()
                    })
                    .await?
                    .into_inner();
                check_diags5(&resp.diagnostics)?;
                Ok(PlanResult {
                    planned_state: extract5(resp.planned_state),
                    planned_private: resp.planned_private,
                    requires_replace: !resp.requires_replace.is_empty(),
                })
            }
            ProviderInner::V6(c) => {
                let resp = c
                    .plan_resource_change(Plan6Req {
                        type_name: resource_type.into(),
                        prior_state: Some(dv6(prior_state)),
                        proposed_new_state: Some(dv6(proposed_new_state)),
                        config: Some(dv6(config)),
                        prior_private,
                        ..Default::default()
                    })
                    .await?
                    .into_inner();
                check_diags6(&resp.diagnostics)?;
                Ok(PlanResult {
                    planned_state: extract6(resp.planned_state),
                    planned_private: resp.planned_private,
                    requires_replace: !resp.requires_replace.is_empty(),
                })
            }
        }
    }

    // ── Apply ─────────────────────────────────────────────────────────────────

    pub async fn apply(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        planned_state: Vec<u8>,
        config: Vec<u8>,
        planned_private: Vec<u8>,
    ) -> Result<Vec<u8>> {
        match &mut self.inner {
            ProviderInner::V5(c) => {
                let resp = c
                    .apply_resource_change(Apply5Req {
                        type_name: resource_type.into(),
                        prior_state: Some(dv5(prior_state)),
                        planned_state: Some(dv5(planned_state)),
                        config: Some(dv5(config)),
                        planned_private,
                        ..Default::default()
                    })
                    .await?
                    .into_inner();
                check_diags5(&resp.diagnostics)?;
                Ok(extract5(resp.new_state))
            }
            ProviderInner::V6(c) => {
                let resp = c
                    .apply_resource_change(Apply6Req {
                        type_name: resource_type.into(),
                        prior_state: Some(dv6(prior_state)),
                        planned_state: Some(dv6(planned_state)),
                        config: Some(dv6(config)),
                        planned_private,
                        ..Default::default()
                    })
                    .await?
                    .into_inner();
                check_diags6(&resp.diagnostics)?;
                Ok(extract6(resp.new_state))
            }
        }
    }
}

// ── DynamicValue helpers ──────────────────────────────────────────────────────

fn dv5(mp: Vec<u8>) -> proto5::DynamicValue {
    proto5::DynamicValue { msgpack: mp, json: vec![] }
}

fn dv6(mp: Vec<u8>) -> proto6::DynamicValue {
    proto6::DynamicValue { msgpack: mp, json: vec![] }
}

fn extract5(dv: Option<proto5::DynamicValue>) -> Vec<u8> {
    dv.map(|d| if !d.msgpack.is_empty() { d.msgpack } else { d.json })
        .unwrap_or_default()
}

fn extract6(dv: Option<proto6::DynamicValue>) -> Vec<u8> {
    dv.map(|d| if !d.msgpack.is_empty() { d.msgpack } else { d.json })
        .unwrap_or_default()
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

fn check_diags5(diags: &[proto5::Diagnostic]) -> Result<()> {
    let errs: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == proto5::diagnostic::Severity::Error as i32)
        .collect();
    if errs.is_empty() {
        return Ok(());
    }
    bail!(
        "provider errors:\n{}",
        errs.iter()
            .map(|d| format!("  {}: {}", d.summary, d.detail))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn check_diags6(diags: &[proto6::Diagnostic]) -> Result<()> {
    let errs: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == proto6::diagnostic::Severity::Error as i32)
        .collect();
    if errs.is_empty() {
        return Ok(());
    }
    bail!(
        "provider errors:\n{}",
        errs.iter()
            .map(|d| format!("  {}: {}", d.summary, d.detail))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

// ── Schema helpers ────────────────────────────────────────────────────────────

fn block_attrs5(block: Option<&proto5::schema::Block>) -> Vec<SchemaAttr> {
    block
        .map(|b| {
            b.attributes
                .iter()
                .map(|a| SchemaAttr {
                    name: a.name.clone(),
                    required: a.required,
                    optional: a.optional,
                    computed: a.computed,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn block_attrs6(block: Option<&proto6::schema::Block>) -> Vec<SchemaAttr> {
    block
        .map(|b| {
            b.attributes
                .iter()
                .map(|a| SchemaAttr {
                    name: a.name.clone(),
                    required: a.required,
                    optional: a.optional,
                    computed: a.computed,
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── TLS config ────────────────────────────────────────────────────────────────

/// go-plugin generates server certs with CA:true (they are self-signed).
/// rustls rejects CA certs used as end-entity certs during normal chain
/// validation, so we bypass chain validation entirely and just pin the exact
/// DER bytes that were received in the handshake line.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_der: Vec<u8>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_der.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_config(
    server_cert_der: &[u8],
    client_cert_der: &[u8],
    client_key_der: &[u8],
) -> Result<rustls::ClientConfig> {
    let verifier = Arc::new(PinnedCertVerifier { expected_der: server_cert_der.to_vec() });
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(client_cert_der.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key_der.to_vec())),
        )?;
    // gRPC requires HTTP/2; advertise h2 via ALPN so the TLS handshake
    // negotiates the right protocol.
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

// ── Channel factory ───────────────────────────────────────────────────────────

async fn make_channel(addr: &Addr, connector: TlsConnector) -> Result<Channel> {
    let server_name: rustls::pki_types::ServerName<'static> =
        "localhost".to_string().try_into()?;

    match addr {
        Addr::Tcp(host, port) => {
            let host = host.clone();
            let port = *port;
            let ch = Endpoint::try_from(format!("https://{host}:{port}"))?
                .connect_with_connector(service_fn(move |_: Uri| {
                    let connector = connector.clone();
                    let sn = server_name.clone();
                    let host = host.clone();
                    async move {
                        let stream = TcpStream::connect((host.as_str(), port)).await?;
                        let tls = connector.connect(sn, stream).await?;
                        Ok::<_, std::io::Error>(TokioIo::new(TlsIo(tls)))
                    }
                }))
                .await?;
            Ok(ch)
        }
        Addr::Unix(path) => {
            let path = path.clone();
            let ch = Endpoint::try_from("http://localhost")?
                .connect_with_connector(service_fn(move |_: Uri| {
                    let connector = connector.clone();
                    let sn = server_name.clone();
                    let path = path.clone();
                    async move {
                        let stream = UnixStream::connect(&path).await?;
                        let tls = connector.connect(sn, stream).await?;
                        Ok::<_, std::io::Error>(TokioIo::new(TlsIo(tls)))
                    }
                }))
                .await?;
            Ok(ch)
        }
    }
}
