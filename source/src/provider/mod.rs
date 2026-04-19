use {
    crate::{
        provider::{
            v_::ProviderShared,
        },
    },
    anyhow::{
        Context as _,
        Result,
        bail,
    },
    hyper_util::rt::TokioIo,
    rustls::{
        DigitallySignedStruct,
        client::danger::{
            HandshakeSignatureValid,
            ServerCertVerified,
            ServerCertVerifier,
        },
        pki_types::{
            CertificateDer,
            PrivateKeyDer,
            PrivatePkcs8KeyDer,
            UnixTime,
        },
    },
    std::{
        io::{
            BufRead,
            BufReader,
        },
        path::Path,
        pin::Pin,
        process::{
            Command,
            Stdio,
        },
        sync::Arc,
        task::{
            Context,
            Poll,
        },
    },
    tokio::{
        io::{
            AsyncRead,
            AsyncWrite,
            ReadBuf,
        },
        net::{
            TcpStream,
            UnixStream,
        },
    },
    tokio_rustls::TlsConnector,
    tonic::transport::{
        Endpoint,
        Uri,
    },
    tower::service_fn,
};

pub(crate) mod v_;
mod v5;
mod v6;

pub enum ProviderInner {
    V5(v5::ProviderInner),
    V6(v6::ProviderInner),
}

impl v_::ProviderInnerImpl for ProviderInner {
    fn get_resource_schema(
        &self,
        type_: &str,
    ) -> std::result::Result<Vec<crate::encoding::SchemaAttr>, anyhow::Error> {
        match self {
            ProviderInner::V5(v) => v.get_resource_schema(type_),
            ProviderInner::V6(v) => v.get_resource_schema(type_),
        }
    }

    async fn plan(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        proposed_new_state: Vec<u8>,
        config: Vec<u8>,
        prior_private: Vec<u8>,
    ) -> std::result::Result<v_::PlanResult, anyhow::Error> {
        match &mut *self {
            ProviderInner::V5(v) => v
                .plan(resource_type, prior_state, proposed_new_state, config, prior_private)
                .await,
            ProviderInner::V6(v) => v
                .plan(resource_type, prior_state, proposed_new_state, config, prior_private)
                .await,
        }
    }

    async fn apply(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        planned_state: Vec<u8>,
        config: Vec<u8>,
        planned_private: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, anyhow::Error> {
        match &mut *self {
            ProviderInner::V5(v) => v
                .apply(resource_type, prior_state, planned_state, config, planned_private)
                .await,
            ProviderInner::V6(v) => v
                .apply(resource_type, prior_state, planned_state, config, planned_private)
                .await,
        }
    }
}

pub async fn new(
    shared: &ProviderShared,
    binary: &Path,
    provider_config: serde_json::Map<String, serde_json::Value>,
) -> Result<ProviderInner, anyhow::Error> {
    // # Launch provider binary
    let mut child =
        Command::new(binary)
            // go-plugin magic cookie. terraform-plugin-go (used by the framework) uses a
            // 64-char value; terraform-plugin-sdk v2 uses only the first 40 chars.
            .env("TF_PLUGIN_MAGIC_COOKIE", "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2")
            .env("PLUGIN_PROTOCOL_VERSIONS", "6,5")
            .env("PLUGIN_CLIENT_CERT", &shared.own_pub_pem)
            .env("PLUGIN_MIN_PORT", "10000")
            .env("PLUGIN_MAX_PORT", "25000")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("Error spawning provider binary [{}]", binary.display()))?;

    // # Get proto details from first line of child stdout
    let child_stdout = child.stdout.take().expect("stdout was piped");
    let handshake_line = {
        let mut r = BufReader::new(child_stdout);
        let mut l = String::new();
        r.read_line(&mut l).context("Error reading provider handshake")?;
        l
    };
    let handshake_parts: Vec<&str> = handshake_line.trim().split('|').collect();
    if handshake_parts.len() < 6 {
        bail!("unexpected handshake line (expected 6 '|'-delimited fields): {handshake_line:?}");
    }
    let proto_version: u32 = handshake_parts[1].parse().context("parsing app proto version")?;

    #[derive(Debug)]
    enum Addr {
        Tcp(String, u16),
        Unix(String),
    }

    let proto_addr = match handshake_parts[2] {
        "tcp" => {
            let (host, port) = handshake_parts[3].rsplit_once(':').context("no port in TCP address")?;
            Addr::Tcp(host.to_string(), port.parse()?)
        },
        "unix" => Addr::Unix(handshake_parts[3].to_string()),
        other => bail!("unsupported network type: {other}"),
    };
    let provider_cert_der = if handshake_parts[5].is_empty() {
        Vec::new()
    } else {
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            handshake_parts[5],
        ).context("base64-decoding server cert")?
    };

    // # Open provider proto connection
    let channel_connector = TlsConnector::from(Arc::new({
        /// go-plugin generates server certs with CA:true (they are self-signed). rustls
        /// rejects CA certs used as end-entity certs during normal chain validation, so we
        /// bypass chain validation entirely and just pin the exact DER bytes that were
        /// received in the handshake line.
        #[derive(Debug)]
        struct PinnedCertVerifier {
            expected_der: Vec<u8>,
            crypto: Arc<rustls::crypto::CryptoProvider>,
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
                    &self.crypto.signature_verification_algorithms,
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
                    &self.crypto.signature_verification_algorithms,
                )
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.crypto.signature_verification_algorithms.supported_schemes()
            }
        }

        let verifier = Arc::new(PinnedCertVerifier {
            expected_der: provider_cert_der.to_vec(),
            crypto: shared.crypto.clone(),
        });
        let mut tls_cfg =
            rustls::ClientConfig::builder_with_provider(shared.crypto.clone())
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_auth_cert(
                    vec![CertificateDer::from(shared.own_pub_der.to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(shared.own_priv_der.to_vec())),
                )?;

        // gRPC requires HTTP/2; advertise h2 via ALPN so the TLS handshake negotiates the
        // right protocol.
        tls_cfg.alpn_protocols = vec![b"h2".to_vec()];

        //. build_tls_config(&hs.server_cert_der, &shared.client_cert_der, &shared.client_key_der)?
        tls_cfg
    }));

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

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    let server_name: rustls::pki_types::ServerName<'static> = "localhost".to_string().try_into()?;
    let channel = match proto_addr {
        Addr::Tcp(host, port) => {
            let host = host.clone();
            let ch =
                Endpoint::try_from(format!("https://{host}:{port}"))?
                    .connect_with_connector(service_fn(move |_: Uri| {
                        let connector = channel_connector.clone();
                        let sn = server_name.clone();
                        let host = host.clone();
                        async move {
                            let stream = TcpStream::connect((host.as_str(), port)).await?;
                            let tls = connector.connect(sn, stream).await?;
                            Ok::<_, std::io::Error>(TokioIo::new(TlsIo(tls)))
                        }
                    }))
                    .await?;
            ch
        },
        Addr::Unix(path) => {
            let path = path.clone();
            let ch = Endpoint::try_from("http://localhost")?.connect_with_connector(service_fn(move |_: Uri| {
                let connector = channel_connector.clone();
                let sn = server_name.clone();
                let path = path.clone();
                async move {
                    let stream = UnixStream::connect(&path).await?;
                    let tls = connector.connect(sn, stream).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(TlsIo(tls)))
                }
            })).await?;
            ch
        },
    };
    match proto_version {
        5 => return Ok(ProviderInner::V5(v5::ProviderInner::new(child, provider_config, channel).await?)),
        6 => return Ok(ProviderInner::V6(v6::ProviderInner::new(child, provider_config, channel).await?)),
        v => {
            return Err(anyhow::anyhow!("Unknown plugin protocol version {}", v));
        },
    };
}
