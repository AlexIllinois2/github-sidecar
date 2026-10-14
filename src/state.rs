//! 共享状态：配置、规则匹配、DNS 解析策略，以及带连接池的上游 HTTP 客户端。

use crate::ca::CaManager;
use crate::config::{Config, Rule, Settings};
use crate::dns::DnsResolver;
use crate::logs::LogBuffer;
use crate::speedtest::IpSpeedTester;

use bytes::Bytes;
use http_body_util::combinators::BoxBody as SyncBoxBody;
use hyper::Error as HyperError;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_crypto;
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower_service::Service;

pub type BoxBody = SyncBoxBody<Bytes, HyperError>;
pub type ProxyClient = Client<HttpsConnector<HttpConnector<ProxyResolver>>, BoxBody>;

#[derive(Default, Debug)]
pub struct Counters {
    pub total: AtomicU64,
    pub tunnel: AtomicU64,
    pub mitm: AtomicU64,
    pub rewrite: AtomicU64,
    pub errors: AtomicU64,
}

impl Counters {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }
}

pub struct Core {
    pub cfg: std::sync::RwLock<Config>,
    pub cfg_path: PathBuf,
    pub dns: DnsResolver,
    pub speed: IpSpeedTester,
    pub ca: CaManager,
    pub logs: Arc<LogBuffer>,
    pub started: Instant,
    pub counters: Counters,
    client: OnceLock<ProxyClient>,
}

impl Core {
    pub fn new(cfg: Config, cfg_path: PathBuf, ca: CaManager, logs: Arc<LogBuffer>) -> Arc<Self> {
        let tls = Arc::new(upstream_tls_config(&cfg.settings));
        let core = Arc::new(Self {
            cfg: std::sync::RwLock::new(cfg),
            cfg_path,
            dns: DnsResolver::new(),
            speed: IpSpeedTester::new(tokio_rustls::TlsConnector::from(tls)),
            ca,
            logs,
            started: Instant::now(),
            counters: Counters::default(),
            client: OnceLock::new(),
        });
        let client = build_upstream_client(core.clone());
        core.client.set(client).expect("client only set once");
        core
    }

    pub fn settings(&self) -> Settings {
        self.cfg.read().unwrap().settings.clone()
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.cfg.read().unwrap().rules.clone()
    }

    pub fn client(&self) -> &ProxyClient {
        self.client.get().expect("upstream client initialized")
    }

    pub fn save_config(&self) -> io::Result<()> {
        let cfg = self.cfg.read().unwrap().clone();
        cfg.save(&self.cfg_path)
    }

    /// 代理隧道/连接策略匹配：返回第一条命中的启用规则
    pub fn match_rule(&self, host: &str) -> Option<Rule> {
        let rules = self.cfg.read().unwrap().rules.clone();
        rules.into_iter().find(|r| r.enabled && r.host_matches(host))
    }

    /// 是否需要解密该域名的 HTTPS。与 match_rule 不同，这里取所有命中规则的并集：
    /// 加速规则（DNS/IP）在前也不能屏蔽掉后面那条需要 MITM 的重定向规则。
    pub fn needs_mitm_for(&self, host: &str) -> bool {
        let rules = self.cfg.read().unwrap().rules.clone();
        rules.iter().any(|r| r.enabled && r.host_matches(host) && r.needs_mitm())
    }

    /// 重定向匹配：需要 rewrite_to 且路径命中
    pub fn match_rewrite(&self, host: &str, path: &str) -> Option<Rule> {
        let rules = self.cfg.read().unwrap().rules.clone();
        rules.into_iter().find(|r| {
            r.enabled && r.is_rewrite_rule() && r.host_matches(host) && path_matches(&r.path_prefixes, path)
        })
    }

    /// 完整解析策略：规则 ip_override → 规则 IP 池测速优选 → 规则 DNS 竞速 → 系统解析
    pub async fn resolve_host(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if let Some(rule) = self.match_rule(host) {
            let ips: Vec<IpAddr> = rule
                .ip_override
                .iter()
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !ips.is_empty() {
                return Ok(ips);
            }
            if !rule.ip_pool.is_empty() {
                if let Ok(ranked) = self.speed.best_ips(host, &rule.ip_pool).await {
                    if !ranked.is_empty() {
                        return Ok(ranked);
                    }
                }
                // 池内候选全部不可达 → 落回 DNS 竞速兜底
            }
            if !rule.dns_servers.is_empty() {
                return self.dns.resolve(host, &rule.dns_servers).await;
            }
        }
        system_resolve(host).await
    }
}

pub async fn system_resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host((host, 0)).await?;
    let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
    ips.dedup();
    if ips.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "系统解析无结果"));
    }
    Ok(ips)
}

fn path_matches(prefixes: &[String], path: &str) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    prefixes.iter().any(|p| {
        let p = p.trim();
        if let Some(needle) = p.strip_prefix('*') {
            path.contains(needle)
        } else {
            path.starts_with(p)
        }
    })
}

/// 自定义 DNS 解析器：接入 hyper-util 的 HttpConnector，规则里的
/// ip_override / dns_servers 对上游连接同样生效（SNI 仍是原域名）。
#[derive(Clone)]
pub struct ProxyResolver {
    pub core: Arc<Core>,
}

impl Service<Name> for ProxyResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let core = self.core.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = core.resolve_host(&host).await?;
            Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect::<Vec<_>>().into_iter())
        })
    }
}

/// 跳过上游 TLS 校验的自定义 verifier（insecure_tls = true 时使用）
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring_crypto::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn load_native_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for e in &loaded.errors {
        tracing::warn!("加载系统根证书出错: {e}");
    }
    let mut added = 0;
    for cert in loaded.certs {
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    tracing::debug!("系统根证书加载 {added} 张");
    roots
}

/// 上游 TLS 客户端配置（insecure_tls 决定是否跳过证书校验）。
/// 启动时构建一次，由上游 HTTP 客户端与 IP 测速共用。
fn upstream_tls_config(settings: &Settings) -> ClientConfig {
    let builder = ClientConfig::builder();
    let with_roots = if settings.insecure_tls {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
    } else {
        builder.with_root_certificates(load_native_roots())
    };
    // 不预置 ALPN：hyper-rustls 会按 enable_http1()/enable_http2() 自行设置，
    // 预先写入 alpn_protocols 会让 HttpsConnectorBuilder 直接 panic。
    with_roots.with_no_client_auth()
}

fn build_upstream_client(core: Arc<Core>) -> ProxyClient {
    let tls = upstream_tls_config(&core.settings());

    let mut http = HttpConnector::new_with_resolver(ProxyResolver { core });
    http.set_connect_timeout(Some(Duration::from_secs(6)));
    http.set_happy_eyeballs_timeout(Some(Duration::from_secs(2)));
    http.enforce_http(false);

    let connector: HttpsConnector<HttpConnector<ProxyResolver>> = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);

    Client::builder(TokioExecutor::new()).build(connector)
}
