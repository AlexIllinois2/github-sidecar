//! IP 测速优选（dev-sidecar 的“IP 优选”）：
//! 对规则配置的候选 IP 池并发做 TCP + TLS 握手（SNI=目标域名，正常证书校验），
//! 取最快的可用 IP 直连。TLS 探测同时验证“可达”与“该 IP 确实服务此域名”，
//! 避免把 github.com 的边缘 IP 误用到 raw.githubusercontent.com 这类不同 CDN 的域名上。
//!
//! 仅探测 443/TLS：池面向 HTTPS 加速场景，纯 HTTP 域名自然落回 DNS/系统解析。

use futures_util::future::join_all;
use rustls_pki_types::ServerName;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;

/// 单个候选 IP 的建连超时（TCP + TLS 握手总计）
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// 测速结果缓存时长，过期后下次请求触发重测
const CACHE_TTL: Duration = Duration::from_secs(300);
const PROBE_PORT: u16 = 443;

#[derive(Debug, Clone)]
struct CacheEntry {
    /// 测速成功的 IP，按 RTT 升序
    ips: Vec<IpAddr>,
    /// 本次探测的候选总数（仅用于展示）
    candidates: usize,
    tested_at: Instant,
}

/// 优选结果快照（管理 API / UI 展示用）
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolStatus {
    pub host: String,
    pub ips: Vec<IpAddr>,
    pub candidates: usize,
    pub age_sec: u64,
}

pub struct IpSpeedTester {
    cache: RwLock<HashMap<String, CacheEntry>>,
    tls: TlsConnector,
}

impl IpSpeedTester {
    pub fn new(tls: TlsConnector) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            tls,
        }
    }

    /// 返回该 host 当前可用的 IP（按 RTT 升序）。缓存新鲜则直接命中，
    /// 否则对池内候选并发测速并缓存。全部候选失败时返回空列表（调用方落回 DNS 竞速）。
    pub async fn best_ips(&self, host: &str, pool: &[String]) -> io::Result<Vec<IpAddr>> {
        if let Some(ips) = self.fresh(host).await {
            return Ok(ips);
        }
        self.reprobe(host, pool).await
    }

    /// 忽略缓存强制重测。连接失败后调用：缓存里的"最优 IP"可能已整体被墙，
    /// 重测既能恢复也能及时暴露"全死"状态（返回空 → 调用方落回 DNS 兜底）。
    pub async fn reprobe(&self, host: &str, pool: &[String]) -> io::Result<Vec<IpAddr>> {
        let candidates = parse_pool(pool);
        if candidates.is_empty() {
            return Ok(vec![]);
        }
        let name = match ServerName::try_from(host.to_ascii_lowercase()) {
            Ok(n) => n,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("非法主机名: {host}"),
                ))
            }
        };
        let mut results = probe_all(&name, &candidates, self.tls.clone()).await;
        results.sort_by_key(|(_, d)| *d);
        let ips: Vec<IpAddr> = results.iter().map(|(ip, _)| *ip).collect();
        if ips.is_empty() {
            tracing::warn!("IP 优选 {host}：{} 个候选全部不可达，将回退 DNS 竞速", candidates.len());
        } else {
            tracing::info!(
                "IP 优选 {host} → {}（{}/{} 候选可用，{}ms）",
                ips[0],
                ips.len(),
                candidates.len(),
                results[0].1.as_millis()
            );
        }
        self.cache_put(host.to_string(), ips.clone(), candidates.len()).await;
        Ok(ips)
    }

    /// 背景刷新：对缓存中已过 TTL 的条目用当前规则池重测；
    /// 规则被删/禁用/池被清空的条目直接移除。get_pool 返回 None 或空池均视为移除。
    pub async fn retest_stale(&self, get_pool: impl Fn(&str) -> Option<Vec<String>>) {
        let stale: Vec<String> = {
            let cache = self.cache.read().await;
            cache
                .iter()
                .filter(|(_, e)| e.tested_at.elapsed() >= CACHE_TTL)
                .map(|(h, _)| h.clone())
                .collect()
        };
        for host in stale {
            match get_pool(&host) {
                Some(pool) if !pool.is_empty() => {
                    let _ = self.best_ips(&host, &pool).await;
                }
                _ => {
                    self.cache.write().await.remove(&host);
                }
            }
        }
    }

    pub async fn snapshot(&self) -> Vec<PoolStatus> {
        let cache = self.cache.read().await;
        let mut v: Vec<PoolStatus> = cache
            .iter()
            .map(|(host, e)| PoolStatus {
                host: host.clone(),
                ips: e.ips.clone(),
                candidates: e.candidates,
                age_sec: e.tested_at.elapsed().as_secs(),
            })
            .collect();
        v.sort_by(|a, b| a.host.cmp(&b.host));
        v
    }

    async fn fresh(&self, host: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.read().await;
        cache
            .get(host)
            .filter(|e| e.tested_at.elapsed() < CACHE_TTL)
            .map(|e| e.ips.clone())
    }

    async fn cache_put(&self, host: String, ips: Vec<IpAddr>, candidates: usize) {
        self.cache.write().await.insert(
            host,
            CacheEntry {
                ips,
                candidates,
                tested_at: Instant::now(),
            },
        );
    }
}

/// 解析并去重候选 IP（非法字符串静默忽略）
fn parse_pool(pool: &[String]) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = pool.iter().filter_map(|s| s.trim().parse().ok()).collect();
    ips.sort();
    ips.dedup();
    ips
}

async fn probe_all(name: &ServerName<'static>, ips: &[IpAddr], tls: TlsConnector) -> Vec<(IpAddr, Duration)> {
    let futs = ips.iter().map(|&ip| {
        let tls = tls.clone();
        let name = name.clone();
        async move {
            let start = Instant::now();
            let ok = probe_one(ip, name, tls).await.is_ok();
            (ip, ok, start.elapsed())
        }
    });
    join_all(futs)
        .await
        .into_iter()
        .filter(|(_, ok, _)| *ok)
        .map(|(ip, _, d)| (ip, d))
        .collect()
}

/// TCP 建连 + TLS 握手（SNI=目标域名，证书校验与上游客户端一致）
async fn probe_one(ip: IpAddr, name: ServerName<'static>, tls: TlsConnector) -> io::Result<()> {
    let addr = SocketAddr::new(ip, PROBE_PORT);
    let tcp = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP 连接超时"))??;
    let _ = tcp.set_nodelay(true);
    tokio::time::timeout(PROBE_TIMEOUT, tls.connect(name, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS 握手超时"))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_parse_pool_dedup_and_filter() {
        let pool: Vec<String> = vec![
            "140.82.112.3".into(),
            " 140.82.112.3 ".into(), // 重复 + 空白
            "not-an-ip".into(),      // 非法
            "192.0.2.1".into(),
        ];
        assert_eq!(parse_pool(&pool), vec![
            "140.82.112.3".parse::<IpAddr>().unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap(),
        ]);
        assert!(parse_pool(&[]).is_empty());
    }

    #[test]
    fn test_rank_sorted_by_rtt() {
        let results = vec![
            ("20.205.243.166".parse::<IpAddr>().unwrap(), Duration::from_millis(80)),
            ("140.82.112.3".parse::<IpAddr>().unwrap(), Duration::from_millis(20)),
        ];
        let ranked = {
            let mut r = results;
            r.sort_by_key(|(_, d)| *d);
            r.into_iter().map(|(ip, _)| ip).collect::<Vec<_>>()
        };
        assert_eq!(ranked[0], "140.82.112.3".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_empty_pool_returns_empty() {
        let tls = TlsConnector::from(Arc::new(rustls::ClientConfig::builder().with_root_certificates(
            rustls::RootCertStore::empty(),
        ).with_no_client_auth()));
        let t = IpSpeedTester::new(tls);
        let ips = t.best_ips("github.com", &[]).await.unwrap();
        assert!(ips.is_empty());
    }
}
