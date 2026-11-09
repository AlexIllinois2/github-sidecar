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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;

/// 单个候选 IP 的 TCP / TLS 单步超时
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// 单个候选 IP 的探测总截止时间（TCP + TLS + HTTP 存活校验），
/// 避免不可用 IP 串行拖慢首个请求
const PROBE_DEADLINE: Duration = Duration::from_secs(4);
/// 测速结果缓存时长，过期后后台重测（stale-while-revalidate，不再阻塞请求）
const CACHE_TTL: Duration = Duration::from_secs(300);
/// 全部候选失败后的负缓存时长。旧逻辑把空结果当成“刚测过”缓存 5 分钟，
/// 于是一次瞬时全挂会变成整整 5 分钟的 DNS 兜底（DNS 常给到坏 IP），
/// 表现为“时好时坏、恢复很慢”。改为 30 秒后重试。
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
/// 同一 host 两次强制重测的最小间隔，避免故障期每个失败请求都触发一轮 12 候选探测
const REPROBE_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// 被看门狗判定数据面卡死的 IP 的冷却时间：冷却期内重新探测也不会把它排回第一，
/// 避免“剔除 → 下次探测又选中 → 继续慢”的循环（实测坏 IP 的握手仍能通过 HEAD）。
const BAD_COOLDOWN: Duration = Duration::from_secs(600);
/// 数据面停顿的累计窗口：同一 IP 在该窗口内累计 2 次停顿才判坏。
/// 单次停顿可能只是 GitHub 侧响应慢，立即剔除会误伤健康 IP 10 分钟。
const STALL_STRIKE_WINDOW: Duration = Duration::from_secs(180);
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
    /// 每个 host 一把探测锁：并发请求只允许一个真正探测，其余等待后复用结果
    gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// 被看门狗判定卡死的 IP 及时间戳：冷却期内探测结果里直接剔除
    bad: Mutex<HashMap<IpAddr, Instant>>,
    /// 数据面停顿的累计次数（IP → (次数, 最近时间)），用于“连续两次才判坏”
    strikes: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    tls: TlsConnector,
}

impl IpSpeedTester {
    pub fn new(tls: TlsConnector) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            bad: Mutex::new(HashMap::new()),
            strikes: Mutex::new(HashMap::new()),
            tls,
        }
    }

    /// 返回该 host 当前可用的 IP（按 RTT 升序）。
    /// - 缓存新鲜：直接命中
    /// - 缓存过期：立即返回旧值并在后台单飞重测（不阻塞请求）
    /// - 无缓存：单飞探测并等待结果
    /// - 上次探测全挂：负缓存 NEGATIVE_TTL 内直接返回空（调用方落回 DNS 竞速），
    ///   到期后后台重测，避免一次瞬时全挂被当成 5 分钟有效结果
    pub async fn best_ips(self: &Arc<Self>, host: &str, pool: &[String]) -> io::Result<Vec<IpAddr>> {
        if let Some(entry) = self.cached(host).await {
            if !entry.ips.is_empty() {
                if entry.tested_at.elapsed() < CACHE_TTL {
                    return Ok(entry.ips);
                }
                self.spawn_refresh(host.to_string(), pool.to_vec());
                return Ok(entry.ips);
            }
            if entry.tested_at.elapsed() >= NEGATIVE_TTL {
                self.spawn_refresh(host.to_string(), pool.to_vec());
            }
            return Ok(vec![]);
        }
        self.refresh(host, pool, false).await
    }

    /// 忽略缓存强制重测。连接失败后调用：缓存里的"最优 IP"可能已整体被墙，
    /// 重测既能恢复也能及时暴露"全死"状态（返回空 → 调用方落回 DNS 兜底）。
    /// 并发调用会被单飞合并；同一 host 在 REPROBE_MIN_INTERVAL 内不会重复探测。
    pub async fn reprobe(self: &Arc<Self>, host: &str, pool: &[String]) -> io::Result<Vec<IpAddr>> {
        self.refresh(host, pool, true).await
    }

    async fn refresh(self: &Arc<Self>, host: &str, pool: &[String], force: bool) -> io::Result<Vec<IpAddr>> {
        let gate = self.gate(host);
        let _guard = gate.lock().await;
        if let Some(entry) = self.cached(host).await {
            let min_age = if force {
                REPROBE_MIN_INTERVAL
            } else if entry.ips.is_empty() {
                NEGATIVE_TTL
            } else {
                CACHE_TTL
            };
            if entry.tested_at.elapsed() < min_age {
                return Ok(entry.ips);
            }
        }
        self.probe_and_cache(host, pool).await
    }

    /// 后台单飞刷新：多个并发请求只会有一个真正探测，其余发现刚测过就直接返回。
    fn spawn_refresh(self: &Arc<Self>, host: String, pool: Vec<String>) {
        let this = self.clone();
        tokio::spawn(async move {
            let gate = this.gate(&host);
            let _guard = gate.lock().await;
            if this.recent(&host, REPROBE_MIN_INTERVAL).await {
                return;
            }
            let _ = this.probe_and_cache(&host, &pool).await;
        });
    }

    async fn probe_and_cache(&self, host: &str, pool: &[String]) -> io::Result<Vec<IpAddr>> {
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
        let mut results = probe_all(host, &name, &candidates, self.tls.clone()).await;
        results.sort_by_key(|(_, d)| *d);
        // 剔除冷却期内的坏 IP。实测坏 IP 的 TCP+TLS+HEAD 仍可能通过，单靠探测
        // 无法识别“握手正常、数据面卡死”，只能依赖隧道看门狗的失败记录。
        let all = results;
        // 先取上一轮首选（需要 await），再做同步过滤，避免非 Send 的锁守卫跨 await
        let prev = self.cached(host).await.and_then(|e| e.ips.first().copied());
        let now = Instant::now();
        // 用独立作用域持有锁：守卫在任何 await 之前析构，保证 future 是 Send
        let mut results: Vec<(IpAddr, Duration)> = {
            let mut marked_bad = self.bad.lock().unwrap();
            marked_bad.retain(|_, t| now.duration_since(*t) < BAD_COOLDOWN);
            all.iter()
                .filter(|(ip, _)| !marked_bad.contains_key(ip))
                .cloned()
                .collect()
        };
        if results.is_empty() {
            // 所有可用 IP 都在冷却期：宁可继续用也不返回空
            results = all;
        }
        let mut ips: Vec<IpAddr> = results.iter().map(|(ip, _)| *ip).collect();
        // 滞回：上一轮的首选如果仍然可用，继续让它当首选。避免每 5 分钟按
        // 握手 RTT 重排后切到一个“握手快、传输差”的 IP（实测会从 0.9s 变成 5s）。
        if let Some(prev) = prev {
            if let Some(pos) = ips.iter().position(|x| *x == prev) {
                let p = ips.remove(pos);
                ips.insert(0, p);
            }
        }
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

    /// 隧道数据面停顿（已有数据往来后上游持续静默）时调用。
    /// 单次不停用；同一 IP 在 STALL_STRIKE_WINDOW 内累计 2 次才按坏 IP 冷却，
    /// 避免把“只是某次响应慢”的健康 IP 误剔除。
    pub async fn record_stall(&self, host: &str, ip: IpAddr) {
        let now = Instant::now();
        let strike = {
            let mut strikes = self.strikes.lock().unwrap();
            strikes.retain(|_, (_, t)| now.duration_since(*t) < STALL_STRIKE_WINDOW);
            let e = strikes.entry(ip).or_insert((0, now));
            e.0 += 1;
            e.1 = now;
            e.0
        };
        if strike >= 2 {
            self.strikes.lock().unwrap().remove(&ip);
            tracing::warn!(
                "IP {ip} 在 {STALL_STRIKE_WINDOW:?} 内累计 {strike} 次数据面停顿，判为坏 IP 并冷却"
            );
            self.mark_bad(host, ip).await;
        }
    }

    /// 隧道判定数据面卡死时调用：记录坏 IP 冷却时间，并从当前列表剔除。
    /// 若列表被清空，保留空条目做负缓存（下一次请求立即落回 DNS，不再同步等探针），
    /// NEGATIVE_TTL 后自动重测；探测也会在 BAD_COOLDOWN 内避开该 IP。
    pub async fn mark_bad(&self, host: &str, ip: IpAddr) {
        self.bad.lock().unwrap().insert(ip, Instant::now());
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get_mut(host) {
            entry.ips.retain(|&x| x != ip);
            if entry.ips.is_empty() {
                entry.tested_at = Instant::now();
            }
        }
    }

    /// 背景刷新：对缓存中已过 TTL 的条目用当前规则池重测；
    /// 规则被删/禁用/池被清空的条目直接移除。get_pool 返回 None 或空池均视为移除。
    pub async fn retest_stale(self: &Arc<Self>, get_pool: impl Fn(&str) -> Option<Vec<String>>) {
        let stale: Vec<String> = {
            let cache = self.cache.read().await;
            cache
                .iter()
                .filter(|(_, e)| {
                    // 空结果（上次全挂）按负缓存时长重试，避免 5 分钟不恢复
                    if e.ips.is_empty() {
                        e.tested_at.elapsed() >= NEGATIVE_TTL
                    } else {
                        e.tested_at.elapsed() >= CACHE_TTL
                    }
                })
                .map(|(h, _)| h.clone())
                .collect()
        };
        for host in stale {
            match get_pool(&host) {
                Some(pool) if !pool.is_empty() => {
                    let _ = self.reprobe(&host, &pool).await;
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

    async fn cached(&self, host: &str) -> Option<CacheEntry> {
        self.cache.read().await.get(host).cloned()
    }

    async fn recent(&self, host: &str, within: Duration) -> bool {
        self.cached(host)
            .await
            .map(|e| e.tested_at.elapsed() < within)
            .unwrap_or(false)
    }

    /// 取（或创建）该 host 的探测锁
    fn gate(&self, host: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.gates
            .lock()
            .unwrap()
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
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

async fn probe_all(host: &str, name: &ServerName<'static>, ips: &[IpAddr], tls: TlsConnector) -> Vec<(IpAddr, Duration)> {
    let futs = ips.iter().map(|&ip| {
        let tls = tls.clone();
        let name = name.clone();
        let host = host.to_string();
        async move {
            let start = Instant::now();
            let ok = probe_one(ip, &host, name, tls).await.is_ok();
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

/// TCP 建连 + TLS 握手 + 一个最小 HEAD 请求（SNI=目标域名，证书校验与上游客户端一致）。
/// 只看握手会漏掉「TCP/TLS 可通但数据面被黑洞/限速」的 IP——这类 IP 会握手成功、
/// 随后字节永远不到，浏览器就挂在这里。因此要求真的收到上游响应字节。
/// 整个探测（TCP+TLS+HTTP）受 PROBE_DEADLINE 约束，避免个别不可用 IP 拖慢整批。
async fn probe_one(ip: IpAddr, host: &str, name: ServerName<'static>, tls: TlsConnector) -> io::Result<()> {
    let addr = SocketAddr::new(ip, PROBE_PORT);
    let host = host.to_string();
    tokio::time::timeout(PROBE_DEADLINE, async move {
        let tcp = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP 连接超时"))??;
        let _ = tcp.set_nodelay(true);
        let mut tls = tokio::time::timeout(PROBE_TIMEOUT, tls.connect(name, tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS 握手超时"))??;
        tokio::time::timeout(PROBE_TIMEOUT, async {
            let req = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            tls.write_all(req.as_bytes()).await?;
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "上游未返回数据"));
            }
            Ok::<(), io::Error>(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP 存活校验超时"))??;
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "探测总超时"))?
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
        let t = Arc::new(IpSpeedTester::new(tls));
        let ips = t.best_ips("github.com", &[]).await.unwrap();
        assert!(ips.is_empty());
    }
}
