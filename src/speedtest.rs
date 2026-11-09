//! IP 测速优选（dev-sidecar 的“IP 优选”）：
//! 对规则配置的候选 IP 池并发做 TCP + TLS 握手（SNI=目标域名，正常证书校验），
//! 取最快的可用 IP 直连。TLS 探测同时验证“可达”与“该 IP 确实服务此域名”，
//! 避免把 github.com 的边缘 IP 误用到 raw.githubusercontent.com 这类不同 CDN 的域名上。
//!
//! 仅探测 443/TLS：池面向 HTTPS 加速场景，纯 HTTP 域名自然落回 DNS/系统解析。

use crate::goodip::LastGood;
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
/// 第一轮 12 个候选全部失败时，立即补测一轮的截止时间。
/// 实测“整批瞬时全挂”后几十秒内会恢复，补测一轮比干等 4 秒间隔更快
const PROBE_DEADLINE_RETRY: Duration = Duration::from_secs(3);
/// 测速结果缓存时长，过期后后台重测（stale-while-revalidate，不再阻塞请求）
const CACHE_TTL: Duration = Duration::from_secs(300);
/// 全部候选失败后的负缓存时长。旧逻辑把空结果当成“刚测过”缓存 5 分钟，
/// 于是一次瞬时全挂会变成整整 5 分钟的 DNS 兜底（DNS 常给到坏 IP），
/// 表现为“时好时坏、恢复很慢”。改为 30 秒后重试。
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
/// 同一 host 两次强制重测的最小间隔，避免故障期每个失败请求都触发一轮 12 候选探测
const REPROBE_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// 上一轮全部失败（空结果）时的重测间隔。启动/网络抖动期常见“整批瞬时全挂”，
/// 实测 20 秒后同一批候选就能恢复；等 NEGATIVE_TTL(30s) 会白等太久。
/// 请求路径不阻塞，只是在后台每 4 秒补一轮探测。
const EMPTY_REPROBE_INTERVAL: Duration = Duration::from_secs(4);
/// 被看门狗判定数据面卡死的 IP 的冷却时间：冷却期内重新探测也不会把它排回第一，
/// 避免“剔除 → 下次探测又选中 → 继续慢”的循环（实测坏 IP 的 TCP+TLS+探测请求仍可能通过）。
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
    /// 被看门狗判定卡死的 (host, IP) 及时间戳：冷却期内解析结果里直接剔除。
    /// 按 host 区分很重要：同一个边缘 IP 对 github.com 黑，不代表对 api.github.com 也黑。
    bad: Mutex<HashMap<(String, IpAddr), Instant>>,
    /// 数据面停顿的累计次数（(host, IP) → (次数, 最近时间)），用于“连续两次才判坏”
    strikes: Mutex<HashMap<(String, IpAddr), (u32, Instant)>>,
    tls: TlsConnector,
    /// 上次真正可用的 IP（落盘，冷启动复用）
    good: Arc<LastGood>,
}

impl IpSpeedTester {
    pub fn new(tls: TlsConnector, good: Arc<LastGood>) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            bad: Mutex::new(HashMap::new()),
            strikes: Mutex::new(HashMap::new()),
            tls,
            good,
        }
    }

    /// 冷启动预置：把落盘的上次可用 IP 放进缓存，时间戳设为已过期——
    /// 下一个请求立即拿到 IP（不再盲试/DNS），同时 best_ips 会自动触发后台重测。
    pub async fn seed(&self, host: &str, ips: Vec<IpAddr>, candidates: usize) {
        if ips.is_empty() {
            return;
        }
        self.cache.write().await.insert(
            host.to_string(),
            CacheEntry {
                ips,
                candidates,
                tested_at: Instant::now() - CACHE_TTL - Duration::from_secs(1),
            },
        );
    }

    /// 剔除冷却期内的坏 IP（按 host）。全部都在冷却期时退回原列表，宁可继续试也不返回空。
    pub fn filter_bad(&self, host: &str, ips: Vec<IpAddr>) -> Vec<IpAddr> {
        if ips.is_empty() {
            return ips;
        }
        let now = Instant::now();
        let mut marked_bad = self.bad.lock().unwrap();
        marked_bad.retain(|_, t| now.duration_since(*t) < BAD_COOLDOWN);
        let kept: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| !marked_bad.contains_key(&(host.to_string(), *ip)))
            .collect();
        if kept.is_empty() {
            ips
        } else {
            kept
        }
    }

    /// 启动时对落盘的 IP 做一次轻量可用性校验，返回仍然可用的子集
    pub async fn validate(&self, host: &str, ips: &[IpAddr]) -> Vec<IpAddr> {
        let Ok(name) = ServerName::try_from(host.to_ascii_lowercase()) else {
            return Vec::new();
        };
        probe_all(host, &name, ips, self.tls.clone(), PROBE_DEADLINE_RETRY)
            .await
            .into_iter()
            .map(|(ip, _)| ip)
            .collect()
    }

    /// 隧道真正拿到了应用层响应时记录，作为下次冷启动的首选 IP
    pub fn record_good(&self, host: &str, ip: IpAddr, source: &str) {
        self.good.record(host, ip, source);
    }

    /// 返回该 host 当前可用的 IP（按实测 RTT 升序）。
    /// - 缓存新鲜：直接命中
    /// - 缓存过期：立即返回旧值并在后台单飞重测（不阻塞请求）
    /// - 无缓存但有落盘的上次可用 IP：立即拿来用（时间戳记为过期），同时后台重测
    /// - 无缓存也无历史：启动后台探测并立即返回空（调用方马上落回 DNS 竞速），
    ///   首个请求不再串行等 4 秒探针；探测结果供后续连接使用
    /// - 上次探测全挂：负缓存内返回空，但每 EMPTY_REPROBE_INTERVAL 补测一轮，
    ///   避免一次瞬时全挂要等满 30 秒才恢复
    pub async fn best_ips(self: &Arc<Self>, host: &str, pool: &[String]) -> io::Result<Vec<IpAddr>> {
        if let Some(entry) = self.cached(host).await {
            if !entry.ips.is_empty() {
                if entry.tested_at.elapsed() < CACHE_TTL {
                    return Ok(entry.ips);
                }
                self.spawn_refresh(host.to_string(), pool.to_vec());
                return Ok(entry.ips);
            }
            if entry.tested_at.elapsed() >= EMPTY_REPROBE_INTERVAL {
                self.spawn_refresh(host.to_string(), pool.to_vec());
            }
            return Ok(vec![]);
        }
        // 无缓存：磁盘里有上次可用的 IP 就先复用（这是冷启动“直接能连上”的关键），
        // 时间戳设为已过期 → 顺手在后台做一轮真实重测，结果不可信时由连接失败兜底
        let persisted = self.good.ips(host);
        if !persisted.is_empty() {
            tracing::info!(
                "冷启动复用上次可用 IP {host} → {:?}（后台重测中）",
                persisted
            );
            self.seed(host, persisted.clone(), pool.len()).await;
            self.spawn_refresh(host.to_string(), pool.to_vec());
            return Ok(persisted);
        }
        // 无缓存：后台探测，不阻塞首个请求
        self.spawn_refresh(host.to_string(), pool.to_vec());
        Ok(vec![])
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
            let min_age = if entry.ips.is_empty() {
                // 空结果：允许较快补测（启动/抖动恢复）；非空则按 force 区分
                EMPTY_REPROBE_INTERVAL
            } else if force {
                REPROBE_MIN_INTERVAL
            } else {
                CACHE_TTL
            };
            if entry.tested_at.elapsed() < min_age {
                return Ok(entry.ips);
            }
        }
        self.probe_and_cache(host, pool, false).await
    }

    /// 后台单飞刷新：多个并发请求只会有一个真正探测，其余发现刚测过就直接返回。
    fn spawn_refresh(self: &Arc<Self>, host: String, pool: Vec<String>) {
        let this = self.clone();
        tokio::spawn(async move {
            let gate = this.gate(&host);
            let _guard = gate.lock().await;
            let within = match this.cached(&host).await {
                Some(e) if e.ips.is_empty() => EMPTY_REPROBE_INTERVAL,
                _ => REPROBE_MIN_INTERVAL,
            };
            if this.recent(&host, within).await {
                return;
            }
            let _ = this.probe_and_cache(&host, &pool, true).await;
        });
    }

    /// retry_on_empty：第一轮全挂时是否立即补测一轮（仅后台刷新使用；
    /// 请求路径上的强制重测保持单轮 4 秒上限，避免拖长浏览器重试周期）。
    async fn probe_and_cache(&self, host: &str, pool: &[String], retry_on_empty: bool) -> io::Result<Vec<IpAddr>> {
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
        let mut results = probe_all(host, &name, &candidates, self.tls.clone(), PROBE_DEADLINE).await;
        if results.is_empty() && retry_on_empty {
            // 启动/抖动期常见整批瞬时全挂：不要等下一次 4 秒轮询，立即补测一轮
            tracing::warn!(
                "IP 优选 {host}：第一轮 {} 个候选全部失败，立即补测一轮",
                candidates.len()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            results = probe_all(host, &name, &candidates, self.tls.clone(), PROBE_DEADLINE_RETRY)
                .await;
        }
        results.sort_by_key(|(_, d)| *d);
        // 剔除冷却期内的坏 IP。实测坏 IP 的 TCP+TLS+探测请求仍可能通过，单靠探测
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
                .filter(|(ip, _)| !marked_bad.contains_key(&(host.to_string(), *ip)))
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
        // 把可用 IP 落盘，供下次冷启动直接复用（只记前几个，避免文件频繁变脏）
        for ip in ips.iter().take(3) {
            self.good.record(host, *ip, "probe");
        }
        Ok(ips)
    }

    /// 隧道数据面停顿（已有数据往来后上游持续静默）时调用。
    /// 单次不停用；同一 IP 在 STALL_STRIKE_WINDOW 内累计 2 次才按坏 IP 冷却，
    /// 避免把“只是某次响应慢”的健康 IP 误剔除。
    pub async fn record_stall(&self, host: &str, ip: IpAddr) {
        let now = Instant::now();
        let key = (host.to_string(), ip);
        let strike = {
            let mut strikes = self.strikes.lock().unwrap();
            strikes.retain(|_, (_, t)| now.duration_since(*t) < STALL_STRIKE_WINDOW);
            let e = strikes.entry(key.clone()).or_insert((0, now));
            e.0 += 1;
            e.1 = now;
            e.0
        };
        if strike >= 2 {
            self.strikes.lock().unwrap().remove(&key);
            tracing::warn!(
                "IP {ip} 在 {STALL_STRIKE_WINDOW:?} 内累计 {strike} 次数据面停顿，判为坏 IP 并冷却"
            );
            self.mark_bad(host, ip).await;
            return;
        }
        // 首次停顿：只做软降级（挪到列表末尾），让浏览器重试时换下一个候选，
        // 而不是再次撞上同一个 IP；短窗口内再次停顿才真正判坏。
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get_mut(host) {
            if entry.ips.len() > 1 {
                if let Some(pos) = entry.ips.iter().position(|x| *x == ip) {
                    let stalled = entry.ips.remove(pos);
                    entry.ips.push(stalled);
                    tracing::info!("IP {ip} 数据面停顿，已降到 {host} 候选列表末尾");
                }
            }
        }
    }

    /// 隧道判定数据面卡死时调用：记录坏 IP 冷却时间，并从当前列表剔除。
    /// 若列表被清空，保留空条目做负缓存（下一次请求立即落回 DNS，不再同步等探针），
    /// NEGATIVE_TTL 后自动重测；探测也会在 BAD_COOLDOWN 内避开该 IP。
    pub async fn mark_bad(&self, host: &str, ip: IpAddr) {
        self
            .bad
            .lock()
            .unwrap()
            .insert((host.to_string(), ip), Instant::now());
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

async fn probe_all(
    host: &str,
    name: &ServerName<'static>,
    ips: &[IpAddr],
    tls: TlsConnector,
    deadline: Duration,
) -> Vec<(IpAddr, Duration)> {
    let futs = ips.iter().map(|&ip| {
        let tls = tls.clone();
        let name = name.clone();
        let host = host.to_string();
        async move {
            let start = Instant::now();
            let ok = probe_one(ip, &host, name, tls, deadline).await.is_ok();
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

/// TCP 建连 + TLS 握手 + 一个最小 GET 请求（SNI=目标域名，证书校验与上游客户端一致）。
/// 只看握手会漏掉「TCP/TLS 可通但数据面被黑洞/限速」的 IP——这类 IP 会握手成功、
/// 随后字节永远不到，浏览器就挂在这里。因此真的拉取一小段响应体，并按完整耗时排序，
/// 比纯握手 RTT 更接近实际吞吐。
/// 用 GET 而不是 HEAD：个别边缘/防护会对 HEAD 直接断开或返回空；任何 HTTP 状态
/// （含 301/403/429）都算“存活”，只要首块响应字节到达即可，不做 2xx 判定。
/// 整个探测（TCP+TLS+HTTP）受 PROBE_DEADLINE 约束，避免个别不可用 IP 拖慢整批。
async fn probe_one(
    ip: IpAddr,
    host: &str,
    name: ServerName<'static>,
    tls: TlsConnector,
    deadline: Duration,
) -> io::Result<()> {
    let addr = SocketAddr::new(ip, PROBE_PORT);
    let host = host.to_string();
    tokio::time::timeout(deadline, async move {
        let tcp = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP 连接超时"))??;
        let _ = tcp.set_nodelay(true);
        let mut tls = tokio::time::timeout(PROBE_TIMEOUT, tls.connect(name, tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS 握手超时"))??;
        tokio::time::timeout(PROBE_TIMEOUT, async {
            let req = format!(
                "GET /robots.txt HTTP/1.1\r\nHost: {host}\r\nUser-Agent: github-sidecar-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            );
            tls.write_all(req.as_bytes()).await?;
            let mut buf = [0u8; 256];
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
        let good = Arc::new(LastGood::load(std::env::temp_dir().join("github-sidecar-test-last-good.json")));
        let t = Arc::new(IpSpeedTester::new(tls, good));
        let ips = t.best_ips("github.com", &[]).await.unwrap();
        assert!(ips.is_empty());
    }
}
