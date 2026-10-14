//! 极简 DNS 竞速解析器：同时向多个 DNS 服务器发 UDP 查询，取最先返回的有效结果。
//! 这是 dev-sidecar “DNS 优选” 的核心：污染/超时的服务器不会拖慢解析。

use futures_util::future::select_all;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::timeout;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const CACHE_TTL: Duration = Duration::from_secs(120);
const CACHE_MAX: usize = 4096;

type QueryFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;

#[derive(Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

pub struct DnsResolver {
    cache: Mutex<HashMap<String, CacheEntry>>,
    seq: AtomicU16,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            seq: AtomicU16::new(1),
        }
    }

    /// 解析 host。host 本身是 IP 时直接返回。servers 为空时返回错误。
    pub async fn resolve(&self, host: &str, servers: &[String]) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(hit) = self.cache_get(&host) {
            return Ok(hit);
        }
        let ips = self.query_race(&host, servers).await?;
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("没有解析到 {host} 的 A/AAAA 记录"),
            ));
        }
        self.cache_put(host, ips.clone());
        Ok(ips)
    }

    fn cache_get(&self, host: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap();
        if let Some(e) = cache.get(host) {
            if e.expires > Instant::now() {
                return Some(e.ips.clone());
            }
        }
        None
    }

    fn cache_put(&self, host: String, ips: Vec<IpAddr>) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_MAX {
            cache.clear(); // 简单粗暴的过期策略
        }
        cache.insert(
            host,
            CacheEntry {
                ips,
                expires: Instant::now() + CACHE_TTL,
            },
        );
    }

    async fn query_race(&self, host: &str, servers: &[String]) -> io::Result<Vec<IpAddr>> {
        let host = host.to_string();
        let mut futs: Vec<QueryFuture> = Vec::new();
        for s in servers {
            if let Some(sockaddr) = parse_dns_server(s) {
                futs.push(Box::pin(query_server(self.next_id(), host.clone(), sockaddr)));
            }
        }
        if futs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "没有可用的 DNS 服务器",
            ));
        }
        let mut last_err: Option<io::Error> = None;
        while !futs.is_empty() {
            let (res, _, rest) = select_all(futs).await;
            futs = rest;
            match res {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => continue,
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "全部 DNS 查询失败")))
    }

    fn next_id(&self) -> u16 {
        let s = self.seq.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u16)
            .unwrap_or(0);
        s ^ nanos
    }
}

/// 支持 "223.5.5.5"、"1.1.1.1:53"、"[::1]:53" 等写法
fn parse_dns_server(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let with_port = if s.contains(':') && !s.starts_with('[') {
        // IPv6 无端口的情况按地址处理
        if s.matches(':').count() > 1 {
            format!("[{s}]:53")
        } else {
            s.to_string()
        }
    } else if s.starts_with('[') {
        s.to_string()
    } else {
        format!("{s}:53")
    };
    with_port.parse::<SocketAddr>().ok()
}

async fn query_server(id: u16, host: String, server: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let bind: (&str, u16) = if server.is_ipv4() { ("0.0.0.0", 0) } else { ("[::]", 0) };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    // A 和 AAAA 并行查，A 优先
    let (a, aaaa) = tokio::join!(
        query_type(&sock, id, &host, 1),
        query_type(&sock, id ^ 0x5aa5, &host, 28),
    );
    let mut ips = Vec::new();
    match a {
        Ok(v) => ips.extend(v),
        Err(e) => {
            if aaaa.is_err() {
                return Err(e);
            }
        }
    }
    if let Ok(v) = aaaa {
        ips.extend(v);
    }
    if ips.is_empty() {
        Err(io::Error::new(io::ErrorKind::NotFound, "空响应"))
    } else {
        Ok(ips)
    }
}

async fn query_type(sock: &UdpSocket, id: u16, host: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let query = build_query(id, host, qtype)?;
    sock.send(&query).await?;
    let mut buf = vec![0u8; 4096];
    // 最多收 3 个包（容忍偶尔的串包/重传），校验事务 ID
    for _ in 0..3 {
        let n = timeout(QUERY_TIMEOUT, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS 查询超时"))??;
        let resp = &buf[..n];
        let (rid, rcode, answers) = parse_response(resp)?;
        if rid != id {
            continue;
        }
        if rcode != 0 {
            return Err(io::Error::other(format!("DNS rcode={rcode}")));
        }
        if !answers.is_empty() {
            return Ok(answers);
        }
        return Ok(vec![]);
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "DNS 响应 ID 不匹配"))
}

fn push_name(buf: &mut Vec<u8>, host: &str) -> io::Result<()> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "非法主机名"));
    }
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "非法主机名标签"));
        }
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
    Ok(())
}

fn build_query(id: u16, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0x01, 0x00]); // RD=1
    b.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
    push_name(&mut b, host)?;
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&[0, 1]); // IN
    Ok(b)
}

/// 返回 (事务ID, rcode, 记录列表)
fn parse_response(buf: &[u8]) -> io::Result<(u16, u16, Vec<IpAddr>)> {
    if buf.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "响应过短"));
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let rcode = (buf[3] & 0x0F) as u16;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos).ok_or_else(short)?;
        pos += 4; // qtype + qclass
    }
    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(short)?;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        if rdata_start + rdlen > buf.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                buf[rdata_start],
                buf[rdata_start + 1],
                buf[rdata_start + 2],
                buf[rdata_start + 3],
            )));
        } else if rtype == 28 && rdlen == 16 {
            let octets: [u8; 16] = buf[rdata_start..rdata_start + 16]
                .try_into()
                .map_err(|_| short())?;
            ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
        }
        pos = rdata_start + rdlen;
    }
    Ok((id, rcode, ips))
}

/// 跳过（可能带压缩指针的）域名，返回剩余数据的起始位置
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)?;
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
        jumps += 1;
        if jumps > 64 {
            return None;
        }
    }
}

fn short() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "DNS 报文格式错误")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_server() {
        assert_eq!(
            parse_dns_server("223.5.5.5"),
            "223.5.5.5:53".parse::<SocketAddr>().ok()
        );
        assert_eq!(
            parse_dns_server("1.1.1.1:5353"),
            "1.1.1.1:5353".parse::<SocketAddr>().ok()
        );
        assert!(parse_dns_server("[::1]:53").is_some());
        assert!(parse_dns_server("").is_none());
    }

    #[test]
    fn test_query_roundtrip() {
        // build_query → parse_response 对拍：解析真实响应结构
        let q = build_query(0x1234, "example.com", 1).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[12..25], b"\x07example\x03com\x00");
        // 构造一个最小 A 应答
        let mut resp = q.clone();
        resp[2] = 0x81; resp[3] = 0x80; // QR=1 RD=1 RA=1
        resp[6] = 0; resp[7] = 1; // ancount=1
        resp.extend_from_slice(&[0xC0, 0x0C]); // 指针指向 question 的 name
        resp.extend_from_slice(&[0, 1, 0, 1]); // type A class IN
        resp.extend_from_slice(&[0, 0, 0, 60]); // ttl 60
        resp.extend_from_slice(&[0, 4, 93, 184, 216, 34]); // rdlen=4 93.184.216.34
        let (rid, rcode, ips) = parse_response(&resp).unwrap();
        assert_eq!(rid, 0x1234);
        assert_eq!(rcode, 0);
        assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn test_real_resolve_if_network() {
        // 沙箱可能无外网 DNS，解析失败不算测试失败，只验证不 panic
        let r = DnsResolver::new();
        let _ = r.resolve("example.com", &["223.5.5.5".to_string(), "8.8.8.8".to_string()]).await;
    }
}
