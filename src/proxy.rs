//! HTTP 代理引擎：
//! - 明文 HTTP：解析请求 → （可选重定向）→ 通过带连接池的客户端转发
//! - CONNECT：按规则决定盲隧道（直连/DNS 竞速/IP 直连）或 MITM 解密转发

use crate::state::{BoxBody, Core, Counters};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HOST, LOCATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// 单个候选 IP 的建连超时。候选是逐个尝试的，取值过大时 12 个不可达 IP
/// 会串行累计到 30s+（正好是"打开很慢"的来源之一）；国内到 GitHub 的 RTT
/// 通常 200~400ms，1.5s 足够区分"可连"与"被丢包"。
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
/// 有规则加速域名（IP 池/DNS 竞速）的整批连接预算
const CONNECT_BUDGET_ACCEL: Duration = Duration::from_secs(4);
/// 无规则域名的整体连接预算：系统代理若被配成手动模式，这些域名也会进来，
/// 必须快速失败，不能靠逐个 IP 串行超时把浏览器的连接池占满。
const CONNECT_BUDGET_PLAIN: Duration = Duration::from_millis(2500);
/// 上游「首字节」看门狗：CONNECT 建立后浏览器会立刻发 ClientHello，若选中的 IP
/// 握手成功但数据面被黑洞（GFW 常见：握手放行、之后字节永不返回），浏览器会一直
/// 挂到超时。3 秒内上游没有回任何一个字节就判定该 IP 假活，剔除并断开，
/// 让浏览器立刻换下一个 IP 重试。已有数据往来后由下面的数据面看门狗继续监督。
const UPSTREAM_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(3);
/// 上游「数据面」看门狗：握手已收到数据后，若客户端在最后一次上游进展之后又发了
/// 数据，而上游持续静默超过该时长，判定该 IP 数据面停顿（GFW 常见的握手放行、
/// 之后限速/黑洞）。实测有 0.2s 完成握手却总耗时 3.48s 的样本。
const UPSTREAM_STALL_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn run(core: Arc<Core>) -> anyhow::Result<()> {
    let settings = core.settings();
    let addr = format!("{}:{}", settings.listen_host, settings.proxy_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("HTTP 代理已监听 {addr}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept 失败: {e}");
                continue;
            }
        };
        let core = core.clone();
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let core = core.clone();
                async move {
                    let resp = handle_request(req, core, peer).await;
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });
            let _ = http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        });
    }
}

async fn handle_request(req: Request<Incoming>, core: Arc<Core>, peer: SocketAddr) -> Response<BoxBody> {
    Counters::inc(&core.counters.total);
    if req.method() == Method::CONNECT {
        handle_connect(req, core, peer).await
    } else {
        forward(req, core, false, peer).await
    }
}

// ---------- CONNECT 处理 ----------

async fn handle_connect(mut req: Request<Incoming>, core: Arc<Core>, peer: SocketAddr) -> Response<BoxBody> {
    let Some(auth) = req.uri().authority().cloned() else {
        return err_resp(StatusCode::BAD_REQUEST, "CONNECT 缺少目标地址");
    };
    let host = auth.host().to_string();
    let port = auth.port_u16().unwrap_or(443);

    let settings = core.settings();
    let mitm = settings.mitm_all || core.needs_mitm_for(&host);

    let up = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match up.await {
            Ok(stream) => {
                if mitm {
                    serve_mitm(core, TokioIo::new(stream), host, peer).await;
                } else {
                    serve_tunnel(core, TokioIo::new(stream), host, port).await;
                }
            }
            Err(e) => {
                tracing::debug!("CONNECT upgrade 失败: {e}");
                Counters::inc(&core.counters.errors);
            }
        }
    });

    // 200 必须先返回，hyper 才会移交底层流
    Response::new(empty_body())
}

async fn serve_tunnel(core: Arc<Core>, mut client_io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static, host: String, port: u16) {
    let rule = core.match_rule(&host);
    let accelerated = rule
        .as_ref()
        .map(|r| !r.ip_pool.is_empty() || !r.dns_servers.is_empty())
        .unwrap_or(false);
    let budget = if accelerated {
        CONNECT_BUDGET_ACCEL
    } else {
        CONNECT_BUDGET_PLAIN
    };

    let ips = match core.resolve_host(&host).await {
        Ok(ips) => ips,
        Err(e) => {
            tracing::warn!("隧道 {host}:{port} 解析失败: {e}");
            Counters::inc(&core.counters.errors);
            let _ = client_io.shutdown().await;
            return;
        }
    };

    let mut target = try_connect_list(&host, port, &ips, budget).await;

    // 恢复链：只对"有 IP 池"的加速域名有意义（缓存里的优选 IP 可能已整体被墙）。
    // 无规则域名不做二次解析重试——同一批 IP 再试一次只会成倍拖长失败时间。
    if target.is_none() {
        if let Some(rule) = rule.as_ref() {
            if !rule.ip_pool.is_empty() {
                let fresh = core.speed.reprobe(&host, &rule.ip_pool).await.unwrap_or_default();
                if !fresh.is_empty() {
                    tracing::info!("隧道 {host}:{port} 缓存 IP 全部失败，重测后用新优选结果重试");
                    target = try_connect_list(&host, port, &fresh, budget).await;
                }
                // 池仍不可用 → DNS 竞速兜底。DNS-only 规则的首次解析已经用过 DNS，不再重复。
                if target.is_none() && !rule.dns_servers.is_empty() {
                    if let Ok(fb) = core.dns.resolve(&host, &rule.dns_servers).await {
                        if !fb.is_empty() {
                            tracing::info!("隧道 {host}:{port} IP 池不可用，落回 DNS 解析重试");
                            target = try_connect_list(&host, port, &fb, budget).await;
                        }
                    }
                }
            }
        }
    }

    match target {
        Some((ip, server)) => {
            tracing::debug!("隧道建立 {host}:{port} → {ip}");
            Counters::inc(&core.counters.tunnel);
            match relay(client_io, server).await {
                TunnelOutcome::Done => {}
                TunnelOutcome::Stalled => {
                    tracing::warn!(
                        "隧道 {host}:{port} 上游 {ip} 在 {:?} 内未返回任何字节（假活/黑洞），已剔除该 IP 并断开，等待浏览器重试",
                        UPSTREAM_FIRST_BYTE_TIMEOUT
                    );
                    core.speed.mark_bad(&host, ip).await;
                }
                TunnelOutcome::DataStalled => {
                    // 单次停顿可能只是 GitHub 侧慢，先断开让浏览器重试；同一 IP 在
                    // 短窗口内连续两次停顿才判定为坏 IP（避免误杀健康 IP 10 分钟）
                    tracing::warn!(
                        "隧道 {host}:{port} 上游 {ip} 数据面停顿超过 {:?}，断开等待浏览器重试",
                        UPSTREAM_STALL_TIMEOUT
                    );
                    core.speed.record_stall(&host, ip).await;
                }
            }
        }
        None => {
            if accelerated {
                tracing::warn!("隧道 {host}:{port} 连不上: 所有候选（优选池/DNS）均失败");
            } else {
                tracing::debug!("隧道 {host}:{port} 无规则直连失败（快速失败）");
            }
            Counters::inc(&core.counters.errors);
            let _ = client_io.shutdown().await;
        }
    }
}

/// 依次尝试连接 IP 列表（resolve 已按 RTT/优先级排序）。
/// budget 是整批候选的总预算：超出后立即放弃，避免不可达 IP 逐个吃满超时。
async fn try_connect_list(host: &str, port: u16, ips: &[std::net::IpAddr], budget: Duration) -> Option<(std::net::IpAddr, TcpStream)> {
    let deadline = Instant::now() + budget;
    let mut last_err = None;
    for ip in ips {
        let step = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) if !remaining.is_zero() => remaining.min(CONNECT_TIMEOUT),
            _ => {
                last_err = Some(format!("整批连接预算 {budget:?} 已耗尽"));
                break;
            }
        };
        let addr = SocketAddr::new(*ip, port);
        match tokio::time::timeout(step, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                tracing::debug!("隧道 {host}:{port} → {ip} 连接成功");
                return Some((*ip, s));
            }
            Ok(Err(e)) => last_err = Some(e.to_string()),
            Err(_) => last_err = Some("连接超时".into()),
        }
    }
    if let Some(e) = last_err {
        tracing::debug!("隧道 {host}:{port} {} 个候选全部失败（最后错误: {e}）", ips.len());
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelOutcome {
    Done,
    /// 上游在首字节超时内没有任何响应（握手成功但数据面黑洞）
    Stalled,
    /// 上游已有数据往来后，在客户端再次发数据的情况下持续静默
    DataStalled,
}

/// 看门狗判定结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StallKind {
    /// 一个字节都没收到：假活/黑洞，可直接判坏
    FakeAlive,
    /// 收到过数据后停顿：可能是瞬时抖动，需累计命中
    DataStalled,
}

/// 双向转发，并在整个连接生命周期监督“上游是否在持续推进”。
/// 空闲超过 IDLE_GIVEUP 且无异常时停止监控，不误杀长连接。
async fn relay(
    client_io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    server: TcpStream,
) -> TunnelOutcome {
    let (client_r, mut client_w) = tokio::io::split(client_io);
    let (server_r, mut server_w) = tokio::io::split(server);
    let client_bytes = Arc::new(AtomicU64::new(0));
    let server_bytes = Arc::new(AtomicU64::new(0));
    let mut client_r = CountingReader {
        inner: client_r,
        count: client_bytes.clone(),
    };
    let mut server_r = CountingReader {
        inner: server_r,
        count: server_bytes.clone(),
    };

    let c2s = async move {
        let _ = tokio::io::copy(&mut client_r, &mut server_w).await;
        let _ = server_w.shutdown().await;
    };
    let s2c = async move {
        let _ = tokio::io::copy(&mut server_r, &mut client_w).await;
        let _ = client_w.shutdown().await;
    };
    tokio::pin!(c2s, s2c);

    let stalled = watchdog(client_bytes.clone(), server_bytes.clone());
    tokio::pin!(stalled);

    tokio::select! {
        _ = &mut c2s => return TunnelOutcome::Done,
        _ = &mut s2c => return TunnelOutcome::Done,
        kind = &mut stalled => {
            match kind {
                Some(StallKind::FakeAlive) => return TunnelOutcome::Stalled,
                Some(StallKind::DataStalled) => return TunnelOutcome::DataStalled,
                None => {}
            }
        }
    }
    // 看门狗已放弃监控（连接空闲或正常）：继续等任一方向自然结束
    tokio::select! {
        _ = &mut c2s => {}
        _ = &mut s2c => {}
    }
    TunnelOutcome::Done
}

/// 上游双向看门狗：
/// - 首字节阶段：客户端已发数据但上游迟迟一个字节都不回 → 假活
/// - 数据面阶段：上游已有进展后，客户端又发出了新数据（请求/窗口更新），
///   而上游持续静默超过 UPSTREAM_STALL_TIMEOUT → 数据面停顿
/// 完全空闲（双方都无数据变化）超过 IDLE_GIVEUP 则停止监控，不干扰长连接。
async fn watchdog(client_bytes: Arc<AtomicU64>, server_bytes: Arc<AtomicU64>) -> Option<StallKind> {
    const TICK: Duration = Duration::from_millis(100);
    /// 双方都无字节变化的空闲上限：超过即放弃监控，让连接自然存活
    const IDLE_GIVEUP: Duration = Duration::from_secs(30);
    let begin = Instant::now();
    let mut first_send: Option<Instant> = None;
    let mut last_server = 0u64;
    let mut last_progress_at = Instant::now();
    let mut client_at_progress = 0u64;
    loop {
        tokio::time::sleep(TICK).await;
        let client = client_bytes.load(Ordering::Relaxed);
        let server = server_bytes.load(Ordering::Relaxed);

        if server > last_server {
            last_server = server;
            last_progress_at = Instant::now();
            client_at_progress = client;
        }
        if server == 0 {
            // 尚无任何上游字节：从客户端首次发数据起算首字节超时
            match first_send {
                Some(t) if t.elapsed() >= UPSTREAM_FIRST_BYTE_TIMEOUT => {
                    return Some(StallKind::FakeAlive)
                }
                Some(_) => {}
                None if client > 0 => first_send = Some(Instant::now()),
                None if begin.elapsed() >= IDLE_GIVEUP => return None,
                None => {}
            }
        } else {
            // 已收到上游数据：只在客户端“有未回应的新数据”时判停顿，
            // 避免把合法的慢响应/长连接当成坏 IP
            if client > client_at_progress && last_progress_at.elapsed() >= UPSTREAM_STALL_TIMEOUT {
                return Some(StallKind::DataStalled);
            }
            if last_progress_at.elapsed() >= IDLE_GIVEUP && client == client_at_progress {
                return None;
            }
        }
    }
}

/// 只统计单向字节数，用于判断客户端是否发出数据、上游是否开始回数据
struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            this.count
                .fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        }
        res
    }
}

async fn serve_mitm(core: Arc<Core>, stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static, host: String, peer: SocketAddr) {
    let cfg = match core.ca.server_config_for(&host) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("为 {host} 签发证书失败: {e}（连接将中断）");
            Counters::inc(&core.counters.errors);
            return;
        }
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    match acceptor.accept(stream).await {
        Ok(tls) => {
            tracing::debug!("MITM 解密 {host}");
            Counters::inc(&core.counters.mitm);
            let io = TokioIo::new(tls);
            let svc = service_fn(move |req: Request<Incoming>| {
                let core = core.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(forward(req, core, true, peer).await)
                }
            });
            let _ = http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        }
        Err(e) => {
            tracing::debug!("TLS 握手失败 ({host}): {e}");
            Counters::inc(&core.counters.errors);
        }
    }
}

// ---------- 明文 / MITM 请求转发 ----------

async fn forward(req: Request<Incoming>, core: Arc<Core>, is_mitm: bool, peer: SocketAddr) -> Response<BoxBody> {
    let method = req.method().clone();
    let settings = core.settings();
    let insecure = settings.insecure_tls;

    // 1. 还原完整 URI。MITM 内层是 origin-form，需要用 Host 头拼出 https://host/path
    let mut uri = req.uri().clone();
    if is_mitm && uri.host().is_none() {
        let host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        if host.is_empty() {
            return err_resp(StatusCode::BAD_REQUEST, "缺少 Host 头");
        }
        match Uri::builder()
            .scheme("https")
            .authority(host.trim_end_matches('.'))
            .path_and_query(uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"))
            .build()
        {
            Ok(u) => uri = u,
            Err(e) => return err_resp(StatusCode::BAD_REQUEST, format!("Host 头非法: {e}")),
        }
    }
    let Some(host) = uri.host().map(|h| h.trim_end_matches('.').to_string()) else {
        return err_resp(StatusCode::BAD_REQUEST, "请求缺少目标主机");
    };
    let path = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let scheme = uri.scheme_str().unwrap_or(if is_mitm { "https" } else { "http" }).to_string();
    let authority = uri
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| host.clone());

    // 2. 镜像重定向
    if method == Method::GET || method == Method::HEAD {
        if let Some(rule) = core.match_rewrite(&host, &path) {
            Counters::inc(&core.counters.rewrite);
            let base = rule.rewrite_to.trim_end_matches('/');
            let location = if rule.full_url {
                format!("{base}/{scheme}://{authority}{path}")
            } else {
                format!("{base}{path}")
            };
            tracing::info!("重定向 {method} {authority}{path} → {location}");
            if let Ok(resp) = Response::builder()
                .status(StatusCode::FOUND)
                .header(LOCATION, &location)
                .body(empty_body())
            {
                return resp;
            }
        }
    }

    // 3. 构造上游请求
    let (mut parts, body) = req.into_parts();
    strip_hop_headers(&mut parts.headers);
    parts.uri = uri;

    // 重试模板：body 是流式不可克隆，仅在无副作用的请求（GET/HEAD 等）失败时才能重建重试
    let retry_tpl = (parts.method.clone(), parts.uri.clone(), parts.headers.clone());
    let retryable = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE);

    let client = core.client().clone();
    let mut result = client.request(Request::from_parts(parts, body.boxed())).await;

    if result.is_err() {
        // 上游连接失败且该域名有 IP 池：缓存的优选 IP 可能已整体被墙，强制重测后重试一次
        if let Some(rule) = core.match_rule(&host).filter(|r| !r.ip_pool.is_empty() && retryable) {
            let fresh = core.speed.reprobe(&host, &rule.ip_pool).await.unwrap_or_default();
            tracing::info!(
                "{peer} {method} {authority} 上游失败，IP 池重测（{}/{} 可用）后重试",
                fresh.len(),
                rule.ip_pool.len()
            );
            let (m, u, h) = retry_tpl;
            let mut builder = Request::builder().method(m).uri(u);
            for (k, v) in h.iter() {
                builder = builder.header(k.clone(), v.clone());
            }
            let built = builder.body(empty_body());
            if let Ok(req2) = built {
                result = client.request(req2).await;
            }
        }
    }

    match result {
        Ok(resp) => {
            let status = resp.status();
            let (mut parts, body) = resp.into_parts();
            strip_hop_headers(&mut parts.headers);
            tracing::info!("{peer} {method} {scheme}://{authority}{path} → {status}{}", insecure_hint(insecure));
            Response::from_parts(parts, body.boxed())
        }
        Err(e) => {
            tracing::warn!("{peer} {method} {scheme}://{authority}{path} → 转发失败: {e}");
            Counters::inc(&core.counters.errors);
            err_resp(StatusCode::BAD_GATEWAY, format!("上游请求失败: {e}"))
        }
    }
}

fn insecure_hint(insecure: bool) -> &'static str {
    if insecure { " [TLS校验已关闭]" } else { "" }
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    let mut extra: Vec<String> = Vec::new();
    if let Some(v) = headers.get("connection").and_then(|v| v.to_str().ok()) {
        extra = v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
    }
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
    for h in extra {
        headers.remove(h);
    }
}

pub fn empty_body() -> BoxBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

pub fn err_resp<S: AsRef<str>>(status: StatusCode, msg: S) -> Response<BoxBody> {
    let body = format!("github-sidecar: {}\n", msg.as_ref());
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
        .unwrap_or_else(|_| Response::new(empty_body()))
}
