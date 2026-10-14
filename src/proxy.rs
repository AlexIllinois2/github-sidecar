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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

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
    let ips = match core.resolve_host(&host).await {
        Ok(ips) => ips,
        Err(e) => {
            tracing::warn!("隧道 {host}:{port} 解析失败: {e}");
            Counters::inc(&core.counters.errors);
            let _ = client_io.shutdown().await;
            return;
        }
    };

    let mut target = try_connect_list(&host, port, &ips).await;

    // 恢复链：缓存里的优选 IP 可能已整体被墙（TCP 通但数据被丢 / 连接超时）。
    // 全部失败时强制重测池 → 仍不行再落回 DNS/系统解析，避免缓存挡住可用的兜底路径。
    if target.is_none() {
        let rule = core.match_rule(&host);
        if let Some(rule) = rule.as_ref().filter(|r| !r.ip_pool.is_empty()) {
            let fresh = core.speed.reprobe(&host, &rule.ip_pool).await.unwrap_or_default();
            if !fresh.is_empty() {
                tracing::info!("隧道 {host}:{port} 缓存 IP 全部失败，重测后用新优选结果重试");
                target = try_connect_list(&host, port, &fresh).await;
            }
        }
        // 池重测后仍全部不可用（或无池）→ 落回 DNS/系统解析兜底
        if target.is_none() {
            let fallback = if let Some(rule) = rule.as_ref().filter(|r| !r.dns_servers.is_empty()) {
                core.dns.resolve(&host, &rule.dns_servers).await
            } else {
                crate::state::system_resolve(&host).await
            };
            if let Ok(fb) = fallback {
                if !fb.is_empty() {
                    tracing::info!("隧道 {host}:{port} IP 池不可用，落回 DNS 解析重试");
                    target = try_connect_list(&host, port, &fb).await;
                }
            }
        }
    }

    match target {
        Some(mut server) => {
            tracing::debug!("隧道建立 {host}:{port}");
            Counters::inc(&core.counters.tunnel);
            if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut server).await {
                tracing::debug!("隧道 {host}:{port} 结束: {e}");
            }
        }
        None => {
            tracing::warn!("隧道 {host}:{port} 连不上: 所有候选（优选池/DNS）均失败");
            Counters::inc(&core.counters.errors);
            let _ = client_io.shutdown().await;
        }
    }
}

/// 依次尝试连接 IP 列表（resolve 已按 RTT/优先级排序）
async fn try_connect_list(host: &str, port: u16, ips: &[std::net::IpAddr]) -> Option<TcpStream> {
    let mut last_err = None;
    for ip in ips {
        let addr = SocketAddr::new(*ip, port);
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                tracing::debug!("隧道 {host}:{port} → {ip} 连接成功");
                return Some(s);
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
    let body = format!("dev-sidecar-rs: {}\n", msg.as_ref());
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
        .unwrap_or_else(|_| Response::new(empty_body()))
}
