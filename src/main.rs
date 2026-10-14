//! dev-sidecar-rs：用 Rust 重写的 dev-sidecar（开发者边车）。
//! 单二进制：HTTP 代理（DNS 竞速 / IP 直连 / 可选 MITM 重定向）+ 内置 Web 管理界面。

mod admin;
mod ca;
mod config;
mod dns;
mod logs;
mod proxy;
mod speedtest;
mod state;
mod systemproxy;

use anyhow::{Context, Result};
use clap::Parser;
use config::{Config, Settings};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// 开发者边车（Rust 版）：单二进制后台加速代理
#[derive(Parser, Debug)]
#[command(name = "dev-sidecar-rs", version, about)]
struct Args {
    /// 配置文件路径（默认 <数据目录>/config.json）
    #[arg(long)]
    config: Option<PathBuf>,
    /// 数据目录（存 CA 证书和配置，默认 ~/.config/dev-sidecar-rs）
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// 覆盖代理端口
    #[arg(long)]
    proxy_port: Option<u16>,
    /// 覆盖管理界面端口
    #[arg(long)]
    admin_port: Option<u16>,
    /// 不自动打开浏览器
    #[arg(long)]
    no_open: bool,
    /// 本次运行不设置系统代理（覆盖配置中的 autoSystemProxy）
    #[arg(long)]
    no_system_proxy: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let data_dir = args.data_dir.clone().unwrap_or_else(|| {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("dev-sidecar-rs")
    });
    let cfg_path = args.config.clone().unwrap_or_else(|| data_dir.join("config.json"));

    let mut cfg = Config::load(&cfg_path).context("读取配置失败")?;
    if let Some(p) = args.proxy_port {
        cfg.settings.proxy_port = p;
    }
    if let Some(p) = args.admin_port {
        cfg.settings.admin_port = p;
    }

    // 日志：stderr + 环形缓冲（管理界面拉取）
    let log_buffer = Arc::new(logs::LogBuffer::default());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(logs::DualLogWriter::new(log_buffer.clone()))
        .init();

    // rustls 全局 crypto provider（ring）
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = ca::CaManager::init(&data_dir).context("初始化根证书失败")?;
    let core = state::Core::new(cfg, cfg_path.clone(), ca, log_buffer.clone());
    let settings = core.settings();

    let admin_url = format!("http://{}:{}", settings.listen_host, settings.admin_port);
    let proxy_addr = format!("{}:{}", settings.listen_host, settings.proxy_port);

    // 代理和管理界面都没有鉴权，监听非回环地址等于对局域网开放
    let loopback = settings.listen_host == "localhost"
        || settings
            .listen_host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if !loopback {
        tracing::warn!(
            "监听地址 {} 不是回环地址：代理与管理界面均无鉴权，同网段的人都能用（也可能被用来中转）",
            settings.listen_host
        );
    }

    // 管理界面（独立线程）
    admin::spawn_admin(core.clone())?;

    // 主 runtime：代理引擎
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("创建 tokio runtime 失败")?;

    let run_core = core.clone();
    let run_settings = settings.clone();
    let no_system_proxy = args.no_system_proxy;
    let no_open = args.no_open;

    rt.block_on(async move {
        // 代理服务器
        let proxy_core = run_core.clone();
        let proxy_task = tokio::spawn(async move {
            if let Err(e) = proxy::run(proxy_core).await {
                tracing::error!("代理服务器启动失败: {e}");
                std::process::exit(1);
            }
        });

        // IP 池启动预热：对启用规则里的字面量 host（不含 *）提前测速，首个请求即命中缓存
        let warm_core = run_core.clone();
        tokio::spawn(async move {
            for rule in warm_core.rules() {
                if !rule.enabled || rule.ip_pool.is_empty() {
                    continue;
                }
                for host in rule.hosts.iter().filter(|h| !h.contains('*')) {
                    let _ = warm_core.speed.best_ips(host, &rule.ip_pool).await;
                }
            }
        });

        // IP 池背景刷新：周期性重测缓存里过期的条目（池被清空的条目会被移除）
        let refresh_core = run_core.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let core = refresh_core.clone();
                core.speed
                    .retest_stale(|host| {
                        core.match_rule(host)
                            .filter(|r| r.enabled)
                            .map(|r| r.ip_pool)
                    })
                    .await;
            }
        });

        // 等两个端口都就绪
        for _ in 0..100 {
            let ok_admin = tokio::net::TcpStream::connect(&run_core.settings().admin_string()).await.is_ok();
            let ok_proxy = tokio::net::TcpStream::connect(&run_core.settings().proxy_string()).await.is_ok();
            if ok_admin && ok_proxy {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        println!("──────────────────────────────────────────────");
        println!("  dev-sidecar-rs v{}", env!("CARGO_PKG_VERSION"));
        println!("  管理界面  {admin_url}");
        println!("  代理地址  {proxy_addr}");
        println!("  数据目录  {}", data_dir.display());
        println!("  CA 证书   {}（在管理界面下载安装）", data_dir.join("ca.crt").display());
        println!("  退出      Ctrl+C（若已设置系统代理会自动恢复）");
        println!("──────────────────────────────────────────────");
        tracing::info!("启动完成");

        // 自动设置系统代理
        let mut proxy_was_set = false;
        if run_settings.auto_system_proxy && !no_system_proxy {
            let (ok, msgs) =
                systemproxy::set_system_proxy(&run_settings.listen_host, run_settings.proxy_port);
            for m in &msgs {
                tracing::info!("{m}");
            }
            proxy_was_set = ok;
        }

        // 自动打开浏览器
        if run_settings.open_browser && !no_open {
            if let Err(e) = open::that_detached(&admin_url) {
                tracing::warn!("自动打开浏览器失败: {e}（请手动访问 {admin_url}）");
            }
        }

        // Ctrl+C / SIGTERM
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await?;
        }

        tracing::info!("收到退出信号，正在清理…");
        if proxy_was_set {
            let (_, msgs) = systemproxy::clear_system_proxy();
            for m in &msgs {
                tracing::info!("{m}");
            }
        }
        proxy_task.abort();
        Ok::<_, anyhow::Error>(())
    })?;

    Ok(())
}

impl Settings {
    fn admin_string(&self) -> String {
        format!("{}:{}", self.listen_host, self.admin_port)
    }
    fn proxy_string(&self) -> String {
        format!("{}:{}", self.listen_host, self.proxy_port)
    }
}
