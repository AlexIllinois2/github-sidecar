//! actix-web 管理后台：静态页面 + REST API。
//! 跑在独立线程的 actix System 里（与主 tokio runtime 互不干扰），通过 Arc<Core> 共享状态。

use crate::config::{Rule, Settings};
use crate::logs::LogEntry;
use crate::state::Core;
use actix_web::{get, post, put, web, HttpResponse, Responder};
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("assets/index.html");
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn spawn_admin(core: Arc<Core>) -> anyhow::Result<()> {
    let settings = core.settings();
    let host = settings.listen_host.clone();
    let port = settings.admin_port;
    let admin_core = core.clone();

    std::thread::Builder::new()
        .name("admin-http".into())
        .spawn(move || {
            let host_err = host.clone();
            let sys = actix_web::rt::System::new();
            let result = sys.block_on(async move {
                let addr = (host.as_str(), port);
                match actix_web::HttpServer::new(move || {
                    actix_web::App::new()
                        .app_data(web::Data::new(admin_core.clone()))
                        .service(index)
                        .service(web::scope("/api")
                            .service(status)
                            .service(get_settings)
                            .service(put_settings)
                            .service(get_rules)
                            .service(put_rules)
                            .service(get_ip_pool)
                            .service(logs)
                            .service(system_proxy))
                        .service(download_ca)
                })
                .workers(2)
                .bind(addr)
                {
                    Ok(server) => server.run().await,
                    Err(e) => Err(e),
                }
            });
            if let Err(e) = result {
                eprintln!("管理界面启动失败（{host_err}:{port}）: {e}");
                std::process::exit(1);
            }
        })?;
    Ok(())
}

fn admin_core(data: &web::Data<Arc<Core>>) -> Arc<Core> {
    Arc::clone(data.get_ref())
}

// ---------- 页面 ----------

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(INDEX_HTML)
}

// ---------- API ----------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResp {
    version: &'static str,
    proxy_addr: String,
    admin_addr: String,
    uptime_sec: u64,
    data_dir: String,
    ca_ready: bool,
    ca_sha256: String,
    counters: CountersDto,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CountersDto {
    total: u64,
    tunnel: u64,
    mitm: u64,
    rewrite: u64,
    errors: u64,
}

#[get("/status")]
async fn status(core: web::Data<Arc<Core>>) -> impl Responder {
    let core = admin_core(&core);
    let settings = core.settings();
    let counters = CountersDto {
        total: crate::state::Counters::get(&core.counters.total),
        tunnel: crate::state::Counters::get(&core.counters.tunnel),
        mitm: crate::state::Counters::get(&core.counters.mitm),
        rewrite: crate::state::Counters::get(&core.counters.rewrite),
        errors: crate::state::Counters::get(&core.counters.errors),
    };
    let resp = StatusResp {
        version: VERSION,
        proxy_addr: format!("{}:{}", settings.listen_host, settings.proxy_port),
        admin_addr: format!("{}:{}", settings.listen_host, settings.admin_port),
        uptime_sec: core.started.elapsed().as_secs(),
        data_dir: core.ca.ca_file().parent().map(|p| p.display().to_string()).unwrap_or_default(),
        ca_ready: true,
        ca_sha256: core.ca.fingerprint(),
        counters,
    };
    web::Json(resp)
}

#[get("/settings")]
async fn get_settings(core: web::Data<Arc<Core>>) -> impl Responder {
    web::Json(admin_core(&core).settings())
}

#[put("/settings")]
async fn put_settings(core: web::Data<Arc<Core>>, body: web::Json<Settings>) -> impl Responder {
    let core = admin_core(&core);
    let old = core.settings();
    let new = body.into_inner();
    let restart_required = new.proxy_port != old.proxy_port
        || new.admin_port != old.admin_port
        || new.listen_host != old.listen_host
        // 上游 TLS 配置在启动时构建一次，之后不再读取
        || new.insecure_tls != old.insecure_tls;
    {
        let mut cfg = core.cfg.write().unwrap();
        cfg.settings = new;
    }
    match core.save_config() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "restartRequired": restart_required })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "ok": false, "error": e.to_string() })),
    }
}

#[get("/rules")]
async fn get_rules(core: web::Data<Arc<Core>>) -> impl Responder {
    web::Json(admin_core(&core).rules())
}

#[put("/rules")]
async fn put_rules(core: web::Data<Arc<Core>>, body: web::Json<Vec<Rule>>) -> impl Responder {
    let core = admin_core(&core);
    let rules = body.into_inner();
    for r in &rules {
        if r.enabled && r.hosts.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "error": format!("规则「{}」没有配置任何域名", r.name),
            }));
        }
        if r.is_rewrite_rule() && !r.rewrite_to.starts_with("http://") && !r.rewrite_to.starts_with("https://") {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "error": format!("规则「{}」的重定向地址必须以 http(s):// 开头", r.name),
            }));
        }
    }
    {
        let mut cfg = core.cfg.write().unwrap();
        cfg.rules = rules;
    }
    match core.save_config() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "ok": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "ok": false, "error": e.to_string() })),
    }
}

#[get("/ip-pool")]
async fn get_ip_pool(core: web::Data<Arc<Core>>) -> impl Responder {
    web::Json(admin_core(&core).speed.snapshot().await)
}

#[get("/logs")]
async fn logs(core: web::Data<Arc<Core>>, query: web::Query<LogsQuery>) -> impl Responder {
    let core = admin_core(&core);
    let entries: Vec<LogEntry> = core.logs.after(query.after.unwrap_or(0), 500);
    let next_seq = entries.last().map(|e| e.seq).unwrap_or(query.after.unwrap_or(0));
    web::Json(serde_json::json!({ "entries": entries, "nextSeq": next_seq }))
}

#[derive(serde::Deserialize)]
struct LogsQuery {
    after: Option<u64>,
}

#[derive(serde::Deserialize)]
struct SystemProxyReq {
    enable: bool,
}

#[post("/system-proxy")]
async fn system_proxy(core: web::Data<Arc<Core>>, body: web::Json<SystemProxyReq>) -> impl Responder {
    let core = admin_core(&core);
    let settings = core.settings();
    let (ok, messages) = if body.enable {
        crate::systemproxy::set_system_proxy(&settings.listen_host, settings.proxy_port)
    } else {
        crate::systemproxy::clear_system_proxy()
    };
    HttpResponse::Ok().json(serde_json::json!({ "ok": ok, "messages": messages }))
}

#[get("/ca.crt")]
async fn download_ca(core: web::Data<Arc<Core>>) -> impl Responder {
    let core = admin_core(&core);
    HttpResponse::Ok()
        .content_type("application/x-pem-file")
        .insert_header(("content-disposition", "attachment; filename=\"dev-sidecar-rs-ca.crt\""))
        .body(core.ca.ca_pem().to_string())
}
