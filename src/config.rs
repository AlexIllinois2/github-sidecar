use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

pub const PROXY_PORT_DEFAULT: u16 = 3128;
pub const ADMIN_PORT_DEFAULT: u16 = 10678;

static RULE_SEQ: AtomicU32 = AtomicU32::new(1);

/// 全局设置。端口等字段修改后需要重启进程生效。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// 代理监听地址（同时用于管理界面）
    pub listen_host: String,
    /// HTTP 代理端口
    pub proxy_port: u16,
    /// 管理界面端口
    pub admin_port: u16,
    /// 启动后自动用系统默认浏览器打开管理界面
    pub open_browser: bool,
    /// 启动时自动设置系统代理，退出时恢复
    pub auto_system_proxy: bool,
    /// 对所有 HTTPS 流量做 MITM（默认关闭；关闭时只对勾了 mitm 的规则解密）
    pub mitm_all: bool,
    /// 忽略上游 TLS 证书校验（仅调试用）
    pub insecure_tls: bool,
    /// 新规则默认使用的 DNS 服务器（竞速解析）
    pub default_dns_servers: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listen_host: "127.0.0.1".into(),
            proxy_port: PROXY_PORT_DEFAULT,
            admin_port: ADMIN_PORT_DEFAULT,
            open_browser: true,
            auto_system_proxy: false,
            mitm_all: false,
            insecure_tls: false,
            default_dns_servers: vec![
                "223.5.5.5".into(),
                "119.29.29.29".into(),
                "114.114.114.114".into(),
                "8.8.8.8".into(),
                "1.1.1.1".into(),
            ],
        }
    }
}

/// 一条加速/拦截规则。
///
/// 匹配语义:
/// - `hosts`: 精确匹配，`*.example.com` 为子域名匹配
/// - `path_prefixes`: 以 `/` 开头表示 `starts_with`；以 `*` 开头表示“路径包含”
/// - `ip_override`: 命中后直接连这些 IP（SNI 仍是原域名）
/// - `ip_pool`: 候选 IP 池，非空时自动对池内 IP 做 443/TCP+TLS(SNI=原域名) 建连测速，
///   优选最快的可用 IP 直连（dev-sidecar 的“IP 优选”）；全失败时落回 DNS 竞速
/// - `dns_servers`: 命中后用这些 DNS 服务器竞速解析
/// - `rewrite_to` + `path_prefixes`: 命中后 302 重定向（`full_url` 为真时拼接完整原始 URL，
///   适合 ghfast.top 这类 `镜像/https://github.com/...` 前缀代理）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub hosts: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub ip_override: Vec<String>,
    pub ip_pool: Vec<String>,
    pub dns_servers: Vec<String>,
    pub rewrite_to: String,
    pub full_url: bool,
    pub mitm: bool,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: new_rule_id(),
            name: "新规则".into(),
            enabled: true,
            hosts: vec![],
            path_prefixes: vec![],
            ip_override: vec![],
            ip_pool: vec![],
            dns_servers: vec![],
            rewrite_to: String::new(),
            full_url: false,
            mitm: false,
        }
    }
}

pub fn new_rule_id() -> String {
    let seq = RULE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("r{nanos:08x}{seq:04x}")
}

impl Rule {
    pub fn host_matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts
            .iter()
            .any(|p| host_matches_pattern(&host, p))
    }

    /// 重定向规则：填了目标地址即生效；path_prefixes 为空表示该域名下所有路径。
    pub fn is_rewrite_rule(&self) -> bool {
        !self.rewrite_to.trim().is_empty()
    }

    /// 解密 HTTPS 才能看见路径做重定向
    pub fn needs_mitm(&self) -> bool {
        self.mitm || self.is_rewrite_rule()
    }
}

pub fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host != suffix && host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Config {
    pub settings: Settings,
    pub rules: Vec<Rule>,
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Config> {
        match fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str::<Config>(&s) {
                Ok(mut c) => {
                    c.migrate_builtin_pools();
                    Ok(c)
                }
                Err(e) => {
                    eprintln!("配置文件解析失败，使用默认配置: {e}");
                    Ok(Config::default_with_rules())
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default_with_rules()),
            Err(e) => Err(e),
        }
    }

    /// 存量配置迁移：内置规则的 IP 池为空而新默认池非空时回填（用户自填的池不动），
    /// 让升级后的老 config.json 直接获得 IP 优选能力。
    fn migrate_builtin_pools(&mut self) {
        for r in &mut self.rules {
            if r.ip_pool.is_empty() {
                if let Some(d) = default_rules().into_iter().find(|d| d.id == r.id) {
                    r.ip_pool = d.ip_pool;
                }
            }
        }
    }

    pub fn default_with_rules() -> Self {
        Self {
            settings: Settings::default(),
            rules: default_rules(),
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, json)
    }
}

#[allow(clippy::too_many_arguments)]
fn rule(id: &str, name: &str, enabled: bool, hosts: &[&str], path_prefixes: &[&str],
       ip_override: &[&str], ip_pool: &[&str], dns_servers: &[&str], rewrite_to: &str, full_url: bool, mitm: bool) -> Rule {
    Rule {
        id: id.into(),
        name: name.into(),
        enabled,
        hosts: hosts.iter().map(|s| s.to_string()).collect(),
        path_prefixes: path_prefixes.iter().map(|s| s.to_string()).collect(),
        ip_override: ip_override.iter().map(|s| s.to_string()).collect(),
        ip_pool: ip_pool.iter().map(|s| s.to_string()).collect(),
        dns_servers: dns_servers.iter().map(|s| s.to_string()).collect(),
        rewrite_to: rewrite_to.into(),
        full_url,
        mitm,
    }
}

/// 内置默认规则（思路来自 dev-sidecar）。
/// GitHub 边缘 IP 会随时间漂移，池只提供“已知曾经可用”的候选，
/// 由 IP 测速优选运行时自动剔除不可达者；DNS 竞速始终兜底。
pub fn default_rules() -> Vec<Rule> {
    let dns: Vec<String> = Settings::default().default_dns_servers;
    let dns_refs: Vec<&str> = dns.iter().map(|s| s.as_str()).collect();
    const GITHUB_IP_POOL: &[&str] = &[
        "140.82.112.3", "140.82.112.4", "140.82.113.3", "140.82.113.4",
        "140.82.114.3", "140.82.116.3", "140.82.121.3",
        "20.205.243.166", "20.27.177.113", "20.200.245.247",
        "20.26.156.215", "4.208.26.197",
    ];
    vec![
        rule(
            "builtin-github",
            "GitHub 加速（IP 优选 + DNS 竞速，无需证书）",
            true,
            &["github.com", "*.github.com", "*.githubusercontent.com", "*.githubassets.com", "*.github.io"],
            &[],
            &[],
            GITHUB_IP_POOL,
            &dns_refs,
            "",
            false,
            false,
        ),
        rule(
            "builtin-github-release",
            "GitHub Release/Archive 镜像重定向（需装 CA）",
            false,
            &["github.com", "codeload.github.com"],
            &["*releases/download/", "*archive/refs/tags/", "*archive/*.zip", "*archive/*.tar.gz"],
            &[],
            &[],
            &[],
            "https://ghfast.top",
            true,
            true,
        ),
        rule(
            "builtin-npm",
            "npm registry → npmmirror（需装 CA）",
            false,
            &["registry.npmjs.org"],
            &[],
            &[],
            &[],
            &[],
            "https://registry.npmmirror.com",
            false,
            true,
        ),
        rule(
            "builtin-googleajax",
            "Google AJAX CDN → 加速镜像（需装 CA）",
            false,
            &["ajax.googleapis.com"],
            &[],
            &[],
            &[],
            &[],
            "https://ajax.loli.net",
            false,
            true,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_match() {
        assert!(host_matches_pattern("github.com", "github.com"));
        assert!(host_matches_pattern("api.github.com", "*.github.com"));
        assert!(!host_matches_pattern("github.com", "*.github.com"));
        assert!(!host_matches_pattern("evilgithub.com", "*.github.com"));
        assert!(!host_matches_pattern("api.github.com", "github.com"));
        assert!(host_matches_pattern("raw.github.COM.", "raw.github.com"));
    }

    #[test]
    fn test_rule_matching() {
        let r = rule("t", "t", true, &["github.com"], &[], &[], &[], &[], "", false, false);
        assert!(r.host_matches("github.com"));
        assert!(!r.host_matches("example.com"));
        let rw = rule("t2", "t2", true, &["github.com"], &["*releases/"], &[], &[], &[], "https://x", true, false);
        assert!(rw.is_rewrite_rule() && rw.needs_mitm());
    }

    #[test]
    fn test_ip_pool_serde() {
        let r = rule("t", "t", true, &["github.com"], &[], &[], &["140.82.112.3"], &[], "", false, false);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"ipPool\":[\"140.82.112.3\"]"));
        // 旧配置没有 ipPool 字段时默认为空
        let old: Rule = serde_json::from_str(r#"{"id":"x","name":"x","enabled":true,"hosts":["github.com"]}"#).unwrap();
        assert!(old.ip_pool.is_empty());
    }

    #[test]
    fn test_migrate_builtin_pools() {
        // 旧配置：builtin-github 池为空 → 回填默认池；用户自填池不动；非内置规则不动
        let old = r#"{
            "settings": {},
            "rules": [
                {"id":"builtin-github","name":"旧名","enabled":true,"hosts":["github.com"],"ipOverride":[],"dnsServers":["223.5.5.5"]},
                {"id":"builtin-github","name":"自填","enabled":true,"hosts":["github.com"],"ipPool":["192.0.2.1"]},
                {"id":"custom","name":"自定义","enabled":true,"hosts":["a.com"]}
            ]
        }"#;
        let mut c: Config = serde_json::from_str(old).unwrap();
        c.migrate_builtin_pools();
        let gh: Vec<&Rule> = c.rules.iter().filter(|r| r.id == "builtin-github").collect();
        assert!(!gh[0].ip_pool.is_empty(), "空池内置规则应回填默认池");
        assert_eq!(gh[1].ip_pool, vec!["192.0.2.1"], "用户自填池不应被覆盖");
        assert!(c.rules.iter().find(|r| r.id == "custom").unwrap().ip_pool.is_empty());
    }
}
