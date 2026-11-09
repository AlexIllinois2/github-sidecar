//! 系统代理设置（尽力而为）：GNOME 用 gsettings，macOS 用 networksetup，Windows 用注册表。
//! 失败时返回提示信息，不影响代理本身运行。

#[cfg(not(windows))]
use std::process::Command;

#[cfg(not(windows))]
fn run(cmd: &mut Command) -> Option<String> {
    match cmd.output() {
        Ok(out) if out.status.success() => None,
        Ok(out) => Some(String::from_utf8_lossy(&out.stderr).trim().to_string()),
        Err(e) => Some(e.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn args_str(args: &[&str]) -> String {
    args.join(" ")
}

/// 设置系统代理前的快照，用于退出或关闭开关时恢复用户原有设置。
/// 字段保存 gsettings 原始输出（字符串值本身带引号），空表示该平台没有快照。
#[derive(Debug, Clone, Default)]
pub struct ProxyBackup {
    pub mode: String,
    pub autoconfig_url: String,
    pub http_host: String,
    pub http_port: String,
    pub https_host: String,
    pub https_port: String,
}

#[cfg(target_os = "linux")]
fn gsettings_get(key: &[&str]) -> Option<String> {
    let out = Command::new("gsettings").args(key).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn snapshot() -> Option<ProxyBackup> {
    Some(ProxyBackup {
        mode: gsettings_get(&["get", "org.gnome.system.proxy", "mode"])?,
        autoconfig_url: gsettings_get(&["get", "org.gnome.system.proxy", "autoconfig-url"])?,
        http_host: gsettings_get(&["get", "org.gnome.system.proxy.http", "host"])?,
        http_port: gsettings_get(&["get", "org.gnome.system.proxy.http", "port"])?,
        https_host: gsettings_get(&["get", "org.gnome.system.proxy.https", "host"])?,
        https_port: gsettings_get(&["get", "org.gnome.system.proxy.https", "port"])?,
    })
}

#[cfg(target_os = "linux")]
fn manual_steps(host: &str, port: u16) -> Vec<Vec<String>> {
    vec![
        vec!["set".into(), "org.gnome.system.proxy".into(), "mode".into(), "'manual'".into()],
        vec!["set".into(), "org.gnome.system.proxy.http".into(), "host".into(), format!("'{host}'")],
        vec!["set".into(), "org.gnome.system.proxy.http".into(), "port".into(), port.to_string()],
        vec!["set".into(), "org.gnome.system.proxy.https".into(), "host".into(), format!("'{host}'")],
        vec!["set".into(), "org.gnome.system.proxy.https".into(), "port".into(), port.to_string()],
    ]
}

#[cfg(target_os = "linux")]
pub fn set_system_proxy(
    host: &str,
    port: u16,
    pac_url: &str,
) -> (bool, Vec<String>, Option<ProxyBackup>) {
    let mut messages = Vec::new();
    let gsettings = |args: &[&str]| run(Command::new("gsettings").args(args));

    // 先快照用户原有设置，退出时才能原样恢复（含原有的 manual/auto/none 模式）
    let backup = snapshot();

    // 优先用 PAC 自动代理：只有规则命中的域名走侧车，其余流量直连。
    // 否则系统里所有流量（Chrome 的 googleapis 等后台请求）都会灌进侧车，
    // 而这些域名既没有规则、又常常连不通，会把浏览器的连接池拖死。
    let auto_steps: Vec<Vec<String>> = vec![
        vec!["set".into(), "org.gnome.system.proxy".into(), "mode".into(), "'auto'".into()],
        vec![
            "set".into(),
            "org.gnome.system.proxy".into(),
            "autoconfig-url".into(),
            format!("'{pac_url}'"),
        ],
    ];
    let mut ok = run_steps(&gsettings, &auto_steps, &mut messages);
    let pac_ok = ok;
    if !ok {
        // PAC 不可用（老版本 GNOME 或 schema 缺键）→ 回退为手动代理
        messages.push("PAC 模式不可用，回退为手动系统代理（全部流量经侧车）".into());
        ok = run_steps(&gsettings, &manual_steps(host, port), &mut messages);
    }
    if ok {
        messages.push(if pac_ok {
            format!("已设置 GNOME 自动代理（PAC: {pac_url}）：仅规则命中的域名走侧车，其余直连。")
        } else {
            "已设置 GNOME 手动系统代理（gsettings）。KDE/其他桌面请手动设置。".into()
        });
        match &backup {
            Some(b) => messages.push(format!(
                "已记录退出前的系统代理设置（mode={}），退出时自动恢复。",
                b.mode.trim_matches('\'')
            )),
            None => messages.push(
                "未能读取原有系统代理设置，退出时将回退为关闭代理（mode=none）。".into(),
            ),
        }
    }
    (ok, messages, backup)
}

#[cfg(target_os = "linux")]
fn run_steps(
    gsettings: &impl Fn(&[&str]) -> Option<String>,
    steps: &[Vec<String>],
    messages: &mut Vec<String>,
) -> bool {
    for step in steps {
        let refs: Vec<&str> = step.iter().map(|s| s.as_str()).collect();
        if let Some(err) = gsettings(&refs) {
            messages.push(format!("gsettings 失败: {err}"));
            return false;
        }
    }
    true
}

/// 恢复退出前的系统代理。若原设置本身就指向本程序（manual 指向本端口，或 auto
/// 指向本程序的 PAC），恢复成它没有意义——退出后只会指向一个已关闭的服务，
/// 因此这种情况下置为 none；其他情况原样恢复。
#[cfg(target_os = "linux")]
pub fn restore_system_proxy(
    backup: &ProxyBackup,
    host: &str,
    port: u16,
    pac_url: &str,
) -> (bool, Vec<String>) {
    if backup.mode.trim().is_empty() {
        return clear_system_proxy();
    }
    let prior_mode = backup.mode.trim_matches('\'');
    let same_as_ours = match prior_mode {
        "manual" => {
            backup.http_host.trim_matches('\'').eq(host)
                && backup.http_port.trim() == port.to_string()
        }
        "auto" => backup.autoconfig_url.trim_matches('\'').eq(pac_url),
        _ => false,
    };

    let mut messages = Vec::new();
    let gsettings = |args: &[&str]| run(Command::new("gsettings").args(args));
    let steps: Vec<Vec<String>> = if same_as_ours {
        vec![vec!["set".into(), "org.gnome.system.proxy".into(), "mode".into(), "'none'".into()]]
    } else {
        vec![
            vec!["set".into(), "org.gnome.system.proxy".into(), "mode".into(), backup.mode.clone()],
            vec!["set".into(), "org.gnome.system.proxy".into(), "autoconfig-url".into(), backup.autoconfig_url.clone()],
            vec!["set".into(), "org.gnome.system.proxy.http".into(), "host".into(), backup.http_host.clone()],
            vec!["set".into(), "org.gnome.system.proxy.http".into(), "port".into(), backup.http_port.clone()],
            vec!["set".into(), "org.gnome.system.proxy.https".into(), "host".into(), backup.https_host.clone()],
            vec!["set".into(), "org.gnome.system.proxy.https".into(), "port".into(), backup.https_port.clone()],
        ]
    };
    let ok = run_steps(&gsettings, &steps, &mut messages);
    if ok {
        messages.push(if same_as_ours {
            "原系统代理指向本程序，已置为 none（避免退出后指向已关闭的端口）。".into()
        } else {
            format!("已恢复退出前的 GNOME 系统代理设置（mode={prior_mode}）。")
        });
    }
    (ok, messages)
}

#[cfg(target_os = "linux")]
pub fn clear_system_proxy() -> (bool, Vec<String>) {
    let mut messages = Vec::new();
    match run(Command::new("gsettings").args(["set", "org.gnome.system.proxy", "mode", "'none'"])) {
        None => messages.push("已恢复 GNOME 系统代理设置".into()),
        Some(err) => messages.push(format!("gsettings 失败: {err}")),
    }
    (true, messages)
}

#[cfg(not(target_os = "linux"))]
pub fn restore_system_proxy(
    _backup: &ProxyBackup,
    _host: &str,
    _port: u16,
    _pac_url: &str,
) -> (bool, Vec<String>) {
    clear_system_proxy()
}

#[cfg(target_os = "macos")]
fn network_services() -> Vec<String> {
    match Command::new("networksetup").args(["-listallnetworkservices"]).output() {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .skip(1) // 第一行是标题
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('*'))
                .collect()
        }
        _ => vec!["Wi-Fi".into()],
    }
}

#[cfg(target_os = "macos")]
pub fn set_system_proxy(host: &str, port: u16, _pac_url: &str) -> (bool, Vec<String>, Option<ProxyBackup>) {
    let mut messages = Vec::new();
    let mut ok = true;
    for svc in network_services() {
        for args in [
            vec!["-setwebproxy", &svc, host, &port.to_string()],
            vec!["-setsecurewebproxy", &svc, host, &port.to_string()],
        ] {
            if let Some(err) = run(Command::new("networksetup").args(&args)) {
                ok = false;
                messages.push(format!("networksetup {args_str(&args)} 失败: {err}"));
            }
        }
        messages.push(format!("已为网络服务「{svc}」设置系统代理"));
    }
    // macOS 侧暂不提供快照：退出时仍按旧逻辑关闭代理
    (ok, messages, None)
}

#[cfg(target_os = "macos")]
pub fn clear_system_proxy() -> (bool, Vec<String>) {
    let mut messages = Vec::new();
    for svc in network_services() {
        for args in [
            vec!["-setwebproxystate", &svc, "off"],
            vec!["-setsecurewebproxystate", &svc, "off"],
        ] {
            if let Some(err) = run(Command::new("networksetup").args(&args)) {
                messages.push(format!("networksetup {args_str(&args)} 失败: {err}"));
            }
        }
    }
    messages.push("已恢复 macOS 系统代理设置".into());
    (true, messages)
}

#[cfg(windows)]
const INET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(windows)]
pub fn set_system_proxy(host: &str, port: u16, _pac_url: &str) -> (bool, Vec<String>, Option<ProxyBackup>) {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey_with_flags(INET_SETTINGS, KEY_SET_VALUE) {
        Ok(key) => {
            let server = format!("{host}:{port}");
            let r = key.set_value("ProxyServer", &server)
                .and_then(|_| key.set_value("ProxyEnable", &1u32));
            match r {
                Ok(()) => (true, vec![format!("已设置 Windows 系统代理为 {server}")], None),
                Err(e) => (false, vec![format!("写注册表失败: {e}")], None),
            }
        }
        Err(e) => (false, vec![format!("打开注册表失败: {e}")], None),
    }
}

#[cfg(windows)]
pub fn clear_system_proxy() -> (bool, Vec<String>) {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey_with_flags(INET_SETTINGS, KEY_SET_VALUE) {
        Ok(key) => match key.set_value("ProxyEnable", &0u32) {
            Ok(()) => (true, vec!["已恢复 Windows 系统代理设置".into()]),
            Err(e) => (false, vec![format!("写注册表失败: {e}")]),
        },
        Err(e) => (false, vec![format!("打开注册表失败: {e}")]),
    }
}
