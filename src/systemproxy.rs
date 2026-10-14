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

#[cfg(target_os = "linux")]
pub fn set_system_proxy(host: &str, port: u16) -> (bool, Vec<String>) {
    let mut messages = Vec::new();
    let gsettings = |args: &[&str]| run(Command::new("gsettings").args(args));

    let mut ok = true;
    let steps: Vec<Vec<String>> = vec![
        vec!["set".into(), "org.gnome.system.proxy".into(), "mode".into(), "'manual'".into()],
        vec!["set".into(), "org.gnome.system.proxy.http".into(), "host".into(), format!("'{host}'")],
        vec!["set".into(), "org.gnome.system.proxy.http".into(), "port".into(), port.to_string()],
        vec!["set".into(), "org.gnome.system.proxy.https".into(), "host".into(), format!("'{host}'")],
        vec!["set".into(), "org.gnome.system.proxy.https".into(), "port".into(), port.to_string()],
    ];
    for step in steps {
        let refs: Vec<&str> = step.iter().map(|s| s.as_str()).collect();
        if let Some(err) = gsettings(&refs) {
            ok = false;
            messages.push(format!("gsettings 失败: {err}"));
            break;
        }
    }
    if ok {
        messages.push("已设置 GNOME 系统代理（gsettings）。KDE/其他桌面请手动设置。".into());
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
pub fn set_system_proxy(host: &str, port: u16) -> (bool, Vec<String>) {
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
    (ok, messages)
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
pub fn set_system_proxy(host: &str, port: u16) -> (bool, Vec<String>) {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey_with_flags(INET_SETTINGS, KEY_SET_VALUE) {
        Ok(key) => {
            let server = format!("{host}:{port}");
            let r = key.set_value("ProxyServer", &server)
                .and_then(|_| key.set_value("ProxyEnable", &1u32));
            match r {
                Ok(()) => (true, vec![format!("已设置 Windows 系统代理为 {server}")]),
                Err(e) => (false, vec![format!("写注册表失败: {e}")]),
            }
        }
        Err(e) => (false, vec![format!("打开注册表失败: {e}")]),
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
