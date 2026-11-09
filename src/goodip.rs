//! 最近可用 IP 的持久化。
//!
//! 冷启动慢的根因之一是“每次都要从零盲试”：12 个候选里当下只有 1~2 个可用，
//! 探测没跑完之前请求只能靠 DNS，DNS 给的 IP 又常是黑洞。这里把“真正拿到过
//! 应用层响应的 IP”（来源 probe=测速优选，tunnel=隧道实际回包）按域名落盘，
//! 下次启动直接把上次可用的 IP 拿来先用，同时后台再做一次轻量校验/重测，
//! 磁盘内容不可信（IP 已失效）时由连接失败快速兜底到 DNS 竞速。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// 单域名最多保留多少个 IP（按最近使用排序）
const MAX_PER_HOST: usize = 6;
/// 同一 IP 两次落盘的最小间隔：一个页面会复用同一 IP 建很多连接，
/// 没必要每次都写盘
const REWRITE_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoodIp {
    pub ip: IpAddr,
    /// Unix 秒
    pub ts: u64,
    /// `probe`（测速优选）| `tunnel`（隧道实际拿到响应）
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileData {
    version: u32,
    #[serde(default)]
    hosts: HashMap<String, Vec<GoodIp>>,
}

pub struct LastGood {
    path: PathBuf,
    hosts: RwLock<HashMap<String, Vec<GoodIp>>>,
}

impl LastGood {
    /// 从磁盘加载（文件缺失/损坏都当空处理，不阻塞启动）
    pub fn load(path: PathBuf) -> Self {
        let hosts = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<FileData>(&bytes) {
                Ok(f) => f.hosts,
                Err(e) => {
                    tracing::warn!("连通信息文件 {} 解析失败，忽略: {e}", path.display());
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        if !hosts.is_empty() {
            let flat: Vec<String> = hosts
                .iter()
                .map(|(h, v)| format!("{h}（{}）", v.len()))
                .collect();
            tracing::info!("已加载上次可用 IP：{}", flat.join("，"));
        }
        Self {
            path,
            hosts: RwLock::new(hosts),
        }
    }

    /// 该域名上次可用的 IP（最近的在前）
    pub fn ips(&self, host: &str) -> Vec<IpAddr> {
        self.hosts
            .read()
            .unwrap()
            .get(host)
            .map(|v| v.iter().map(|e| e.ip).collect())
            .unwrap_or_default()
    }

    /// 记录一个真正可用的 IP
    pub fn record(&self, host: &str, ip: IpAddr, source: &str) {
        let now = unix_now();
        let mut changed = false;
        {
            let mut hosts = self.hosts.write().unwrap();
            let list = hosts.entry(host.to_string()).or_default();
            if let Some(pos) = list.iter().position(|e| e.ip == ip) {
                let recent = pos == 0 && now.saturating_sub(list[pos].ts) < REWRITE_INTERVAL_SECS;
                if !recent {
                    let mut e = list.remove(pos);
                    e.ts = now;
                    e.source = source.to_string();
                    list.insert(0, e);
                    changed = true;
                }
            } else {
                list.insert(
                    0,
                    GoodIp {
                        ip,
                        ts: now,
                        source: source.to_string(),
                    },
                );
                list.truncate(MAX_PER_HOST);
                changed = true;
            }
        }
        if changed {
            self.save();
        }
    }

    /// 启动校验后保留仍然可用的 IP（空列表则删除该域名）
    pub fn retain(&self, host: &str, keep: &[IpAddr]) {
        let mut changed = false;
        let mut empty = false;
        {
            let mut hosts = self.hosts.write().unwrap();
            if let Some(list) = hosts.get_mut(host) {
                let before = list.len();
                list.retain(|e| keep.contains(&e.ip));
                changed = list.len() != before;
                empty = list.is_empty();
                if changed && !empty {
                    tracing::info!("上次可用 IP {host} 校验后保留 {} 个", list.len());
                }
            }
            if empty {
                hosts.remove(host);
            }
        }
        if changed {
            self.save();
        }
    }

    /// 全部域名 → 上次可用 IP 快照（启动校验用）
    pub fn snapshot(&self) -> HashMap<String, Vec<IpAddr>> {
        self.hosts
            .read()
            .unwrap()
            .iter()
            .map(|(h, v)| (h.clone(), v.iter().map(|e| e.ip).collect()))
            .collect()
    }

    /// 原子落盘（先写临时文件再 rename，避免半截文件）
    fn save(&self) {
        let data = {
            let hosts = self.hosts.read().unwrap();
            FileData {
                version: 1,
                hosts: hosts.clone(),
            }
        };
        let Ok(json) = serde_json::to_vec_pretty(&data) else {
            return;
        };
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let tmp = self.path.with_extension("json.tmp");
        if fs::write(&tmp, json).is_ok() {
            let _ = fs::rename(&tmp, &self.path);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
