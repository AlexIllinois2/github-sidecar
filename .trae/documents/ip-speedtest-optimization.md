# IP 自动测速优选（对齐原版 dev-sidecar 的 IP 优选逻辑）

## Context

复刻版把原版 dev-sidecar 的"内置 IP 池 + 自动测速优选"简化成了纯 DNS 竞速，导致 DNS 拿到的 IP 被墙时（如 github.com → 20.205.243.166 超时）整个加速失效，还要用户手动测 IP 手填 `ipOverride`。本次补回原版核心逻辑：**规则可配置候选 IP 池（ipPool），自动对池内 IP 做 TCP+TLS 建连测速，选最快可达的 IP 直连（SNI 仍是原域名，证书校验正常）**，用户零配置开箱即用。

优先级链：`ip_override`（手填，最高）→ **`ipPool` 测速优选（新增）** → `dns_servers` 竞速 → 系统解析。测速全失败时自动落到 DNS 竞速兜底。

测速方式选择 TCP+TLS 握手（SNI=目标域名、走 rustls 正常证书校验）而非纯 TCP：可避免"IP 可达但不服务该域名"的误选（如 github.com 边缘 IP 与 raw.githubusercontent.com 的 Fastly IP 不同），一次探测同时验证可达性与正确性。

## 改动文件

### 1. 新增 `src/speedtest.rs`（核心模块）

```rust
pub struct IpSpeedTester {
    cache: tokio::sync::RwLock<HashMap<String, CacheEntry>>, // host -> 条目
}
struct CacheEntry {
    ips: Vec<IpAddr>,      // 测速成功的 IP，按 RTT 升序
    pool: Vec<IpAddr>,     // 本次测速用的池（背景刷新时对照是否需要重测）
    tested_at: Instant,
}
```

- `const PROBE_TIMEOUT: Duration = 3s; const CACHE_TTL: Duration = 300s;`
- `new(tls: TlsConnector)`：构造时注入复用的 TLS 连接器（见第 2 点）
- `async fn best_ips(&self, host: &str, pool: &[String]) -> io::Result<Vec<IpAddr>>`：
  - 缓存未过期 → 直接返回
  - 否则并发探测：对池内每个可解析的 IP（去重）`timeout(3s, TcpStream::connect(ip:443))`，连上后再 `TlsConnector.connect(ServerName::tryFrom(host), tcp)` 完成 TLS 握手，计时取 RTT
  - 成功者按 RTT 排序缓存并返回；全部失败返回空（调用方走 DNS 兜底）
  - 新测速完成时 `tracing::info!("IP 优选 {host} → {最快IP}（{成功数}/{总数} 候选可用，{最快RTT}ms）")`
- `async fn retest_stale(&self, reprobe: impl Fn(&str) -> Option<Vec<String>>)`：对缓存里已过 TTL 的条目重测（背景任务用）
- `fn snapshot(&self) -> Vec<PoolStatus>`：供管理 API 展示（host、当前最优 IP 列表、age 秒）
- 纯逻辑辅助函数 `fn rank(results: Vec<(IpAddr, Duration)>) -> Vec<IpAddr>` 单独抽出便于单测
- 并发重复测速不去重（突发请求最多重复探测池大小数量的连接，成本可控，保持简单）

### 2. `src/state.rs`

- 把 `build_upstream_client` 里构建 rustls `ClientConfig` 的逻辑抽成 `pub(crate) fn upstream_tls_config(settings: &Settings) -> ClientConfig`（原逻辑不动：insecure_tls 时用 `NoVerify`，否则 native roots），`build_upstream_client` 与 `Core::new` 共用
- `Core` 增加 `pub speed: IpSpeedTester`；`Core::new` 里 `IpSpeedTester::new(TlsConnector::from(Arc::new(upstream_tls_config(&cfg.settings))))`
- `resolve_host`（L119-137）在 `ip_override` 分支后插入：

```rust
if !rule.ip_pool.is_empty() {
    if let Ok(ips) = self.speed.best_ips(host, &rule.ip_pool).await {
        if !ips.is_empty() {
            return Ok(ips);
        }
    }
    // 测速全失败 → 继续走 dns_servers 竞速兜底
}
```

- 三个调用方（`ProxyResolver::call`、`serve_tunnel`）无需改动：resolve 返回的有序 IP 列表已按"最快优先"排列，hyper 连接器与盲隧道都会逐个尝试

### 3. `src/config.rs`

- `Rule` 增加 `pub ip_pool: Vec<String>`（serde camelCase → `ipPool`，`#[serde(default)]` 由结构体级 `default` 覆盖）；注释说明"候选 IP 池，非空时自动测速优选，443/TLS 探测"
- `default_rules()`：`builtin-github` 规则填入候选池（GitHub 已知边缘 IP，本机已实测其中 140.82.112.3 / 20.27.177.113 可用）：
  `140.82.112.3, 140.82.112.4, 140.82.113.3, 140.82.114.3, 140.82.116.3, 140.82.121.3, 20.205.243.166, 20.27.177.113, 20.200.245.247, 20.26.156.215, 4.208.26.197`；规则名改为"GitHub 加速（IP 优选 + DNS 竞速，无需证书）"
- **存量配置迁移**：`Config::load` 解析成功后调用 `fn migrate_builtin_pools(&mut self)` —— 遍历规则，对 id 命中 `default_rules()` 同 id 且存量 `ip_pool` 为空、默认池非空的规则，回填默认池（用户改过的非空池不动）。这样新逻辑对已有 config.json 立即生效
- 测试：serde 往返 `ipPool` 字段；迁移函数对"旧配置回填 / 用户自定义不覆盖"的断言

### 4. `src/main.rs`

- `rt.block_on` 内、`ctrl_c` 等待前追加：
  - **启动预热**：`tokio::spawn` 遍历启用且 `ip_pool` 非空的规则的**字面量 host**（不含 `*`，如 github.com、codeload.github.com），调 `best_ips` 预热缓存，首个浏览器请求即命中缓存
  - **背景刷新**：`tokio::spawn` + `tokio::time::interval(300s)`，每轮对 `speed.snapshot()` 里的过期 host 用 `core.match_rule(host)` 取当前池重测（池已删空的条目直接移除）

### 5. `src/admin.rs`

- `/api` scope 增加 `get_ip_pool`：`GET /api/ip-pool` → `web::Json(core.speed.snapshot())`（host → 最优 IP、age、池大小），用于 UI 展示优选结果

### 6. `src/assets/index.html`

- 规则编辑器仿照 `#fDns`（dnsServers）增加"候选 IP 池（自动测速优选，每行一个 IP）"textarea（`#fPool`）；`openRuleEditor` / `applyRuleEdit` / `addRule` 同步读写 `r.ipPool`
- 规则卡片摘要 chips 增加 `IP优选×N`（仿 L331-332 的 ipOverride/dnsServers 写法）
- 增加一个只读小面板（规则区下方）轮询 `/api/ip-pool` 展示各 host 当前选中的 IP 与测速时间，让"选了哪个 IP"可见

### 7. `README.md`

- 功能表、规则说明补 `ipPool`（IP 优选）描述；修正"与原版的差异"里"IP 与镜像站留给用户填"的表述（IP 部分已恢复自动优选，镜像仍留给用户）

## 不做的事

- 不加 JS 脚本拦截、远程配置源（用户本次只选了 IP 优选）
- 不去重并发测速、不做多轮取均值测速（保持精简）
- 明文 HTTP（80 端口）不走 TLS 探测，池对纯 HTTP 域名不生效（自然落回 DNS/系统解析），代码注释说明

## 验证

1. `cargo +stable-x86_64-pc-windows-msvc clippy -- -D warnings && cargo +stable-x86_64-pc-windows-msvc test`
2. 重启运行中的实例（先停旧进程），观察启动日志出现预热测速结果（github.com → 某可用 IP）
3. 清掉此前手动加的 `ipOverride`（PUT /api/rules），`curl --ssl-no-revoke -x http://127.0.0.1:3128 https://github.com` → 200，日志出现"IP 优选 github.com → …"
4. `curl -x proxy https://raw.githubusercontent.com/github/gitignore/main/README.md` → 200（github.com 池对其 SNI 探测失败，应自动落回 DNS 竞速，验证兜底正确）
5. `GET /api/ip-pool` 返回测速快照；打开管理界面确认规则编辑器有 IP 池字段、结果面板正常显示
6. 手动把池里塞一个假 IP（如 192.0.2.1），确认混合池下仍选出可用 IP；全坏池时请求经 DNS 兜底仍成功
