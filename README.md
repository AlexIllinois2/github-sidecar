# github-sidecar

[docmirror/dev-sidecar](https://github.com/docmirror/dev-sidecar)（开发者边车）核心功能的 Rust 重写版。
**单二进制**，无常驻 Electron，适合日常后台挂着跑：启动即监听 HTTP 代理端口，并自动用系统默认浏览器打开内置 Web 管理界面。

## 功能

| 功能 | 说明 |
| --- | --- |
| HTTP/HTTPS 代理 | 基于 hyper + rustls，带上游连接池 |
| DNS 竞速（优选） | 命中规则的域名同时向多个公共 DNS 发查询，取最快的有效结果，绕开污染/超时 |
| IP 测速优选 | 规则可配候选 IP 池，自动对池内 IP 做 TCP+TLS 握手 + `GET /robots.txt` 存活校验，按完整请求耗时选最快的可用 IP 直连（原版 dev-sidecar 的 IP 优选）；探测不阻塞首个请求，整批全挂会立即补测一轮；连接路径对前 8 个候选并行竞速（happy eyeballs）；最近可用的 IP 按域名落盘，下次启动直接复用并后台重测 |
| IP 直连 | 规则可指定目标 IP 列表，直连但保留原 SNI/主机名（dev-sidecar 的 github 加速思路） |
| 镜像重定向 | 命中域名+路径的 GET/HEAD 请求 302 到镜像站（ghproxy.net、npmmirror 等），需 MITM |
| MITM 解密 | 按规则解密 HTTPS（首用自动生成根 CA，按域名即时签发叶证书），`mitmAll` 默认**关闭**；内置的 GitHub Release 与 raw 图片镜像规则均默认**关闭**，因此默认没有任何 MITM 流量，CA 不参与链路；开启后需先装 CA |
| Web 管理界面 | actix-web 内置，热更新规则/设置，实时日志，CA 下载，IP 优选结果展示 |
| 系统代理 | 一键设置/恢复（GNOME gsettings / macOS networksetup / Windows 注册表）；`autoSystemProxy` 默认开启，退出时恢复为设置前的状态（若原设置就指向本程序则置为 none）。Linux 默认走 **PAC 自动代理**（本机 HTTP 提供 `proxy.pac`）：只有加速规则命中的域名走侧车，其余直连；代理不可达时回退 DIRECT |
| 自动打开浏览器 | 可关（`--no-open` 或设置里关闭） |

## 快速开始

```bash
cargo build --release
./target/release/github-sidecar            # 启动并自动打开 http://127.0.0.1:10678
```

- 代理地址：`http://127.0.0.1:3128`
- 管理界面：`http://127.0.0.1:10678`
- 数据目录：`~/.config/github-sidecar/`（`ca.crt`、`ca.key.pem`、`config.json`）

终端使用：

```bash
export https_proxy=http://127.0.0.1:3128 http_proxy=http://127.0.0.1:3128
# 只想让 git 走代理：
git config --global http.https://github.com.proxy http://127.0.0.1:3128
```

命令行参数：`--proxy-port`、`--admin-port`、`--data-dir`、`--config`、`--no-open`、`--no-system-proxy`。

## 规则说明

规则按顺序匹配，第一条命中的生效。每条规则可以组合：

- **hosts**：`github.com` 精确匹配、`*.github.com` 子域匹配
- **ip_override**：直连这些 IP（TLS 的 SNI 仍是原域名，证书校验正常通过），优先级最高
- **ip_pool**：候选 IP 池，自动对池内 IP 做 443/TCP+TLS（SNI=原域名）建连测速，选最快的可用 IP 直连；
  全部失败自动落回 DNS 竞速兜底。结果缓存 5 分钟并后台重测；全部候选失败的负缓存只有 30 秒，
  避免一次瞬时全挂被当成 5 分钟有效结果。真正可用过的 IP 会写入
  `~/.config/github-sidecar/last-good.json`（域名 → IP、时间戳、来源），下次启动先复用再后台校验。
  管理界面「IP 优选结果」面板可见当前选择
- **dns_servers**：对这些 DNS 服务器竞速解析
- **path_prefixes + rewrite_to**：路径命中后 302 重定向。留空表示该域名下的全部路径；
  前缀以 `/` 开头是 starts_with，以 `*` 开头是 contains；
  `fullUrl` 开启时把完整原始 URL 拼到镜像地址后面（如 `https://ghproxy.net/https://github.com/...`）
- **mitm**：解密该域名的 HTTPS 才能看见并改写路径（需要安装 CA；仅 DNS/IP 加速不需要）

解析优先级：`ip_override`（手填）→ `ip_pool`（测速优选）→ `dns_servers`（竞速）→ 系统解析。

只要规则填了 `rewrite_to`，该域名的 HTTPS 就会被解密（不看路径无法改写），并且解密判定取
**所有命中规则的并集**：把纯 DNS/IP 加速规则排在前面，不会屏蔽掉后面那条需要 MITM 的重定向规则。

内置默认规则：GitHub 主域（`github.com`）IP 优选 + DNS 竞速；子域（`*.github.com`，含 api/gist/codeload）
的可用 IP 与主站不是同一套，只用 DNS 竞速；`*.githubusercontent.com`、`*.githubassets.com`、`*.github.io`
由 Fastly 承载，实测直连与经侧车耗时相当甚至更好，因此默认**不走侧车**（规则保留、`enabled=false`，
需要时可在管理页开启做 DNS 竞速）。
GitHub Release/Archive 镜像 → `ghproxy.net`（默认**关闭**，需装 CA；开启后仅下载路径重写，
但 github.com 会因此被全域名 MITM 解密，网页/API 的 HTTP/2 也会降级为 HTTP/1.1，所以按需开启）。
GitHub raw 图片 → `ghproxy.net`（默认**关闭**，需装 CA；只重写图片扩展名。该域名在国内常被 SNI
级阻断，页面里的 README 图片会因此裂图；开启后能显示图片，但会解密该域名的所有 HTTPS 请求，
对不信任本 CA 的程序有影响，所以默认不启用，需要时手动开。带 token 的私有 raw 链接不要依赖此规则）。
默认关闭状态下没有任何启用的 MITM/重定向规则，`mitmAll` 也为 `false`，CA 不参与链路。

## 与原版 (Electron) 的差异

- 原版的 **JS 拦截脚本** 改为数据驱动的重定向规则（覆盖 release/npm/ajax 等常见场景，但不支持任意自定义 JS）
- 原 IP/镜像列表随时间失效：本版以内置候选池 + 自动测速优选保持 IP 可用（镜像站仍留给用户在界面里填）
- 无托盘图标（本来就是后台进程 + 网页管理）；无油猴脚本包
- Linux 下系统代理走 gsettings（GNOME），KDE 等其它桌面请手动配

## 架构

```
src/
├── main.rs          启动编排（配置 → CA → 代理 → 管理线程 → 开浏览器 → Ctrl+C 清理）
├── config.rs        Settings/Rule 模型、默认规则、持久化
├── state.rs         共享状态、规则匹配、上游客户端（连接池 + 自定义解析器 + TLS）
├── dns.rs           手写精简 UDP DNS 客户端（A/AAAA 并发、多服务器竞速、缓存）
├── speedtest.rs     IP 测速优选（候选池 TCP+TLS+GET 并发探测、按完整耗时排序、缓存/后台重测、数据面卡死剔除）
├── goodip.rs       最近可用 IP 的落盘与冷启动复用（域名 → IP/时间戳/来源）
├── ca.rs            根 CA 生成/加载、按域名即时签发叶证书（rcgen + rustls）
├── proxy.rs         代理引擎：明文转发 / CONNECT 盲隧道（前 8 候选并行竞速 + TLS app-data 看门狗）/ MITM 解密转发
├── admin.rs         actix-web 管理后台（REST API + 内嵌单页 UI）
├── logs.rs          tracing 双写（stderr + 环形缓冲供 UI 轮询）
├── systemproxy.rs   三平台系统代理设置
└── assets/index.html  Web UI（原生 JS 单文件，编译期嵌入）
```

代理跑在主 tokio runtime；actix-web 管理后台在独立线程自己的 actix System 里，通过 `Arc<Core>` 共享，互不干扰。

## 开发

```bash
cargo check          # 类型检查
cargo clippy         # lint（当前零警告）
cargo test           # 单元测试（规则匹配 / DNS 编解码 / CA 生成）
cargo build --release
```

Windows 上要显式用 MSVC 工具链（`cargo +stable-x86_64-pc-windows-msvc check|build`）：
若默认 host 是 `x86_64-pc-windows-gnu`，`getrandom` 会因找不到 `dlltool.exe` 直接编译失败。

## 已知限制

- 代理与监听在 0.0.0.0 时的管理界面都没有鉴权，只建议回环使用（启动时会告警）
- 上游只走 HTTP/1.1；被 MITM 的连接里带 `Upgrade`（WebSocket）的请求会被当作普通请求转发而升级失败，
  需要走原域名的话给该域名关掉 MITM 规则即可（盲隧道不受影响）
- 规则改动即时生效，但端口/监听地址/`insecureTls` 需要重启进程
- `raw.githubusercontent.com` 图片镜像会把原始 URL 交给第三方 `ghproxy.net`；带 `token=` 的私有链接
  会被第三方看到且通常无法取回，不要依赖该规则访问私有资源
