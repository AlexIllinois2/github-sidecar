# github-sidecar

[docmirror/dev-sidecar](https://github.com/docmirror/dev-sidecar)（开发者边车）核心功能的 Rust 重写版，
定位很窄：**一个只为 GitHub 加速的本地 HTTP 代理**。

- **单二进制**，没有常驻 Electron，适合日常后台挂着跑
- **默认只接管 GitHub 域名**（Linux 下由 PAC 分流），其他流量直连，不干扰命令行和桌面程序
- **默认不解密任何 HTTPS**：没有任何启用中的 MITM/重定向规则，CA 不参与链路
- 启动即监听代理端口，并自动用系统默认浏览器打开内置 Web 管理界面

## 功能

| 功能 | 说明 |
| --- | --- |
| HTTP/HTTPS 代理 | 基于 hyper + rustls，带上游连接池 |
| DNS 竞速（优选） | 命中规则的域名同时向多个公共 DNS 发查询，取最快的有效结果，绕开污染/超时 |
| IP 测速优选 | 规则可配候选 IP 池，对池内 IP 并发做 TCP+TLS（SNI=原域名）+ `GET /robots.txt` 存活校验，按完整请求耗时选最快的可用 IP 直连；探测不阻塞首个请求，整批全挂会立即补测一轮；连接路径对前 8 个候选并行竞速（happy eyeballs） |
| 冷启动复用 | 真正拿到过响应的 IP 按域名落盘到 `last-good.json`，下次启动直接拿来先连，同时在后台重测/校验 |
| IP 直连 | 规则可指定目标 IP 列表，直连但保留原 SNI/主机名（dev-sidecar 的 github 加速思路） |
| 镜像重定向 | 命中域名+路径的 GET/HEAD 请求 302 到镜像站（ghproxy.net、npmmirror 等），需 MITM |
| MITM 解密 | 按规则解密 HTTPS（首用自动生成根 CA，按域名即时签发叶证书），`mitmAll` 默认**关闭**；内置的 Release 与 raw 图片镜像规则也默认**关闭**，因此默认没有任何 MITM 流量 |
| 故障恢复 | 隧道看门狗识别“握手成功但数据面黑洞”，单次停顿先换 IP，短窗口内累计两次才冷却该 IP |
| Web 管理界面 | actix-web 内置，热更新规则/设置，实时日志，CA 下载，IP 优选结果展示，「打开 GitHub」快捷入口 |
| 系统代理 | Linux 用 **PAC 自动代理**（只代理启用规则命中的域名）；macOS/Windows 只能设全局手动代理。`autoSystemProxy` 默认开启，退出时恢复 |
| 自动打开浏览器 | 可关（`--no-open` 或设置里关闭） |

## 快速开始

```bash
cargo build --release
./target/release/github-sidecar            # 启动并自动打开 http://127.0.0.1:10678
```

- 代理地址：`http://127.0.0.1:3128`
- 管理界面：`http://127.0.0.1:10678`
- 数据目录：`~/.config/github-sidecar/`（`config.json`、`ca.crt`、`ca.key.pem`、`last-good.json`）

终端使用：

```bash
export https_proxy=http://127.0.0.1:3128 http_proxy=http://127.0.0.1:3128
# 只想让 git 走代理：
git config --global http.https://github.com.proxy http://127.0.0.1:3128
```

命令行参数：`--proxy-port`、`--admin-port`、`--data-dir`、`--config`、`--no-open`、`--no-system-proxy`。

## 系统代理

默认 `autoSystemProxy=true`，启动时自动设置、Ctrl+C / SIGTERM 退出时恢复。

- **Linux（GNOME）**：设为「自动代理」，指向 `http://127.0.0.1:10678/proxy.pac`。
  PAC 由管理端口动态生成，只包含**启用中规则**的域名，命中返回 `PROXY 127.0.0.1:3128; DIRECT`
  （侧车不可达时浏览器直连兜底），其余域名一律 `DIRECT`。gsettings 不支持 PAC 时自动回退为手动代理。
  设置前会快照原有 mode/autoconfig-url/http/https 设置，退出时原样恢复；若原设置本身指向本程序，则置为 `none`。
- **macOS / Windows**：系统层面没有可用的 PAC 通路，设置的是**全局手动代理**（`networksetup` / 注册表），
  所有流量都会经过侧车；退出时关闭代理，不恢复设置前的代理（平台未做快照）。
- **KDE 等其他桌面**：不自动设置，请手动把系统代理指向 `http://127.0.0.1:3128`。

## 规则说明

规则按顺序匹配，第一条命中的生效。每条规则可以组合：

- **hosts**：`github.com` 精确匹配、`*.github.com` 子域匹配
- **ip_override**：直连这些 IP（TLS 的 SNI 仍是原域名，证书校验正常通过），优先级最高
- **ip_pool**：候选 IP 池，自动对池内 IP 做 443/TCP+TLS（SNI=原域名）建连测速，选最快的可用 IP 直连；
  全部失败自动落回 DNS 竞速兜底。管理界面「IP 优选结果」面板可见当前选择
- **dns_servers**：对这些 DNS 服务器竞速解析
- **path_prefixes + rewrite_to**：路径命中后 302 重定向。留空表示该域名下的全部路径；
  前缀以 `/` 开头是 starts_with，以 `*` 开头是 contains；
  `fullUrl` 开启时把完整原始 URL 拼到镜像地址后面（如 `https://ghproxy.net/https://github.com/...`）
- **mitm**：解密该域名的 HTTPS 才能看见并改写路径（需要安装 CA；仅 DNS/IP 加速不需要）

解析顺序：`ip_override`（手填）→ `ip_pool`（测速优选）→ 上次可用 IP + `dns_servers` 竞速 → 系统解析。
所有候选都会按 `(域名, IP)` 剔除冷却期内的坏 IP（全部命中冷却时退回原列表，不会把域名断掉）。

只要规则填了 `rewrite_to`，该域名的 HTTPS 就会被解密（不看路径无法改写），并且解密判定取
**所有命中规则的并集**：把纯 DNS/IP 加速规则排在前面，不会屏蔽掉后面那条需要 MITM 的重定向规则。

### IP 优选的探测与缓存

- **判据是真实响应字节，不只看握手**：TCP + TLS 之后发 `GET /robots.txt`，任何 HTTP 状态码都算存活，
  只看是否拿到首块响应字节。HEAD 只能证明响应头到达，无法识别“握手成功、数据面黑洞”，实测会把
  HEAD 200 但 GET 一个字节都没有的 IP 当成可用。
- **并发 12、单步 2s、整轮 4s 截止**；整轮全挂时 500ms 后立即补测一轮（3s 截止）。
  实测 12 并发与 4 并发/串行的可用 IP 完全相同，降低并发只会把整轮从 ~1.5s 拖到 6s/21s，故不做限流。
- **缓存 5 分钟**，过期后台单飞重测（stale-while-revalidate，不阻塞请求）；空结果的负缓存 30 秒，
  但每 4 秒会后台补测一轮，不会一次瞬时全挂要等满 30 秒。
- **坏 IP 冷却 600 秒**：数据面停顿在同一 `(域名, IP)` 上 180 秒内累计 2 次才判坏并冷却，探测与
  DNS/系统解析结果都会避开它。

### 连通信息持久化（冷启动）

真正可用过的 IP 会写入 `~/.config/github-sidecar/last-good.json`（域名 → IP、时间戳、来源
`probe`/`tunnel`，每域名最多 6 个，原子写入）。启动后：

1. 有历史记录时**立即复用它建连**（不等探测跑完），同时后台跑一轮真实重测；
2. 对只做 DNS 竞速的域名，后台对落盘 IP 逐个做一次轻量校验，失效的删除；
3. 没有任何历史（或盘上 IP 全失效）时，仍按“后台探测 + DNS 竞速”兜底，不阻塞首个请求。

### 内置默认规则

| 规则 | 域名 | 默认 | 说明 |
| --- | --- | --- | --- |
| `builtin-github` | `github.com` | 开 | IP 优选（12 个候选）+ DNS 竞速 |
| `builtin-github-subdomain` | `*.github.com`（含 api/gist/codeload） | 开 | 可用 IP 与主站不是同一套，只做 DNS 竞速 |
| `builtin-github-cdn` | `*.githubusercontent.com`、`*.githubassets.com`、`*.github.io` | **关** | Fastly 承载，实测直连与经侧车相当甚至更好（avatars 直连更稳），让浏览器直连 |
| `builtin-github-release` | `github.com` 下载路径 | **关** | 302 到 `ghproxy.net`，需 MITM |
| `builtin-github-raw-image` | `raw.githubusercontent.com` 图片 | **关** | 302 到 `ghproxy.net`，需 MITM |

默认关闭状态下没有任何启用的 MITM/重定向规则，`mitmAll` 也为 `false`，CA 不参与链路。
升级时会对存量配置做一次性迁移（`raw-image-mitm-off`、`cdn-direct-v1`），只关闭这两个内置规则，
之后手动开启不会被再次覆盖，用户自建/修改的规则不动。

## 管理界面

- 状态卡片：请求数、隧道数、错误数；IP 优选结果与当前选定 IP
- 「快捷入口 → 打开 GitHub」：新标签页打开 `https://github.com`（浏览器遵循系统代理时自动经侧车）
- 规则/设置热更新、实时日志、CA 证书下载、系统代理开关

## 与原版 (Electron) 的差异

- 原版的 **JS 拦截脚本** 改为数据驱动的重定向规则（覆盖 release/npm/ajax 等常见场景，但不支持任意自定义 JS）
- 原 IP/镜像列表随时间失效：本版以内置候选池 + 自动测速优选 + 落盘复用保持 IP 可用（镜像站仍留给用户在界面里填）
- **默认只接管 GitHub 相关域名**：Linux 用 PAC 分流；原版更容易连无关流量一起接管
- 无托盘图标（本来就是后台进程 + 网页管理）；无油猴脚本包
- Linux 下系统代理走 gsettings（GNOME），KDE 等其它桌面请手动配

## 架构

```
src/
├── main.rs          启动编排（配置 → CA → 代理 → 管理线程 → 开浏览器 → 信号清理）
├── config.rs        Settings/Rule 模型、默认规则、一次性迁移、持久化
├── state.rs         共享状态、规则匹配、上游客户端（连接池 + 自定义解析器 + TLS）
├── dns.rs           手写精简 UDP DNS 客户端（A/AAAA 并发、多服务器竞速、缓存）
├── speedtest.rs     IP 测速优选（并发 GET 探测、按耗时排序、缓存/补测、坏 IP 冷却）
├── goodip.rs        最近可用 IP 的落盘与冷启动复用（域名 → IP/时间戳/来源）
├── ca.rs            根 CA 生成/加载、按域名即时签发叶证书（rcgen + rustls）
├── proxy.rs         代理引擎：明文转发 / CONNECT 盲隧道（前 8 候选并行竞速 + TLS app-data 看门狗）/ MITM 解密转发
├── admin.rs         actix-web 管理后台（REST API、动态 PAC + 内嵌单页 UI）
├── logs.rs          tracing 双写（stderr + 环形缓冲供 UI 轮询）
├── systemproxy.rs   三平台系统代理设置与恢复
└── assets/index.html  Web UI（原生 JS 单文件，编译期嵌入）
```

代理跑在主 tokio runtime；actix-web 管理后台在独立线程自己的 actix System 里，通过 `Arc<Core>` 共享，互不干扰。

## 开发

```bash
cargo check          # 类型检查
cargo clippy         # lint
cargo test           # 单元测试（规则匹配 / DNS 编解码 / 测速排序）
cargo build --release
```

Windows 上要显式用 MSVC 工具链（`cargo +stable-x86_64-pc-windows-msvc check|build`）：
若默认 host 是 `x86_64-pc-windows-gnu`，`getrandom` 会因找不到 `dlltool.exe` 直接编译失败。

## 已知限制

- 代理与监听在 0.0.0.0 时的管理界面都没有鉴权，只建议回环使用（启动时会告警）
- **macOS / Windows 是全局代理**：所有流量（不只 GitHub）都会经过侧车，没有 PAC 分流
- **非正常退出会残留系统代理**：`kill -9`、崩溃、断电时来不及恢复，PAC/手动代理会指向一个已关闭的端口。
  Linux 手动修：`gsettings set org.gnome.system.proxy mode 'none'`；macOS：`networksetup -setwebproxystate Wi-Fi off`
  （并关闭 secure web proxy）；Windows 在「Internet 选项 → 连接 → 局域网设置」里关闭代理
- `raw.githubusercontent.com` 在国内常被 SNI 级阻断：**直连和走侧车都拿不到数据**。启用 raw 图片镜像
  （需 MITM）才能显示 README 图片，代价是该域名所有 HTTPS 被解密
- 启用 raw 图片镜像后，原始 URL 会交给第三方 `ghproxy.net`；带 `token=` 的私有链接会被第三方看到且通常
  无法取回，**不要依赖该规则访问私有资源**
- 上游只走 HTTP/1.1；被 MITM 的连接里带 `Upgrade`（WebSocket）的请求会被当作普通请求转发而升级失败，
  需要走原域名的话给该域名关掉 MITM 规则即可（盲隧道不受影响）
- 规则改动即时生效，但端口/监听地址/`insecureTls` 需要重启进程
- 网络处于“整批 IP 同时被杀”的坏窗口时（GFW 分钟级波动），仍要靠重试等网络恢复；侧车能做的是
  每 4 秒补测、停顿后换 IP、复用上次可用 IP，而不是凭空变出可用线路
