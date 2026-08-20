# pto-auth-proxy

面向共享 Linux 服务器的认证出口代理。它在本机提供 SOCKS5 和 HTTP CONNECT
入口，使用每位用户自己的 PAM `authd` 鉴权，并通过域名白名单限制外部访问。

## ⚠️ 重要启动要求

Auth Proxy 主进程必须以配置中的 `PTO_AUTH_PROXY_OWNER` 用户运行（默认
`pypto`），不能以 root 或其他普通用户运行。否则主进程无法通过用户 `authd` 的
身份检查，其他用户的认证会失败。授权访问代理的用户组是 `proxyusers`；它与主进程
运行用户是两个不同概念。

推荐通过 systemd 启动：

```bash
sudo systemctl start pto-auth-proxy
```

需要前台诊断时，必须显式切换为代理用户：

```bash
sudo -u pypto pto-auth-proxy validate
sudo -u pypto pto-auth-proxy run
```

以下启动方式会被拒绝，并输出所需用户及修复命令：

```bash
pto-auth-proxy run
sudo pto-auth-proxy run
```

检查现有进程时，用户列应显示 `pypto`：

```bash
ps -o user,group,pid,args -C python3 | grep auth_proxy.py
```

公开命令为 `pto-auth-proxy`，正式安装遵循 `pypto-tools` 布局：

```text
/home/pypto-tools/pto-auth-proxy/
├── app/       # 可升级程序
├── config/    # 管理员配置和白名单，升级不覆盖
├── state/     # 统计、告警和报告
├── logs/      # 服务日志
└── tmp/       # 临时空间
```

## 数据链路

```text
应用
 ├── HTTP CONNECT 127.0.0.1:20809
 └── SOCKS5      127.0.0.1:20808
                       │
                 pto-auth-proxy
          用户组检查 / 白名单 / 审计
                 ┌─────┴──────────────┐
                 │ 认证旁路            │ 放行后的业务流量
                 ▼                     ▼
 /run/pto-auth-proxy/<uid>/   上游 127.0.0.1:4780
          authd.sock
                 │             （SSH RemoteForward 落点）
          用户自己的 authd              │
                 │                      ▼
              PAM 验证          远端工作站 xray → Internet
```

共享代理以非 root 用户（默认 `pypto`）运行。每个用户的 `authd` 只服务自己的身份：
首次接入通过 PAM 验证 Linux 密码并签发独立代理令牌，后续连接验证令牌；旧密码凭据
仍保持兼容。socket 所有者和 `SO_PEERCRED` 用于校验调用方身份。

`20808/20809` 是认证、白名单和审计入口，并不直接提供公网出口。每条认证并放行的
业务连接都会通过 SOCKS5 转发到 `127.0.0.1:4780`。该端口是远端工作站建立的 SSH
RemoteForward 在本机的落点，再由工作站上的 xray 访问 Internet；老版和新版都使用
这条链路，新版只是把上游地址从硬编码改成了配置项。若 `4780` 未监听，认证仍可能
成功，但业务请求会返回 `UPSTREAM-DEAD` 或 `502 Bad Gateway`。反向隧道应由建立它
的远端工作站使用 systemd/autossh 保证重连，本机的 `pto-auth-proxy.service` 无法自行
创建该远端隧道。

`pto-auth-proxy-egress-guard.service` 使用 IPv4/IPv6 `iptables owner` 规则保护
配置项 `PTO_AUTH_PROXY_GUARD_PORTS` 指定的回环上游端口（默认 `4780/4781`）：只有
代理服务账号（默认 `pypto`）能够直接连接这些端口。普通用户
必须通过认证入口 `20808/20809`，即使属于 `proxyusers` 组也不能绕过认证直连上游。
守卫服务独立于主代理运行，启动或重载规则不需要重启主代理。它每30秒检查一次规则，
发现规则被其他服务清空或覆盖时自动恢复；主代理也要求守卫成功启动后才会启动。

## 启动与重启行为

- 共享入口、出口守卫和 `pto-auth-proxy-authd-members.service` 安装并 enable 后会随
  服务器启动。
- 成员启动服务会在每次开机时枚举 `proxyusers`，通过系统级模板为每位成员启动其
  `authd`，并创建用户独占、代理组只读穿越的 `/run/pto-auth-proxy/<uid>/` 目录。
  用户不需要逐个 enable 实例，也不依赖登录会话或 linger。旧版手工实例仍兼容
  `/tmp/authproxy-<user>.sock`。
- `pto-auth-proxy join` 会优先复用已启用或运行中的 systemd 实例，并只清理旧版的
  per-home watchdog，不会启动第二个 authd；因此用户仍可安全地手动执行 `join`。
- 当前尚无 systemd 实例时，`join` 保留 `setsid + nohup` watchdog 作为首次接入的
  兼容回退；下次服务器启动会自动切换为系统级实例，之后不需要重新 `join`。
- 新增或移除组成员会在下次开机自动反映。管理员若希望立即切换，可单独启动对应模板
  实例，不需要重启共享代理。

## GitHub 支持范围

默认白名单支持 GitHub 仓库网页、API、raw 内容、release/LFS 常用资源和 HTTPS
Git 操作：

- `github.com`、`*.github.com`
- `githubusercontent.com`、`*.githubusercontent.com`
- `githubassets.com`、`*.githubassets.com`
- `codeload.github.com`

`ghcr.io`、`github.io` 和 `github.dev` 不属于核心仓库访问，默认不开放。需要时应
单独评审并加入管理员维护的 `config/whitelist.txt`。

交互式端到端测试会实际读取 GitHub 仓库网页、仓库 API 和 raw README，而不只
检查端口或 HTTP 状态码。

## 源码检查

以下命令不监听端口、不改系统状态：

```bash
./tests/run.sh
./bin/pto-auth-proxy validate
```

真实端到端测试需要现有代理服务和用户凭据，因此保持为显式交互操作：

```bash
./bin/pto-auth-proxy test
```

## 安装边界

安装、配置和生效严格分离。安装器默认只复制 `app/`，不会创建配置、安装 service
或启停现有代理：

```bash
sudo ./scripts/install.sh
```

首次创建非敏感配置和白名单：

```bash
sudo ./scripts/install.sh --init-config
```

显式安装共享代理、成员启动器和每用户 authd 模板，但仍不 enable/start/restart：

```bash
sudo ./scripts/install.sh --install-service
```

安装全部 unit 并设置开机自启动（不会立即启动或重启任何服务）：

```bash
sudo ./scripts/install.sh --init-config --enable-service
```

更新检查器与代理服务相互独立。制作镜像或预装文件时，可以只安装 unit 而不启动
轮询：

```bash
sudo ./scripts/install.sh --install-updater
```

生产服务器完成接入时应启用 timer，让主仓状态检查持续运行；这只启用轮询，并不等于
允许部署某个 commit，也不会重启代理：

```bash
sudo ./scripts/install.sh --enable-updater
```

首次上线前先校验配置；确认生产端口未被其他进程占用后，再显式启动：

```bash
sudo -u pypto pto-auth-proxy validate
sudo systemctl start pto-auth-proxy
```

管理员应以配置的代理用户运行 `pto-auth-proxy validate`，再使用影子端口验证。
`validate` 会拒绝错误的运行用户。停止旧服务、绑定
生产端口和 start/restart 均属于单独的上线操作，不由安装器执行。只有显式传入
`--enable-service` 时，安装器才会 enable 主代理、出口守卫和成员 authd 启动器。

## 配置

正式配置位于：

```text
/home/pypto-tools/pto-auth-proxy/config/auth-proxy.env
/home/pypto-tools/pto-auth-proxy/config/whitelist.txt
```

配置示例见 `config/auth-proxy.env.example`。不得将密码、token、私钥或
`~/.proxy-secret*` 写入工具配置或 Git。

常用只读命令：

```bash
pto-auth-proxy validate
pto-auth-proxy traffic 30
pto-auth-proxy traffic 30 --json
pto-auth-proxy report today
pto-auth-proxy status
```

修改白名单后可向运行进程发送 `SIGHUP` 热加载；这属于生产配置变更，应由管理员
明确执行。

## 用户接入

管理员将用户加入配置的代理组后，用户可显式运行：

```bash
pto-auth-proxy join
```

如果管理员已启用该用户的 systemd 实例，`join` 会复用它并进行交互式验证；否则会
安装并重启兼容 watchdog。因此该命令不是只读操作，但在两种模式间不会创建互相抢占
socket 的重复 daemon。`join` 只要求输入一次密码：PAM 验证成功后，自动生成权限为
`0600` 的代理令牌和环境文件，并幂等地接入 `.bashrc` 或 `.zshrc`。新版 authd 只
保存令牌摘要，Linux 密码不会作为长期代理凭据落盘。用户不需要
手动复制代理变量；新终端会将 HTTP/HTTPS 流量指向认证入口 `20809`，并将
`ALL_PROXY/all_proxy` 指向认证 SOCKS5 入口 `20808`。已经运行的 VS Code/Codex
不会被重启，需要用户方便时自行 Reload Window。

密码只允许用户在本机交互式终端中输入，不应发送给 AI、写入聊天、命令参数、仓库或
共享日志。shell rc 只包含对环境文件的引用，不包含代理凭据。令牌轮换时旧令牌有
10 分钟宽限，避免正在运行的工具突然断线。

日常自检只需运行 `pto-auth-proxy status`。它会用一行结果检查组成员、authd、凭据、
`20809` 认证链路、守卫服务以及 `4780/4781` 直连隔离，不会打印凭据。主代理对客户
端握手、上游连接、上游握手、半关闭收尾和关闭阶段均设有本机超时；上游异常时会快速失败并回收
双向转发任务，不会长期积累挂起连接。

## 主仓控制更新

更新检查与更新部署是两个不同状态：生产服务器上的 timer 持续轮询主仓，主仓
`update/rollout.json` 再决定是否允许部署以及部署哪个 commit。timer 启用本身不会
部署代码；只有 `enabled=true` 且 `target` 是完整 commit ID 时才会进入候选验证。

| `enabled` | `target` | 含义 |
| --- | --- | --- |
| `false` | 任意值 | 暂停部署；仍可保留 timer 进行主仓状态检查 |
| `true` | 空字符串 | 已允许部署但尚未选择版本（armed but idle）；正常退出，不测试、不安装 |
| `true` | 完整 commit ID | 验证并暂存该精确版本；不会自动选择分支 HEAD |

日常待命时采用第二种状态：部署能力已打开，但 `target` 为空，所以不会发生更新。填写
目标时必须同时把 `sequence` 设置为比上次成功暂存更大的正整数。序号倒退或被不同
commit 重复使用会被拒绝；回退到旧 commit 还必须显式设置
`allow_rollback: true`。

推荐发布顺序：

1. 将完整代码、安装器和测试合入 `main`，记录该代码提交的完整 commit ID。
2. 确认目标提交包含可在 updater 沙箱中运行的幂等安装逻辑；全局入口已经指向正确
   位置时不得重复改写 `/usr/local/bin`。
3. 再提交一个只修改 `update/rollout.json` 的控制提交，把 `target` 指向第一步并递增
   `sequence`。控制提交本身不是部署目标。
4. 观察更新服务日志与 `pending-activation` 标记。完成或暂不发布下一版时，可清空
   `target` 保持待命；需要紧急停止部署能力时，将 `enabled` 改为 `false`。

timer 每天北京时间 03:37 检查一次，并加入最多20分钟的随机延迟，避免所有服务器
同时访问主仓。服务器关机错过该窗口时不会在白天补跑，等待下一天即可。
在本机没有直接公网出口时，仓库拉取以非 root 代理服务账号通过受出口守卫保护的本地
SOCKS 上游完成，不复制用户 token。更新器只接受目标分支历史中的完整 commit，先以
非 root 代理账号运行候选仓库测试，成功后才安装。它保留本地配置、白名单、状态和
日志，也不会运行 `systemctl restart`：
新版本标记为 `pending-activation`，在管理员下次计划重启或服务器开机时自然激活。
因此主仓不能远程强制中断正在使用 Codex 的连接。

自动更新意味着主仓代码最终会在服务器上运行，应严格保护仓库写权限、主分支合入权限
和管理员账号。自动更新会同步应用文件和全部 systemd unit，并执行 daemon-reload，
但不会 enable、start 或 restart 服务；已运行进程保持不变，新 unit 在下次启动时生效。
安装失败时，适配器同时恢复此前的应用目录和 unit，避免新旧版本混用。

仓库拉取、清单校验、commit去重、分支祖先检查、锁和版本标记均位于独立的
`modules/repo_auto_update/`。该目录不引用 auth-proxy 名称，可以整体复制给其他工具。
接入方只需提供一份root管理的配置以及两个适配器入口：非root候选验证和root安装。
auth-proxy自己的适配器是 `scripts/auto-update-adapter.sh`；业务备份、测试和安装逻辑
不会混入通用模块。完整复用接口见模块内 `README.md` 和 `example.env`。

## 开发

仓库结构：

```text
bin/pto-auth-proxy                 # 统一命令入口
config/auth-proxy.env.example      # 非敏感配置模板
scripts/install.sh                 # 只安装，不自动生效
systemd/pto-auth-proxy.service.in  # 非 root service 模板
systemd/pto-auth-proxy-egress-guard.service.in # 上游端口访问控制
systemd/pto-auth-proxy-authd@.service.in # 每用户 authd 系统级模板
systemd/pto-auth-proxy-authd-members.service.in # 开机启动全部授权用户 authd
modules/repo_auto_update/          # 可复制的通用主仓更新模块
skills/pto-auth-proxy/SKILL.md     # 仓库级 AI Skill
tests/                             # 可重复自动测试
auth_proxy.py                      # SOCKS5 / HTTP CONNECT 主进程
authd.py                           # 每用户 PAM 认证进程
status_proxy.py                    # 一行式用户就绪检查
join-proxy.sh                      # 交互式用户接入
configure-shell.sh                 # 幂等生成用户代理环境
update/rollout.json                # 主仓发布控制清单
scripts/auto-update-adapter.sh     # auth-proxy验证/安装适配器
test_proxy.sh                      # 交互式端到端测试
config/whitelist.txt               # 初始白名单
```
