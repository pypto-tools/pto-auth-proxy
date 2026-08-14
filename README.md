# pto-auth-proxy

面向共享 Linux 服务器的认证出口代理。它在本机提供 SOCKS5 和 HTTP CONNECT
入口，使用每位用户自己的 PAM `authd` 鉴权，并通过域名白名单限制外部访问。

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
                       │
          /tmp/authproxy-<user>.sock
                       │
                 用户自己的 authd
                       │
             上游 127.0.0.1:4780
```

共享代理以非 root 用户（默认 `pypto`）运行。每个用户的 `authd` 只验证自己的
Linux 密码，并使用 socket 所有者和 `SO_PEERCRED` 校验调用方身份。

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

显式安装 systemd unit，但仍不 enable/start/restart：

```bash
sudo ./scripts/install.sh --install-service
```

管理员应先运行 `pto-auth-proxy validate`，再使用影子端口验证。停止旧服务、绑定
生产端口、enable/start/restart 均属于单独的上线操作，不由安装器执行。

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
```

修改白名单后可向运行进程发送 `SIGHUP` 热加载；这属于生产配置变更，应由管理员
明确执行。

## 用户接入

管理员将用户加入配置的代理组后，用户可显式运行：

```bash
pto-auth-proxy join
```

该操作会安装并重启当前用户自己的 `authd`，因此不是只读命令。密码只允许用户在
本机交互式终端中输入，不应发送给 AI、写入聊天、命令参数、仓库或共享日志。
代理 URL 使用的凭据文件应保存 URL 编码后的值并设为 `0600`，避免特殊字符破坏
HTTP/SOCKS URL。

## 开发

仓库结构：

```text
bin/pto-auth-proxy                 # 统一命令入口
config/auth-proxy.env.example      # 非敏感配置模板
scripts/install.sh                 # 只安装，不自动生效
systemd/pto-auth-proxy.service.in  # 非 root service 模板
skills/pto-auth-proxy/SKILL.md     # 仓库级 AI Skill
tests/                             # 可重复自动测试
auth_proxy.py                      # SOCKS5 / HTTP CONNECT 主进程
authd.py                           # 每用户 PAM 认证进程
join-proxy.sh                      # 交互式用户接入
test_proxy.sh                      # 交互式端到端测试
config/whitelist.txt               # 初始白名单
```
