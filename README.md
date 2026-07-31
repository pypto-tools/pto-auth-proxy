# Auth Proxy

面向共享 Linux 服务器的认证出口代理。它在本机提供 SOCKS5 和 HTTP CONNECT
两个入口，使用用户自己的 Linux/PAM 凭据认证，只允许 `proxyusers` 用户组访问，
并通过域名白名单限制可访问的外部服务。

该工具主要用于让 Claude Code、Codex、Git、npm、pip 等开发工具安全地复用一条
受控的上游代理链路，同时保留按用户统计、异常检测和每日审计报告。

## 工作机制

```text
CLI / SDK
   │
   ├── HTTP CONNECT 127.0.0.1:20809
   └── SOCKS5      127.0.0.1:20808
                         │
                         ▼
                  auth_proxy.py
             用户组检查 / 白名单检查
                         │
              Unix socket 请求认证
                         ▼
            用户自己的 authd.py 进程
                  PAM 验证 Linux 密码
                         │
                         ▼
             上游代理 127.0.0.1:4780
                         │
                         ▼
                 允许的外部服务
```

代理主进程不会直接替其他用户调用 PAM。每位用户运行一个属于自己 UID 的 `authd`
守护进程，它只验证该用户本人的密码，并通过 Unix socket 的所有者和
`SO_PEERCRED` 校验调用方身份。成功认证会短暂缓存，以避免并发请求反复触发 PAM。

## 主要能力

- 同时支持 SOCKS5 用户名/密码认证和 HTTP CONNECT Basic 认证；
- 只监听 `127.0.0.1`，默认不向外部网络暴露端口；
- 同时检查 Linux 用户组和 PAM 密码；
- 按域名 glob 白名单放行，默认拒绝公共 IP 直连；
- 记录连接结果、目标域名和上下行流量；
- 检测大流量上传、高 QPS、认证失败和白名单探测；
- 每天生成 Markdown 和 JSON 审计报告；
- 收到 `SIGHUP` 后热加载 `whitelist.txt`。

## 文件说明

| 文件 | 用途 |
| --- | --- |
| `auth_proxy.py` | SOCKS5/HTTP CONNECT 代理、访问控制、统计和报告 |
| `authd.py` | 每用户运行的 PAM 验证守护进程 |
| `join-proxy.sh` | 用户接入脚本：安装并启动自己的 authd |
| `test_proxy.sh` | 用户组、认证、白名单和网络链路自测 |
| `whitelist.txt` | 允许访问的域名规则 |
| `auth_proxy.service` | 代理主进程的 systemd unit 模板 |
| `authd.service` | 每用户 authd 的 systemd user unit 模板 |
| `skill/SKILL.md` | 自动化用户接入流程 |

## 环境要求

- Linux 和 Python 3；
- PAM，以及可被 Python 导入的 `python-pam`；
- 已创建的 `proxyusers` Linux 用户组；
- 在 `127.0.0.1:4780` 可用的上游 HTTP/SOCKS 代理；
- 部署用户有权创建并访问 `/tmp/authproxy-<user>.sock`。

默认部署路径为 `/data/pypto/auth-proxy`。如果使用其他路径，需要同步修改
`join-proxy.sh` 和 systemd unit 中的路径。运行数据目录可通过
`AUTHPROXY_DIR` 环境变量调整。

## 管理员部署

以下命令应由服务器管理员根据实际用户和权限策略执行：

```bash
# 创建代理用户组
sudo groupadd -f proxyusers

# 将代理进程所有者和使用者加入组
sudo usermod -aG proxyusers pypto
sudo usermod -aG proxyusers <USER>

# 安装 PAM Python 模块（openEuler/RHEL 系）
sudo dnf install -y python3-pam
```

安装并检查 systemd unit：

```bash
sudo cp auth_proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now auth_proxy.service
sudo systemctl status auth_proxy.service
```

`auth_proxy.service` 是环境相关的模板。启用前应检查 `User`、`Group`、
`ExecStart`、`AUTHPROXY_DIR` 和 `ReadWritePaths` 是否与实际部署一致。

## 用户接入

管理员将用户加入 `proxyusers` 后，用户需要重新登录，让新的组成员关系生效，然后执行：

```bash
cd /data/pypto/auth-proxy
bash join-proxy.sh
```

脚本会：

1. 检查用户组和 `python-pam`；
2. 将 `authd.py` 安装到 `~/.local/bin/authproxy-authd.py`；
3. 启动用户自己的 authd 和 watchdog；
4. 可选地使用当前用户密码做一次本地认证测试。

认证 socket 默认位于：

```text
/tmp/authproxy-<username>.sock
```

## 配置客户端

推荐使用 HTTP CONNECT 入口，它适用于绝大多数 CLI 和 Node.js 工具：

```bash
umask 077
printf '%s' 'YOUR_LINUX_PASSWORD' > ~/.proxy-secret
chmod 600 ~/.proxy-secret
```

在 `~/.bashrc` 中加入：

```bash
export HTTPS_PROXY="http://$(id -un):$(cat ~/.proxy-secret)@127.0.0.1:20809"
export HTTP_PROXY="$HTTPS_PROXY"
export NO_PROXY='localhost,127.0.0.0/8,::1,169.254.169.254,192.168.0.0/16,10.0.0.0/8'
```

仅在客户端只支持 SOCKS5 时使用：

```bash
export ALL_PROXY="socks5h://$(id -un):$(cat ~/.proxy-secret)@127.0.0.1:20808"
```

重新加载 shell 后运行端到端检查：

```bash
source ~/.bashrc
bash /data/pypto/auth-proxy/test_proxy.sh
```

## 白名单

`whitelist.txt` 每行一个域名或 glob：

```text
github.com
*.github.com
openai.com
*.openai.com
```

修改后向代理进程发送 `SIGHUP`，无需重启已有连接：

```bash
sudo systemctl kill -s HUP auth_proxy.service
```

如果 `whitelist.txt` 不存在，程序会使用 `auth_proxy.py` 中的内置默认规则。

## 运行数据

运行数据默认写入 `AUTHPROXY_DIR`，不会提交到 Git：

| 路径 | 内容 |
| --- | --- |
| `auth_proxy.log` | 主进程文本日志 |
| `stats.jsonl` | 每次连接的用户、目标、结果和流量 |
| `alerts.jsonl` | 异常检测事件 |
| `reports/YYYY-MM-DD.md` | 每日可读报告 |
| `reports/YYYY-MM-DD.json` | 每日结构化报告 |

这些文件包含用户和访问目标等审计信息，应限制读取权限，并按组织的数据保留策略处理。

## 安全注意事项

- 不要提交 `~/.proxy-secret`、密码、日志、统计或报告；
- 不要将监听地址改为 `0.0.0.0`，除非另有防火墙和 TLS 保护；
- 不要放开公共 IP 直连，否则可能绕过域名白名单；
- 不要连续尝试错误密码，PAM `faillock` 可能锁定账号；
- 修改代理进程用户后，要同步检查 authd 中允许的调用方 UID；
- 上线前应复核 systemd 权限和硬化选项是否适配当前发行版。
