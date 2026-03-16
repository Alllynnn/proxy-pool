# 🚀 Proxy Pool — sing-box 多端口代理池

一键将代理订阅转换为 **每个节点一个本地端口** 的 sing-box 配置，实现多 IP 出口代理池。

## ✨ 特性

- 🔄 **多订阅合并** — 支持多个订阅 URL，节点自动合并到同一端口池
- 📡 **协议全覆盖** — anytls / tuic / vless / vmess / trojan / shadowsocks
- 📋 **订阅格式** — Clash YAML / Base64 URI 列表自动检测
- 🔃 **文件变动自动重载** — 修改 `subscriptions.conf` 后自动更新配置并重启
- 🖥️ **systemd 集成** — 开机自启、日志管理、状态监控一体化
- 🌐 **局域网共享** — 默认监听 `0.0.0.0`，局域网内设备均可使用

## 📦 架构

```
订阅 URL (可多个)
   ↓
subscriptions.conf (多行配置)
   ↓
sub2singbox.py 解析 + 转换
   ↓
sing-box config.json
   ↓
0.0.0.0:20001 → 节点1 (SOCKS5)
0.0.0.0:20002 → 节点2 (SOCKS5)
0.0.0.0:20003 → 节点3 (SOCKS5)
...
```

## 🛠️ 快速部署

### 1. 安装 sing-box

```bash
# Ubuntu / Debian
sudo curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
sudo chmod a+r /etc/apt/keyrings/sagernet.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" | \
  sudo tee /etc/apt/sources.list.d/sagernet.list
sudo apt-get update && sudo apt-get install -y sing-box
```

### 2. 部署脚本

```bash
sudo mkdir -p /opt/proxy-pool
sudo cp sub2singbox.py update-subscription.sh /opt/proxy-pool/
sudo chmod +x /opt/proxy-pool/update-subscription.sh
```

### 3. 配置订阅

```bash
# 创建订阅配置文件，每行一个 URL
sudo tee /opt/proxy-pool/subscriptions.conf << 'EOF'
# 每行一个订阅 URL，# 开头为注释
https://your-subscription-url-1/clash
https://your-subscription-url-2/clash
EOF
```

### 4. 首次运行

```bash
sudo /opt/proxy-pool/update-subscription.sh
```

### 5. 设置自动重载（可选）

```bash
# 安装 systemd path unit — 修改 subscriptions.conf 后自动更新
sudo cp proxy-pool-watcher.path proxy-pool-update.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-pool-watcher.path
```

## 📖 使用方法

### 基本使用

```bash
# 测试代理
curl --socks5 127.0.0.1:20001 ifconfig.me

# 从局域网使用
curl --socks5 <服务器IP>:20001 ifconfig.me

# 在程序中使用
export ALL_PROXY=socks5://127.0.0.1:20001
```

### 管理操作

```bash
# 编辑订阅（保存后自动更新！）
sudo nano /opt/proxy-pool/subscriptions.conf

# 手动更新
sudo /opt/proxy-pool/update-subscription.sh

# 添加新订阅并更新
sudo /opt/proxy-pool/update-subscription.sh "https://new-sub-url"

# 查看自动更新日志
sudo journalctl -u proxy-pool-update.service --no-pager -n 30

# 查看 sing-box 状态
systemctl status sing-box

# 查看活跃端口数
sudo ss -lntp | grep sing-box | wc -l
```

### 脚本参数

```bash
# 多订阅模式（推荐）
python3 sub2singbox.py --config /opt/proxy-pool/subscriptions.conf

# 单订阅模式
python3 sub2singbox.py --sub "https://example.com/sub"

# 本地文件模式
python3 sub2singbox.py --sub-file /tmp/nodes.yaml

# 自定义端口和监听地址
python3 sub2singbox.py --config subscriptions.conf --start-port 30001 --listen 127.0.0.1

# 预览配置（不写入文件）
python3 sub2singbox.py --config subscriptions.conf --dry-run
```

## 📁 文件说明

| 文件 | 说明 |
|------|------|
| `sub2singbox.py` | 核心脚本：订阅解析 + sing-box 配置生成 |
| `update-subscription.sh` | 一键更新脚本（拉取 → 生成 → 验证 → 重启） |
| `subscriptions.conf` | 订阅配置文件模板 |
| `proxy-pool-watcher.path` | systemd path unit（监控文件变更） |
| `proxy-pool-update.service` | systemd service unit（执行更新） |

## ⚙️ 环境要求

- Linux (Ubuntu 20.04+ / Debian 11+)
- Python 3.8+
- PyYAML (`pip install pyyaml` 或系统自带)
- [sing-box](https://sing-box.sagernet.org/) 1.13+

## 📝 注意事项

- sing-box 1.13+ 有破坏性变更，本项目已适配新格式
- `subscriptions.conf` 中的订阅 URL 不要包含敏感信息（公开仓库，该文件以模板形式存在）
- 默认端口从 20001 开始递增，确保防火墙放行相应端口

## License

MIT
