#!/bin/bash
# update-subscription.sh — 一键更新代理池
# 用法:
#   ./update-subscription.sh              # 读取 subscriptions.conf 配置
#   ./update-subscription.sh "单个URL"    # 直接指定 URL（同时保存到配置文件）

set -e

POOL_DIR="/opt/proxy-pool"
CONFIG_FILE="/etc/sing-box/config.json"
SUBS_CONF="$POOL_DIR/subscriptions.conf"
START_PORT=20001
LISTEN="0.0.0.0"

echo "================================================"
echo "  代理池订阅更新 — $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================"

# 确定模式
if [ -n "$1" ]; then
    # 提供了 URL 参数 → 追加到配置文件（避免重复）
    if ! grep -qF "$1" "$SUBS_CONF" 2>/dev/null; then
        echo "$1" >> "$SUBS_CONF"
        echo "[INFO] 已将订阅追加到 $SUBS_CONF"
    fi
fi

# 检查配置文件
if [ ! -f "$SUBS_CONF" ]; then
    echo "[ERROR] 配置文件 $SUBS_CONF 不存在"
    echo "请创建配置文件，每行一个订阅 URL："
    echo "  echo 'https://your-sub-url' > $SUBS_CONF"
    exit 1
fi

# 生成配置
cd "$POOL_DIR"
python3 sub2singbox.py \
    --config "$SUBS_CONF" \
    --start-port "$START_PORT" \
    --listen "$LISTEN" \
    --output "$CONFIG_FILE"

# 检查配置
echo ""
echo "[CHECK] 验证 sing-box 配置..."
if sing-box check -c "$CONFIG_FILE"; then
    echo "  ✓ 配置文件语法正确"
else
    echo "  ✗ 配置文件有误，不重启服务"
    exit 1
fi

# 重启服务
echo "[RESTART] 重启 sing-box 服务..."
sudo systemctl restart sing-box

# 等待启动
sleep 2

# 检查状态
if systemctl is-active --quiet sing-box; then
    NODE_COUNT=$(grep -c '"type": "socks"' "$CONFIG_FILE" || echo 0)
    echo ""
    echo "================================================"
    echo "  ✓ 代理池更新完成"
    echo "  活跃节点: $NODE_COUNT"
    echo "  端口范围: $START_PORT ~ $((START_PORT + NODE_COUNT - 1))"
    echo "  监听地址: $LISTEN"
    echo "================================================"
else
    echo "  ✗ sing-box 启动失败"
    sudo journalctl -u sing-box --no-pager -n 20
    exit 1
fi
