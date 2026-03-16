#!/usr/bin/env python3
"""
sub2singbox.py — 订阅转 sing-box 多端口代理池配置生成器

支持格式：
  - Clash YAML 订阅（自动检测）
  - Base64 编码的 URI 列表（vmess:// vless:// trojan:// ss://）

支持协议：
  anytls / tuic / vless / vmess / trojan / shadowsocks

用法：
  python3 sub2singbox.py --sub "https://your-subscription-url" [--start-port 20001] [--listen 0.0.0.0]
"""

import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.parse
import ssl
import re
from typing import Optional

# ─────────────────────── 订阅拉取 ───────────────────────

def fetch_subscription(url: str) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box/sub2singbox"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return resp.read().decode("utf-8")

def decode_base64(s: str) -> str:
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8")
    except Exception:
        return base64.b64decode(s).decode("utf-8")

# ─────────────────────── Clash YAML 解析 ───────────────────────

def parse_clash_yaml(content: str) -> list:
    """解析 Clash YAML 格式订阅，返回节点列表"""
    try:
        import yaml
    except ImportError:
        print("[ERROR] 需要安装 PyYAML: pip3 install pyyaml", file=sys.stderr)
        sys.exit(1)

    data = yaml.safe_load(content)
    proxies = data.get("proxies", [])
    nodes = []

    for proxy in proxies:
        ptype = proxy.get("type", "")
        name = proxy.get("name", "unknown")
        node = None

        if ptype == "anytls":
            node = clash_anytls(proxy)
        elif ptype == "tuic":
            node = clash_tuic(proxy)
        elif ptype == "vless":
            node = clash_vless(proxy)
        elif ptype == "vmess":
            node = clash_vmess(proxy)
        elif ptype == "trojan":
            node = clash_trojan(proxy)
        elif ptype in ("ss", "shadowsocks"):
            node = clash_ss(proxy)
        else:
            print(f"  [SKIP] 不支持的 Clash 协议: {ptype} ({name})", file=sys.stderr)
            continue

        if node:
            node["name"] = name
            nodes.append(node)

    return nodes


def _build_tls(proxy: dict) -> Optional[dict]:
    """从 Clash proxy 构建 sing-box TLS 对象"""
    tls_enabled = proxy.get("tls", False)
    if not tls_enabled:
        return None
    tls = {
        "enabled": True,
        "insecure": proxy.get("skip-cert-verify", False),
    }
    sni = proxy.get("sni") or proxy.get("servername") or proxy.get("server", "")
    if sni:
        tls["server_name"] = sni
    alpn = proxy.get("alpn")
    if alpn:
        tls["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    fp = proxy.get("client-fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    # Reality
    pbk = proxy.get("reality-opts", {}).get("public-key", "")
    if pbk:
        tls["reality"] = {
            "enabled": True,
            "public_key": pbk,
            "short_id": proxy.get("reality-opts", {}).get("short-id", ""),
        }
    return tls


def clash_anytls(proxy: dict) -> Optional[dict]:
    """Clash anytls → sing-box anytls outbound"""
    outbound = {
        "type": "anytls",
        "tag": "",
        "server": proxy["server"],
        "server_port": int(proxy["port"]),
        "password": proxy.get("password", ""),
    }
    # anytls 强制 TLS
    tls = {
        "enabled": True,
        "insecure": proxy.get("skip-cert-verify", False),
    }
    sni = proxy.get("sni") or proxy.get("server", "")
    if sni:
        tls["server_name"] = sni
    alpn = proxy.get("alpn")
    if alpn:
        tls["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    fp = proxy.get("client-fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    outbound["tls"] = tls
    return {"outbound": outbound}


def clash_tuic(proxy: dict) -> Optional[dict]:
    """Clash tuic → sing-box tuic outbound"""
    outbound = {
        "type": "tuic",
        "tag": "",
        "server": proxy["server"],
        "server_port": int(proxy["port"]),
        "uuid": proxy.get("uuid", ""),
        "password": proxy.get("password", ""),
    }
    cc = proxy.get("congestion-controller", "bbr")
    if cc:
        outbound["congestion_control"] = cc
    # tuic 强制 TLS
    tls = {
        "enabled": True,
        "insecure": proxy.get("skip-cert-verify", False),
    }
    sni = proxy.get("sni") or proxy.get("server", "")
    if sni:
        tls["server_name"] = sni
    alpn = proxy.get("alpn")
    if alpn:
        tls["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    outbound["tls"] = tls
    return {"outbound": outbound}


def clash_vless(proxy: dict) -> Optional[dict]:
    """Clash vless → sing-box vless outbound"""
    outbound = {
        "type": "vless",
        "tag": "",
        "server": proxy["server"],
        "server_port": int(proxy["port"]),
        "uuid": proxy.get("uuid", ""),
    }
    flow = proxy.get("flow", "")
    if flow:
        outbound["flow"] = flow
    tls_obj = _build_tls(proxy)
    if tls_obj:
        outbound["tls"] = tls_obj
    # Transport
    net = proxy.get("network", "tcp")
    if net == "ws":
        ws_opts = proxy.get("ws-opts", {})
        transport = {"type": "ws"}
        if ws_opts.get("path"):
            transport["path"] = ws_opts["path"]
        if ws_opts.get("headers", {}).get("Host"):
            transport["headers"] = {"Host": ws_opts["headers"]["Host"]}
        outbound["transport"] = transport
    elif net == "grpc":
        grpc_opts = proxy.get("grpc-opts", {})
        transport = {"type": "grpc"}
        if grpc_opts.get("grpc-service-name"):
            transport["service_name"] = grpc_opts["grpc-service-name"]
        outbound["transport"] = transport
    return {"outbound": outbound}


def clash_vmess(proxy: dict) -> Optional[dict]:
    """Clash vmess → sing-box vmess outbound"""
    outbound = {
        "type": "vmess",
        "tag": "",
        "server": proxy["server"],
        "server_port": int(proxy["port"]),
        "uuid": proxy.get("uuid", ""),
        "security": proxy.get("cipher", "auto"),
        "alter_id": int(proxy.get("alterId", 0)),
    }
    tls_obj = _build_tls(proxy)
    if tls_obj:
        outbound["tls"] = tls_obj
    net = proxy.get("network", "tcp")
    if net == "ws":
        ws_opts = proxy.get("ws-opts", {})
        transport = {"type": "ws"}
        if ws_opts.get("path"):
            transport["path"] = ws_opts["path"]
        if ws_opts.get("headers", {}).get("Host"):
            transport["headers"] = {"Host": ws_opts["headers"]["Host"]}
        outbound["transport"] = transport
    elif net == "grpc":
        grpc_opts = proxy.get("grpc-opts", {})
        transport = {"type": "grpc"}
        if grpc_opts.get("grpc-service-name"):
            transport["service_name"] = grpc_opts["grpc-service-name"]
        outbound["transport"] = transport
    elif net == "h2":
        h2_opts = proxy.get("h2-opts", {})
        transport = {"type": "http"}
        if h2_opts.get("host"):
            transport["host"] = h2_opts["host"] if isinstance(h2_opts["host"], list) else [h2_opts["host"]]
        if h2_opts.get("path"):
            transport["path"] = h2_opts["path"]
        outbound["transport"] = transport
    return {"outbound": outbound}


def clash_trojan(proxy: dict) -> Optional[dict]:
    """Clash trojan → sing-box trojan outbound"""
    outbound = {
        "type": "trojan",
        "tag": "",
        "server": proxy["server"],
        "server_port": int(proxy["port"]),
        "password": proxy.get("password", ""),
    }
    # trojan 默认 TLS
    tls = {
        "enabled": True,
        "insecure": proxy.get("skip-cert-verify", False),
    }
    sni = proxy.get("sni") or proxy.get("server", "")
    if sni:
        tls["server_name"] = sni
    fp = proxy.get("client-fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    outbound["tls"] = tls
    net = proxy.get("network", "tcp")
    if net == "ws":
        ws_opts = proxy.get("ws-opts", {})
        transport = {"type": "ws"}
        if ws_opts.get("path"):
            transport["path"] = ws_opts["path"]
        if ws_opts.get("headers", {}).get("Host"):
            transport["headers"] = {"Host": ws_opts["headers"]["Host"]}
        outbound["transport"] = transport
    elif net == "grpc":
        grpc_opts = proxy.get("grpc-opts", {})
        transport = {"type": "grpc"}
        if grpc_opts.get("grpc-service-name"):
            transport["service_name"] = grpc_opts["grpc-service-name"]
        outbound["transport"] = transport
    return {"outbound": outbound}


def clash_ss(proxy: dict) -> Optional[dict]:
    """Clash shadowsocks → sing-box shadowsocks outbound"""
    outbound = {
        "type": "shadowsocks",
        "tag": "",
        "server": proxy["server"],
        "server_port": int(proxy["port"]),
        "method": proxy.get("cipher", ""),
        "password": proxy.get("password", ""),
    }
    return {"outbound": outbound}


# ─────────────────── Base64 URI 列表解析 ───────────────────

def parse_vmess_uri(uri: str) -> Optional[dict]:
    try:
        raw = uri.replace("vmess://", "")
        data = json.loads(decode_base64(raw))
        server = data.get("add", "")
        port = int(data.get("port", 443))
        uuid = data.get("id", "")
        aid = int(data.get("aid", 0))
        net = data.get("net", "tcp")
        tls_val = data.get("tls", "")
        sni = data.get("sni", "") or data.get("host", "") or server
        path = data.get("path", "")
        host = data.get("host", "")
        name = data.get("ps", "") or f"{server}:{port}"
        security = data.get("scy", "auto") or "auto"
        if not server or not uuid:
            return None
        outbound = {"type": "vmess", "tag": "", "server": server, "server_port": port,
                     "uuid": uuid, "security": security, "alter_id": aid}
        if tls_val == "tls":
            outbound["tls"] = {"enabled": True, "server_name": sni, "insecure": True}
        if net == "ws":
            t = {"type": "ws"}
            if path: t["path"] = path
            if host: t["headers"] = {"Host": host}
            outbound["transport"] = t
        elif net == "grpc":
            t = {"type": "grpc"}
            if path: t["service_name"] = path
            outbound["transport"] = t
        return {"name": name, "outbound": outbound}
    except Exception as e:
        print(f"  [WARN] vmess 解析失败: {e}", file=sys.stderr)
        return None


def parse_vless_uri(uri: str) -> Optional[dict]:
    try:
        raw = uri.replace("vless://", "")
        at_idx = raw.index("@")
        uuid = raw[:at_idx]
        rest = raw[at_idx + 1:]
        fragment = ""
        if "#" in rest:
            rest, fragment = rest.rsplit("#", 1)
            fragment = urllib.parse.unquote(fragment)
        query_str = ""
        if "?" in rest:
            host_port, query_str = rest.split("?", 1)
        else:
            host_port = rest
        if host_port.startswith("["):
            bracket_end = host_port.index("]")
            server = host_port[1:bracket_end]
            port = int(host_port[bracket_end + 2:])
        else:
            server, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        params = dict(urllib.parse.parse_qsl(query_str))
        name = fragment or f"{server}:{port}"
        outbound = {"type": "vless", "tag": "", "server": server, "server_port": port, "uuid": uuid}
        flow = params.get("flow", "")
        if flow:
            outbound["flow"] = flow
        security = params.get("security", "none")
        sni = params.get("sni", "") or server
        fp = params.get("fp", "")
        if security in ("tls", "reality"):
            tls_obj = {"enabled": True, "server_name": sni, "insecure": True}
            if fp:
                tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
            if security == "reality":
                tls_obj["reality"] = {"enabled": True,
                                      "public_key": params.get("pbk", ""),
                                      "short_id": params.get("sid", "")}
            outbound["tls"] = tls_obj
        net_type = params.get("type", "tcp")
        path = params.get("path", "")
        host = params.get("host", "")
        if net_type == "ws":
            t = {"type": "ws"}
            if path: t["path"] = path
            if host: t["headers"] = {"Host": host}
            outbound["transport"] = t
        elif net_type == "grpc":
            t = {"type": "grpc"}
            sn = params.get("serviceName", "")
            if sn: t["service_name"] = sn
            outbound["transport"] = t
        return {"name": name, "outbound": outbound}
    except Exception as e:
        print(f"  [WARN] vless 解析失败: {e}", file=sys.stderr)
        return None


def parse_trojan_uri(uri: str) -> Optional[dict]:
    try:
        raw = uri.replace("trojan://", "")
        fragment = ""
        if "#" in raw:
            raw, fragment = raw.rsplit("#", 1)
            fragment = urllib.parse.unquote(fragment)
        query_str = ""
        if "?" in raw:
            main_part, query_str = raw.split("?", 1)
        else:
            main_part = raw
        at_idx = main_part.index("@")
        password = urllib.parse.unquote(main_part[:at_idx])
        host_port = main_part[at_idx + 1:]
        if host_port.startswith("["):
            bracket_end = host_port.index("]")
            server = host_port[1:bracket_end]
            port = int(host_port[bracket_end + 2:])
        else:
            server, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        params = dict(urllib.parse.parse_qsl(query_str))
        name = fragment or f"{server}:{port}"
        sni = params.get("sni", "") or server
        outbound = {"type": "trojan", "tag": "", "server": server, "server_port": port,
                     "password": password, "tls": {"enabled": True, "server_name": sni, "insecure": True}}
        fp = params.get("fp", "")
        if fp:
            outbound["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        net_type = params.get("type", "tcp")
        path = params.get("path", "")
        host = params.get("host", "")
        if net_type == "ws":
            t = {"type": "ws"}
            if path: t["path"] = path
            if host: t["headers"] = {"Host": host}
            outbound["transport"] = t
        elif net_type == "grpc":
            t = {"type": "grpc"}
            sn = params.get("serviceName", "")
            if sn: t["service_name"] = sn
            outbound["transport"] = t
        return {"name": name, "outbound": outbound}
    except Exception as e:
        print(f"  [WARN] trojan 解析失败: {e}", file=sys.stderr)
        return None


def parse_ss_uri(uri: str) -> Optional[dict]:
    try:
        raw = uri.replace("ss://", "")
        fragment = ""
        if "#" in raw:
            raw, fragment = raw.rsplit("#", 1)
            fragment = urllib.parse.unquote(fragment)
        if "@" in raw:
            encoded_part, host_port = raw.split("@", 1)
            decoded = decode_base64(encoded_part)
            method, password = decoded.split(":", 1)
            if host_port.startswith("["):
                bracket_end = host_port.index("]")
                server = host_port[1:bracket_end]
                port = int(host_port[bracket_end + 2:])
            else:
                server, port_s = host_port.rsplit(":", 1)
                port = int(port_s)
        else:
            decoded = decode_base64(raw)
            match = re.match(r'^(.+?):(.+?)@(.+):(\d+)$', decoded)
            if not match:
                return None
            method, password, server, port = match.groups()
            port = int(port)
        name = fragment or f"{server}:{port}"
        outbound = {"type": "shadowsocks", "tag": "", "server": server,
                     "server_port": port, "method": method, "password": password}
        return {"name": name, "outbound": outbound}
    except Exception as e:
        print(f"  [WARN] ss 解析失败: {e}", file=sys.stderr)
        return None


def parse_uri_list(content: str) -> list:
    """解析 Base64 编码的 URI 列表"""
    try:
        decoded = decode_base64(content)
        lines = decoded.strip().split("\n")
    except Exception:
        lines = content.strip().split("\n")
    nodes = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        node = None
        if line.startswith("vmess://"):
            node = parse_vmess_uri(line)
        elif line.startswith("vless://"):
            node = parse_vless_uri(line)
        elif line.startswith("trojan://"):
            node = parse_trojan_uri(line)
        elif line.startswith("ss://"):
            node = parse_ss_uri(line)
        if node:
            nodes.append(node)
    return nodes


# ─────────────────── 自动检测格式 ───────────────────

def parse_subscription(content: str) -> list:
    """自动检测订阅格式（Clash YAML / Base64 URI）并解析"""
    stripped = content.strip()
    if stripped.startswith("---") or stripped.startswith("port:") or "proxies:" in stripped[:500]:
        print("  → 检测到 Clash YAML 格式")
        return parse_clash_yaml(content)
    else:
        print("  → 检测到 Base64 URI 列表格式")
        return parse_uri_list(content)


# ─────────────────── 生成 sing-box 配置 ───────────────────

def generate_singbox_config(nodes: list, start_port: int, listen: str) -> dict:
    inbounds = []
    outbounds = []
    route_rules = []

    for i, node in enumerate(nodes):
        port = start_port + i
        in_tag = f"in-{i:04d}"
        out_tag = f"out-{i:04d}"

        inbounds.append({
            "type": "socks",
            "tag": in_tag,
            "listen": listen,
            "listen_port": port,
        })

        node["outbound"]["tag"] = out_tag
        outbounds.append(node["outbound"])

        route_rules.append({
            "inbound": [in_tag],
            "outbound": out_tag,
        })

    outbounds.append({"type": "direct", "tag": "direct"})

    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": route_rules,
            "final": "direct",
        },
    }
    return config


# ─────────────────── 多订阅配置文件 ───────────────────

DEFAULT_CONFIG = "/opt/proxy-pool/subscriptions.conf"

def load_subscriptions_from_config(config_path: str) -> list:
    """
    从配置文件读取订阅列表。格式：
      - 每行一个订阅 URL
      - # 开头为注释
      - 空行忽略
    """
    urls = []
    with open(config_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def fetch_and_parse_all(urls: list) -> list:
    """拉取并解析多个订阅，合并所有节点"""
    all_nodes = []
    for i, url in enumerate(urls, 1):
        print(f"  [{i}/{len(urls)}] {url[:70]}...")
        try:
            content = fetch_subscription(url)
            nodes = parse_subscription(content)
            print(f"    ✓ {len(nodes)} 个节点")
            all_nodes.extend(nodes)
        except Exception as e:
            print(f"    ✗ 拉取失败: {e}", file=sys.stderr)
    return all_nodes


# ─────────────────── 主函数 ───────────────────

def main():
    parser = argparse.ArgumentParser(
        description="订阅转 sing-box 多端口代理池配置",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  # 多订阅模式（推荐）— 从配置文件读取所有订阅
  python3 sub2singbox.py --config /opt/proxy-pool/subscriptions.conf

  # 单订阅模式
  python3 sub2singbox.py --sub "https://example.com/sub"

  # 本地文件模式
  python3 sub2singbox.py --sub-file /tmp/nodes.yaml

配置文件格式 (subscriptions.conf)：
  # 每行一个订阅 URL，# 开头为注释
  https://example.com/sub1/clash
  https://example.com/sub2/clash
""",
    )
    parser.add_argument("--config", nargs="?", const=DEFAULT_CONFIG,
                        help=f"多订阅配置文件路径 (默认: {DEFAULT_CONFIG})")
    parser.add_argument("--sub", help="单个订阅 URL")
    parser.add_argument("--sub-file", help="本地订阅文件")
    parser.add_argument("--start-port", type=int, default=20001, help="起始端口 (默认: 20001)")
    parser.add_argument("--listen", default="0.0.0.0", help="监听地址 (默认: 0.0.0.0)")
    parser.add_argument("--output", default="/etc/sing-box/config.json", help="输出配置文件路径")
    parser.add_argument("--dry-run", action="store_true", help="仅输出到 stdout，不写文件")
    args = parser.parse_args()

    if not args.config and not args.sub and not args.sub_file:
        # 默认尝试使用配置文件
        if os.path.exists(DEFAULT_CONFIG):
            args.config = DEFAULT_CONFIG
        else:
            parser.error("请提供 --config / --sub / --sub-file 之一")

    # ── 获取节点 ──
    nodes = []

    if args.config:
        print(f"[1/4] 读取多订阅配置: {args.config}")
        urls = load_subscriptions_from_config(args.config)
        if not urls:
            print("[ERROR] 配置文件中没有有效的订阅 URL！", file=sys.stderr)
            sys.exit(1)
        print(f"  共 {len(urls)} 个订阅")
        print("[2/4] 拉取并解析所有订阅...")
        nodes = fetch_and_parse_all(urls)
    elif args.sub:
        print(f"[1/4] 拉取订阅: {args.sub[:60]}...")
        content = fetch_subscription(args.sub)
        print("[2/4] 解析节点...")
        nodes = parse_subscription(content)
    else:
        print(f"[1/4] 读取本地文件: {args.sub_file}")
        with open(args.sub_file, "r") as f:
            content = f.read()
        print("[2/4] 解析节点...")
        nodes = parse_subscription(content)

    if not nodes:
        print("[ERROR] 没有解析到任何有效节点！", file=sys.stderr)
        sys.exit(1)
    print(f"  ✓ 总计 {len(nodes)} 个节点")

    # 统计类型
    from collections import Counter
    types = Counter(n["outbound"]["type"] for n in nodes)
    for t, c in types.items():
        print(f"    {t}: {c}")

    # 生成配置
    print("[3/4] 生成 sing-box 配置...")
    config = generate_singbox_config(nodes, args.start_port, args.listen)
    config_json = json.dumps(config, indent=2, ensure_ascii=False)

    if args.dry_run:
        print(config_json)
    else:
        print(f"[4/4] 写入配置: {args.output}")
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w") as f:
            f.write(config_json)
        print(f"  ✓ 配置已写入 {args.output}")

    # 输出端口映射表
    print("\n" + "=" * 60)
    print(f"  代理池 — 共 {len(nodes)} 个节点")
    print("=" * 60)
    for i, node in enumerate(nodes):
        port = args.start_port + i
        proto = node["outbound"]["type"]
        name = node["name"]
        print(f"  socks5://{args.listen}:{port}  →  [{proto}] {name}")
    print("=" * 60)
    print(f"\n端口范围: {args.start_port} ~ {args.start_port + len(nodes) - 1}")
    print(f"示例: curl --socks5 127.0.0.1:{args.start_port} ifconfig.me")


if __name__ == "__main__":
    main()

