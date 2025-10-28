#!/bin/sh
# ===============================
# Nodogsplash 内核依赖检测脚本（适用于 Padavan）
# 作者: 
# ===============================

# 彩色输出定义
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
NC="\033[0m"

ok()   { echo -e "${GREEN}✔ $1${NC}"; }
fail() { echo -e "${RED}✘ $1${NC}"; }
warn() { echo -e "${YELLOW}! $1${NC}"; }

echo "======================================="
echo "🔍 Nodogsplash 内核功能依赖检测开始"
echo "======================================="

# ---------- 1. 检查 iptables 三个主要表 ----------
echo ""
echo "➡ 检查 iptables 表支持情况..."
TABLES=$(cat /proc/net/ip_tables_names 2>/dev/null)
if echo "$TABLES" | grep -q "filter"; then ok "iptable_filter 已支持"; else fail "缺少 iptable_filter"; fi
if echo "$TABLES" | grep -q "mangle"; then ok "iptable_mangle 已支持"; else fail "缺少 iptable_mangle"; fi
if echo "$TABLES" | grep -q "nat"; then ok "iptable_nat 已支持"; else fail "缺少 iptable_nat"; fi
[ -z "$TABLES" ] && warn "/proc/net/ip_tables_names 文件为空，可能为内核未启用 iptables"

# ---------- 2. 检查匹配与标记模块 ----------
echo ""
echo "➡ 检查匹配与标记模块..."
MATCHES=$(cat /proc/net/ip_tables_matches 2>/dev/null)
if echo "$MATCHES" | grep -q "mark"; then ok "xt_mark/ipt_mark 已支持"; else fail "缺少 xt_mark 模块"; fi
if echo "$MATCHES" | grep -q "mac"; then ok "xt_mac/ipt_mac 已支持"; else fail "缺少 xt_mac 模块"; fi

# ---------- 3. 检查 iptables 版本 ----------
echo ""
echo "➡ 检查 iptables 版本..."
IPTVER=$(iptables -V 2>/dev/null)
if echo "$IPTVER" | grep -q "v"; then
    echo "$IPTVER"
    VER=$(echo "$IPTVER" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -n1)
    MAJOR=$(echo "$VER" | cut -d. -f1)
    MINOR=$(echo "$VER" | cut -d. -f2)
    PATCH=$(echo "$VER" | cut -d. -f3)
    if [ "$MAJOR" -gt 1 ] || [ "$MINOR" -gt 4 ] || { [ "$MINOR" -eq 4 ] && [ "$PATCH" -ge 21 ]; }; then
        ok "iptables 版本满足要求 ($VER ≥ 1.4.21)"
    else
        fail "iptables 版本过低 ($VER)"
    fi
else
    fail "未检测到 iptables 命令或版本信息"
fi

echo ""
echo "======================================="
echo "✅ 检测完成！请根据红色 ✘ 提示修复缺失模块"
echo "======================================="
