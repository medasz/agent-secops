#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse-ids-excel.py - 解析流量传感器「告警列表」导出的 xlsx，产出规范化 JSON 事实基座（fact base）
供 ids-fastReport 子技能做告警研判与报告渲染。

输入：IDS 平台导出的「告警列表-流量传感器_列表导出*.xlsx」（68 列标准表头）
输出：规范化 JSON，包含：
  - meta        : 输入文件、行数、时间窗口、报告时间
  - stats       : 确定性聚合（总数/按级别/按结果/按攻击维度/按二级类型/威胁名称 Top/时间分桶）
  - classification : 外部攻击 / 横向攻击 / 外联攻击 / 其他 四类拆分
  - top_sources / top_victims : 攻击源 Top & 受害主机 Top（含地理、威胁、次数）
  - compromised : 失陷/攻击成功受害主机清单
  - ioc         : IOC 抽取（外联域名、公网攻击源、URI 特征、命中 IOC 字段）
  - rows        : 逐行规范化简表（供 LLM 攻击链推理，字段精简防上下文爆炸）

用法：
  python parse-ids-excel.py --input <xlsx> --output <json> [--sheet Sheet1] [--report-time "YYYY-MM-DD HH:MM:SS"]
依赖：python3 + openpyxl（pip install openpyxl）
"""
import argparse, json, os, re, sys
from collections import Counter, OrderedDict

try:
    import openpyxl
except ImportError:
    sys.stderr.write("[ERROR] 缺少 openpyxl，请先安装：pip install openpyxl\n")
    sys.exit(1)

# ---------------------------------------------------------------- 字段常量
VICTIM = "受害IP"
ATTACK_IP = "攻击IP"
ASSET_IP = "资产IP"
FIRST_TIME = "首次发生时间"
LAST_TIME = "最近发生时间"
LV1 = "一级告警类型"
LV2 = "二级告警类型"
THREAT = "威胁名称"
IOC_ID = "威胁情报IOC/规则ID"
RESULT = "攻击结果"
LEVEL = "威胁级别"
COUNT = "次数"
STAGE = "攻击阶段"
DIMENSION = "攻击维度"
GEO = "攻击IP地理信息"
DOMAIN = "域名"
URI = "URI"
SRC_IP = "源IP"
DST_IP = "目的IP"
SRC_PORT = "源端口"
DST_PORT = "目的端口"
PROTO = "协议"
DISPOSE = "处置状态"
XFF = "XFF代理"
THREAT_TAGS_ATK = "攻击IP情报标签"

LEVEL_ORDER = ["低危", "中危", "高危", "危急"]
RESULT_OF_INTEREST = ("攻击成功", "失陷")

# 内网判定：局域网占位 / RFC1918 / 常见内网网段
PRIVATE_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|169\.254\.|"
    r"100\.6[4-9]\.|100\.[7-9]\d\.|100\.1[01]\d\.|100\.12[0-7]\.)")

# 公共递归 DNS / 合法基础设施源（非攻击源，供审计但不应视为外部攻击者）
PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    "223.5.5.5", "223.6.6.6", "119.29.29.29", "114.114.114.114",
    "180.76.76.76", "208.67.222.222", "208.67.220.220",
}

def is_internal_ip(ip):
    if not ip:
        return True
    ip = str(ip).strip()
    if ip.lower() == "局域网":
        return True
    return bool(PRIVATE_RE.match(ip))


DEFAULT_WHITELIST = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "..", "references", "ipWhite.md")

def _ip_to_long(ip):
    """点分 IPv4 -> 32 位无符号整数；失败返回 -1（与 whitelist.js ip2long 一致）"""
    parts = ip.split(".")
    if len(parts) != 4:
        return -1
    try:
        vals = [int(p) for p in parts]
    except ValueError:
        return -1
    if any(v < 0 or v > 255 for v in vals):
        return -1
    r = 0
    for v in vals:
        r = (r << 8) | v
    return r & 0xFFFFFFFF


def extract_export_window(path):
    """从导出文件名解析「导出时间窗口」（用于报告标题，统一 ES 版格式）。
    文件名形如「告警列表-流量传感器_列表导出2026-08-16T21_00_00.000至2026-08-17T09_00_00.000.xlsx」，
    解析为 [start, end]（"YYYY-MM-DD HH:MM:SS"）；解析失败返回 [None, None]。
    """
    fn = os.path.basename(path)
    m = re.search(
        r"(\d{4}-\d{2}-\d{2})T(\d{2})_(\d{2})_(\d{2})\.000至"
        r"(\d{4}-\d{2}-\d{2})T(\d{2})_(\d{2})_(\d{2})\.000",
        fn,
    )
    if not m:
        return [None, None]
    g = m.groups()
    start = f"{g[0]} {g[1]}:{g[2]}:{g[3]}"
    end = f"{g[4]} {g[5]}:{g[6]}:{g[7]}"
    return [start, end]


def load_whitelist(path):
    """解析 references/ipWhite.md（与父级 shared/whitelist.js 同格式：单IP/CIDR/短段/长段），
    返回 [{format, ipLong, maskLong?, startLong?, endLong?}]。用于把公司/内网/合法源从
    外部攻击源清单剔除，保持 §3 与 §2.4 封禁表口径一致。文件缺失时返回空表，仅靠内置私网/DNS判定。"""
    if not path or not os.path.exists(path):
        return []
    entries = []
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if not s or s.startswith(("#", "|", "-")):
            continue
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$", s)
        if m:
            base = _ip_to_long(m.group(1)); bits = int(m.group(2))
            if base != -1 and 0 <= bits <= 32:
                mask = (~0 << (32 - bits)) & 0xFFFFFFFF if bits else 0
                entries.append({"format": "cidr", "ipLong": base, "maskLong": mask})
            continue
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", s)
        if m:
            a, b = _ip_to_long(m.group(1)), _ip_to_long(m.group(2))
            if a != -1 and b != -1 and b >= a:
                entries.append({"format": "range", "startLong": a, "endLong": b})
            continue
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", s)
        if m:
            a = _ip_to_long(m.group(1) + m.group(2)); b = _ip_to_long(m.group(1) + m.group(3))
            if a != -1 and b != -1 and b >= a:
                entries.append({"format": "range", "startLong": a, "endLong": b})
            continue
        m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", s)
        if m:
            v = _ip_to_long(m.group(1))
            if v != -1:
                entries.append({"format": "single", "ipLong": v})
    return entries


def in_whitelist(ip, entries):
    if not ip or not entries:
        return False
    v = _ip_to_long(str(ip).strip())
    if v == -1:
        return False
    for e in entries:
        if e["format"] == "single" and v == e["ipLong"]:
            return True
        if e["format"] == "cidr" and (v & e["maskLong"]) == (e["ipLong"] & e["maskLong"]):
            return True
        if e["format"] == "range" and e["startLong"] <= v <= e["endLong"]:
            return True
    return False

def norm_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 1

def norm_str(v):
    return "" if v is None else str(v).strip()

def hour_bucket(ts):
    # ts like "2026-08-13 06:31:33"
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[ T])(\d{2})", str(ts))
    if not m:
        return None
    return m.group(1).replace("T", " ") + m.group(2) + ":00"

def sub_after(text, key):
    """从字符串中截取 key 之后的内容（用于 XFF 链抽取关键字段，保守实现）"""
    idx = text.find(key)
    return text[idx+len(key):] if idx >= 0 else ""

# ------------------------------------------------------------------ 主逻辑
def parse_excel(path, sheet=None):
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    name = sheet or wb.sheetnames[0]
    ws = wb[name]
    it = ws.iter_rows(values_only=True)
    hdr = list(next(it))
    idx = {h: i for i, h in enumerate(hdr)}
    def g(r, k):
        i = idx.get(k)
        return r[i] if i is not None and i < len(r) else None

    records = []
    times = []
    for r in it:
        first = norm_str(g(r, FIRST_TIME))
        last = norm_str(g(r, LAST_TIME))
        if first:
            times.append(first)
        if last:
            times.append(last)
        records.append({
            "first_time": first,
            "last_time": last,
            "victim": norm_str(g(r, VICTIM)),
            "attack_ip": norm_str(g(r, ATTACK_IP)),
            "asset_ip": norm_str(g(r, ASSET_IP)),
            "lv1": norm_str(g(r, LV1)),
            "lv2": norm_str(g(r, LV2)),
            "threat": norm_str(g(r, THREAT)),
            "ioc_id": norm_str(g(r, IOC_ID)),
            "result": norm_str(g(r, RESULT)),
            "level": norm_str(g(r, LEVEL)),
            "count": norm_int(g(r, COUNT)),
            "stage": norm_str(g(r, STAGE)),
            "dimension": norm_str(g(r, DIMENSION)),
            "geo": norm_str(g(r, GEO)),
            "domain": norm_str(g(r, DOMAIN)),
            "uri": norm_str(g(r, URI))[:300],
            "dispose": norm_str(g(r, DISPOSE)),
            "proto": norm_str(g(r, PROTO)),
            "sip": norm_str(g(r, SRC_IP)),
            "dip": norm_str(g(r, DST_IP)),
            "sport": norm_str(g(r, SRC_PORT)),
            "dport": norm_str(g(r, DST_PORT)),
            "xff": norm_str(g(r, XFF)),
            "atk_tags": norm_str(g(r, THREAT_TAGS_ATK)),
            "severity_rank": LEVEL_ORDER.index(norm_str(g(r, LEVEL))) if norm_str(g(r, LEVEL)) in LEVEL_ORDER else -1,
        })
    wb.close()
    return records, sorted(times) if times else []

def classify(rec):
    """基于 攻击维度 主字段 + IP/地理 兜底，返回 external / lateral / tunnel / other"""
    dim = rec["dimension"]
    src = rec["attack_ip"]
    if dim == "外部攻击":
        # IDS 维度字段不可全信：若源为内网 IP，实为内网横向/内部互访；公共 DNS 为合法基础服务
        if src and is_internal_ip(src):
            return "lateral"
        if src and src.strip() in PUBLIC_DNS:
            return "other"
        return "external"
    if dim == "横向攻击":
        return "lateral"
    if dim == "外联攻击":
        return "tunnel"
    # 兜底
    if src and not is_internal_ip(src):
        return "external"
    return "other"

def build(records, times, input_path, report_time, whitelist_entries=None):
    whitelist_entries = whitelist_entries or []
    total = len(records)
    by_level = Counter(r["level"] for r in records if r["level"])
    by_result = Counter(r["result"] for r in records if r["result"])
    by_lv1 = Counter(r["lv1"] for r in records if r["lv1"])
    by_lv2 = Counter(r["lv2"] for r in records if r["lv2"])
    by_threat = Counter(r["threat"] for r in records if r["threat"])
    by_dim = Counter(r["dimension"] for r in records if r["dimension"])

    # 时间分桶按最近发生时间
    hourly = Counter()
    for r in records:
        b = hour_bucket(r["last_time"] or r["first_time"])
        if b:
            hourly[b] += 1

    # 分类拆分
    classes = {"external": [], "lateral": [], "tunnel": [], "other": []}
    for r in records:
        classes[classify(r)].append(r)

    # 攻击源 Top（只对外部/横向的真源，外联反向看受害）
    def src_agg(recs, key):
        agg = OrderedDict()
        for r in recs:
            k = r[key]
            if not k:
                continue
            d = agg.setdefault(k, {"ip": k, "geo": r["geo"], "threat": Counter(), "lv2": Counter(),
                                   "level": Counter(),
                                   "count": 0, "records": 0, "victims": set(), "first": None, "last": None})
            d["count"] += r["count"]
            d["records"] += 1
            if r["threat"]:
                d["threat"][r["threat"]] += r["count"]
            if r["lv2"]:
                d["lv2"][r["lv2"]] += r["count"]
            if r["level"]:
                d["level"][r["level"]] += 1
            if r["victim"]:
                d["victims"].add(r["victim"])
            d["first"] = min(d["first"], r["first_time"]) if d["first"] and r["first_time"] else (d["first"] or r["first_time"])
            d["last"] = max(d["last"], r["last_time"]) if d["last"] and r["last_time"] else (d["last"] or r["last_time"])
        return agg

    # 外部攻击源/受害：仅取真正的公网外部攻击（源为公网 IP 且非白名单）。内网"外部攻击"维度记录
    # 已由 classify() 归入 lateral；白名单(ipWhite.md)源在此剔除，保持与 §2.4 封禁表口径一致
    # whitelist_excluded：统计被白名单剔除的 unique 源 IP 数（与 ES 版 gen-md-report 的 whitelistedExcluded 按 IP 计口径一致）
    whitelist_excluded = len({r["attack_ip"] for r in classes["external"]
                              if r.get("attack_ip") and in_whitelist(r["attack_ip"], whitelist_entries)})
    ext_recs = [r for r in classes["external"] if not in_whitelist(r.get("attack_ip"), whitelist_entries)]
    ext_src = src_agg(ext_recs, "attack_ip")
    ext_vic = src_agg(ext_recs, "victim")

    # 外联攻击：发起方通常为受害/资产主机，目的为公网。按受害(发起)IP聚合
    tunnel_src = src_agg(classes["tunnel"], "victim")
    # 外联目的(公网IOC)
    tunnel_dst = src_agg(classes["tunnel"], "attack_ip")

    # XFF 代理聚合：抽提 XFF 链中的外部真实客户端 IP -> 受害主机集
    # XFF 列文本形如 "192.0.2.42" 或 "198.51.100.201,203.0.113.201"（链末端为最外层真实客户端）
    xff_by_client = OrderedDict()      # 外部真实客户端IP -> {victims:set, count, threat:Counter, first,last}
    xff_victim_map = OrderedDict()     # 受害IP -> {clients:set, count, first,last}
    for r in records:
        if not r["xff"] or not r["victim"]:
            continue
        clients = [c.strip() for c in re.split(r"[,\s;|，；]+", r["xff"]) if c.strip()]
        if not clients:
            continue
        # 链末端(最外层)视为外部真实客户端；仅取非内网项避免把 CDN/网关内跳当客户端
        externals = [c for c in clients if not is_internal_ip(c)] or clients[-1:]
        for cli in externals:
            c = xff_by_client.setdefault(cli, {"ip": cli, "victims": set(), "count": 0,
                                               "threat": Counter(), "first": None, "last": None,
                                               "geo": None})
            c["victims"].add(r["victim"])
            c["count"] += r["count"]
            if r["threat"]:
                c["threat"][r["threat"]] += r["count"]
            c["first"] = min(c["first"], r["first_time"]) if c["first"] and r["first_time"] else (c["first"] or r["first_time"])
            c["last"] = max(c["last"], r["last_time"]) if c["last"] and r["last_time"] else (c["last"] or r["last_time"])
            if r["geo"]:
                c["geo"] = c["geo"] or r["geo"]
        v = xff_victim_map.setdefault(r["victim"], {"ip": r["victim"], "clients": set(), "count": 0,
                                                    "first": None, "last": None})
        v["clients"].update(externals)
        v["count"] += r["count"]

    # 横向/内部攻击分析：仅取横向攻击维度的源与目的 Top + 按小时（供报告 §4）
    lateral_recs = classes["lateral"]
    lateral_src = src_agg(lateral_recs, "attack_ip")   # 横向源
    lateral_dst = src_agg(lateral_recs, "victim")      # 横向目标(受害)
    lateral_hourly = Counter()
    for r in lateral_recs:
        b = hour_bucket(r["last_time"] or r["first_time"])
        if b:
            lateral_hourly[b] += 1

    # 外部攻击：按二级类型分布 + 按小时分布（供报告 §2.4 / §2.5）
    # 复用上面已剔除白名单/私网的 ext_recs，保证趋势与 §3 外部源口径一致
    ext_by_lv2 = Counter(r["lv2"] for r in ext_recs if r["lv2"])
    ext_hourly = Counter()
    # 横向/内部攻击：按二级类型分布（供报告 §4.2）
    lateral_by_lv2 = Counter(r["lv2"] for r in lateral_recs if r["lv2"])
    for r in ext_recs:
        b = hour_bucket(r["last_time"] or r["first_time"])
        if b:
            ext_hourly[b] += 1

    # 失陷/攻击成功受害主机
    compromised = OrderedDict()
    for r in records:
        if r["result"] in RESULT_OF_INTEREST and r["victim"]:
            d = compromised.setdefault(r["victim"], {"ip": r["victim"], "result": Counter(), "level": Counter(),
                                                     "threat": Counter(), "records": 0, "count": 0,
                                                     "sources": set(), "last": None})
            d["result"][r["result"]] += 1
            d["level"][r["level"]] += 1
            d["threat"][r["threat"]] += r["count"]
            d["records"] += 1
            d["count"] += r["count"]
            if r["attack_ip"]:
                d["sources"].add(r["attack_ip"])
            d["last"] = max(d["last"], r["last_time"]) if d["last"] else r["last_time"]

    # IOC 抽取
    # 域名聚合：仅取「协议 = dns」的 DNS 查询记录（父 ban-domain-table.js 同为 DNS 服务器语义），
    # 按域名聚合 lv2 攻击类型 + 最近发生时间；天然排除 HTTP Host/SNI 与 ip:port 噪音。
    ioc_domains = OrderedDict()
    ioc_uris = Counter()
    ioc_public = Counter()
    for r in records:
        if r["proto"].lower() == "dns" and r["domain"]:
            for d in re.split(r"[,\s;|，；]+", r["domain"]):
                d = d.strip()
                if not d or "." not in d:
                    continue
                rec = ioc_domains.setdefault(d, {"domain": d, "count": 0, "records": 0,
                                                 "lv2": Counter(), "max_timestamp": None})
                rec["count"] += r["count"]
                rec["records"] += 1
                if r["lv2"]:
                    rec["lv2"][r["lv2"]] += r["count"]
                if r["last_time"] and (rec["max_timestamp"] is None or r["last_time"] > rec["max_timestamp"]):
                    rec["max_timestamp"] = r["last_time"]
        if r["uri"] and len(r["uri"]) > 3:
            ioc_uris[r["uri"]] += 1
        if not is_internal_ip(r["attack_ip"]) and r["attack_ip"]:
            ioc_public[r["attack_ip"]] += 1

    stats = {
        "total": total,
        "by_level": dict(by_level),
        "by_result": dict(by_result),
        "by_lv1": dict(by_lv1),
        "by_lv2": dict(by_lv2),
        "by_dimension": dict(by_dim),
        "top_threats": by_threat.most_common(40),
        "hourly": OrderedDict(sorted(hourly.items())),
        "class_breakdown": {k: len(v) for k, v in classes.items()},
        # 被白名单(ipWhite.md)剔除的外部源 IP 数（供 §6.1；与 ES 版 whitelistedExcluded 口径一致）
        "whitelist_excluded": whitelist_excluded,
        # 外部攻击:按二级类型 / 按小时（供报告 §2.4/2.5）
        "external_by_lv2": dict(ext_by_lv2.most_common()),
        "external_hourly": OrderedDict(sorted(ext_hourly.items())),
        # 横向攻击:按二级类型（供报告 §4.2）
        "lateral_by_lv2": dict(lateral_by_lv2.most_common()),
        # 横向攻击:按小时（供报告 §4.5）
        "lateral_hourly": OrderedDict(sorted(lateral_hourly.items())),
    }

    def triify(d):
        return [{"ip": k, "geo": v["geo"], "count": v["count"], "records": v["records"],
                 "top_threat": v["threat"].most_common(3), "top_lv2": v["lv2"].most_common(3),
                 "levels": dict(v["level"]),
                 "victim_count": len(v["victims"]), "first": v["first"], "last": v["last"]}
                for k, v in sorted(d.items(), key=lambda kv: (-kv[1]["count"], -kv[1]["records"]))]

    fact = {
        "meta": {
            "input": input_path,
            "total_rows": total,
            "window_start": times[0] if times else "",
            "window_end": times[-1] if times else "",
            "export_window_start": extract_export_window(input_path)[0],
            "export_window_end": extract_export_window(input_path)[1],
            "report_time": report_time,
        },
        "stats": stats,
        "classification": {
            "external": triify(ext_src),
            "victims": triify(ext_vic),
            "tunnel_sources": triify(tunnel_src),
            "tunnel_destinations": triify(tunnel_dst),
            # 横向/内部攻击：源与目标 Top（供报告 §4.3/4.4）
            "lateral_sources": triify(lateral_src),
            "lateral_targets": triify(lateral_dst),
            # XFF 代理：外部真实客户端 -> 受害主机（供 §5.1）
            "xff_clients": [
                {"ip": v["ip"], "victims": sorted(v["victims"]),
                 "top_threat": v["threat"].most_common(3),
                 "count": v["count"], "first": v["first"], "last": v["last"],
                 "geo": v["geo"]}
                for v in sorted(xff_by_client.values(), key=lambda x: (-x["count"], x["ip"]))[:40]
            ],
            "xff_victims": [
                {"ip": v["ip"], "clients": sorted(v["clients"]), "count": v["count"],
                 "first": v["first"], "last": v["last"]}
                for v in sorted(xff_victim_map.values(), key=lambda x: (-x["count"], x["ip"]))[:80]
            ],
        },
        "compromised": [{**v, "result": dict(v["result"]), "level": dict(v["level"]),
                         "top_threat": v["threat"].most_common(5), "sources": sorted(v["sources"])}
                        for v in compromised.values()],
        "ioc": {
            "domains": [
                {"domain": v["domain"], "count": v["count"], "records": v["records"],
                 "attack_types": [{"type": t, "count": c} for t, c in v["lv2"].most_common(5)],
                 "max_timestamp": v["max_timestamp"]}
                for v in sorted(ioc_domains.values(), key=lambda x: (-x["count"], x["domain"]))[:60]
            ],
            "public_attack_ips": ioc_public.most_common(60),
            "uris": ioc_uris.most_common(30),
        },
        # 精简逐行，供 LLM 攻击链推理；保留异常/成功/失陷优先
        "rows": [{
            "t": r["first_time"], "last": r["last_time"], "victim": r["victim"],
            "src": r["attack_ip"], "geo": r["geo"], "threat": r["threat"],
            "result": r["result"], "level": r["level"], "n": r["count"],
            "dim": r["dimension"], "stage": r["stage"], "proto": r["proto"],
            "sport": r["sport"], "dport": r["dport"], "uri": r["uri"][:120],
            "domain": r["domain"], "xff": r["xff"][:80], "g": r["geo"],
        } for r in records],
    }
    return fact

def main():
    ap = argparse.ArgumentParser(description="解析 IDS 导出 Excel 为规范化 JSON 事实基座")
    ap.add_argument("--input", required=True, help="xlsx 文件路径")
    ap.add_argument("--output", required=True, help="输出 JSON 路径")
    ap.add_argument("--sheet", default=None, help="工作表名（默认第一个）")
    ap.add_argument("--report-time", default="", help="报告时间，如 2026-08-13 18:40:00")
    ap.add_argument("--whitelist", default=DEFAULT_WHITELIST,
                    help="白名单文件（默认 references/ipWhite.md，剔除公司/内网/合法源，与封禁表口径一致）")
    a = ap.parse_args()

    if not os.path.exists(a.input):
        sys.stderr.write(f"[ERROR] 输入文件不存在: {a.input}\n"); sys.exit(2)
    records, times = parse_excel(a.input, a.sheet)
    if not records:
        sys.stderr.write("[ERROR] 表中无数据行\n"); sys.exit(3)
    wl = load_whitelist(a.whitelist)
    fact = build(records, times, a.input, a.report_time, whitelist_entries=wl)
    os.makedirs(os.path.dirname(os.path.abspath(a.output)), exist_ok=True)
    # newline="\n" 保证跨平台产出 LF（下游 MD 渲染对 CRLF 敏感）
    with open(a.output, "w", encoding="utf-8", newline="\n") as f:
        json.dump(fact, f, ensure_ascii=False, indent=2)
    sys.stdout.write(
        f"[OK] parsed {fact['meta']['total_rows']} rows | window {fact['meta']['window_start']} ~ {fact['meta']['window_end']}\n"
        f"  by_dimension={fact['stats']['by_dimension']}\n"
        f"  by_level={fact['stats']['by_level']}\n"
        f"  by_result={fact['stats']['by_result']}\n"
        f"  compromised={len(fact['compromised'])}\n"
        f"  output={a.output}\n")
    sys.exit(0)

if __name__ == "__main__":
    main()
