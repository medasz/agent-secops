#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
render-skeleton.py - 依据 parse-ids-excel.py 产出的 JSON 事实基座，渲染确定性 MD 骨架。

严格对齐 alert-report-template.md 的章节结构：
  §1 报告概述 / §2 外部攻击研判(2.1-2.5) / §3 攻击成功·失陷IP研判 /
  §4 内部攻击研判(4.1-4.5) / §5 专项研判(5.1-5.4) / §6 详细数据附录(6.1-6.2)
并额外保留「§7 攻击链还原与研判结论」（LLM 补写，研判核心价值）与
「§8 安全建议」（模板固定四项），使离线 IDS 报告与主报告（路径A）同构。

确定性铁律：除 §7 攻击链还原/研判结论由 LLM 补写外，其余统计与清单全部由本脚本
依据事实基座渲染，LLM 不得重造或删改脚本数字。

用法：
  python render-skeleton.py --input <facts.json> --output <skeleton.md> \
      [--title <标题>] \
      [--ban-ip-table <ban-ip-table-{date}.md>] \
      [--ban-domain-table <ban-domain-table-{date}.md>] \
      [--whitelist-count N] \
      [--threat-intel-table <threat-intel-table-{date}.md>] \
      [--xff-ban-ip-table <xff-ban-ip-table-{date}.md>] \
      [--xff-threat-intel-table <xff-threat-intel-table-{date}.md>]
依赖：python3
"""
import argparse, json, os, sys

LEVEL_ORDER = ["低危", "中危", "高危", "危急"]


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(esc(c) for c in r) + " |")
    return "\n".join(out)


def join_threat(top_threat):
    if not top_threat:
        return "—"
    return ", ".join(f"{t[0]}({t[1]})" for t in top_threat[:2])


def read_file_or_note(path, note):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return note


def scan_keywords(ext, kws):
    """从外部攻击源按关键词（威胁名称/二级类型）派生专项命中，确定性渲染。"""
    hits = []
    seen = set()
    for x in ext:
        names = [t[0] for t in x.get("top_threat", [])] + [t[0] for t in x.get("top_lv2", [])]
        text = " ".join([str(x.get("ip", ""))] + names).lower()
        if any(kw.lower() in text for kw in kws) and x["ip"] not in seen:
            seen.add(x["ip"])
            hits.append((x["ip"], join_threat(x.get("top_threat", [])) or "—", x["count"]))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--title", default=None,
                    help="报告标题；缺省时自动由导出窗口生成，格式「安全运营研判告警分析报告 {start} ~ {end}」（start/end 用 '-' 连接）")
    ap.add_argument("--ban-ip-table", default=None, help="ban-ip-table-{date}.md（四列封禁表，注入 §2.1）")
    ap.add_argument("--ban-domain-table", default=None, help="ban-domain-table-{date}.md（注入 §2.2）")
    ap.add_argument("--whitelist-count", type=int, default=None,
                    help="白名单过滤排除 IP 总数（覆盖用；默认自动取 fact JSON 的 stats.whitelist_excluded，即解读阶段被 ipWhite.md 剔除的外部源 IP 数）")
    ap.add_argument("--threshold-filtered-count", type=int, default=None,
                    help="阈值过滤排除 IP 数（ban-ip-candidates JSON 的 threshold_filtered_count，攻击次数≤min-attacks，注入 §6.1）")
    ap.add_argument("--valid-external-count", type=int, default=None,
                    help="有效外部攻击 IP 数（阈值过滤后剩余封禁候选数，注入 §6.1）")
    ap.add_argument("--min-attacks", type=int, default=10,
                    help="阈值下限（攻击次数≤此值即被阈值过滤，默认 10，注入 §6.1）")
    ap.add_argument("--threat-intel-table", default=None, help="融合情报表 MD（注入 §2.3；Step 2C 产出，微步可用时必填）")
    ap.add_argument("--xff-ban-ip-table", default=None, help="XFF 封禁表 MD（注入 §5.1；Step 2D gen-xff-judgment.js 产出，必填）")
    ap.add_argument("--xff-threat-intel-table", default=None, help="XFF 情报表 MD（注入 §5.1；Step 2C/2D 产出，微步可用时必填）")
    a = ap.parse_args()

    with open(a.input, encoding="utf-8") as f:
        d = json.load(f)

    meta = d["meta"]; st = d["stats"]; cls = d["classification"]

    # ---- 标题自动推导：与 ES 版一致，格式「安全运营研判告警分析报告 {start} ~ {end}」----
    # 优先取导出文件名窗口（export_window_*）；缺失时回退告警首末时间（window_*）。
    def fmt_win(s):
        return (s or "").replace(" ", "-")
    ew_start, ew_end = fmt_win(meta.get("export_window_start")), fmt_win(meta.get("export_window_end"))
    w_start, w_end = fmt_win(meta.get("window_start")), fmt_win(meta.get("window_end"))
    win_start, win_end = (ew_start, ew_end) if (ew_start and ew_end) else (w_start, w_end)
    if a.title:
        title = a.title
    elif win_start and win_end:
        title = f"安全运营研判告警分析报告 {win_start} ~ {win_end}"
    else:
        title = "安全运营研判告警分析报告（流量传感器导出）"

    by_dim = st.get("by_dimension", {})
    compromised = d.get("compromised", [])
    ioc = d.get("ioc", {})
    ext = cls.get("external", [])
    victims = cls.get("victims", [])
    lateral_src = cls.get("lateral_sources", [])
    lateral_dst = cls.get("lateral_targets", [])
    xff_clients = cls.get("xff_clients", [])
    xff_victims = cls.get("xff_victims", [])
    external_by_lv2 = st.get("external_by_lv2", {})
    external_hourly = st.get("external_hourly", {})
    lateral_hourly = st.get("lateral_hourly", {})
    lateral_by_lv2 = st.get("lateral_by_lv2", {})

    out = []
    # ---- 报告头（固定元信息，gen-html-report.js 据此抽取 title/time/range/analyst）----
    out.append(f"# {title}")
    out.append("")
    out.append(f"**报告生成时间**：{meta.get('report_time') or '（待填）'}")
    out.append(f"**数据来源**：{os.path.basename(meta.get('input') or '').strip() or '（待填）'}")
    out.append(f"**研判时间范围**：{meta.get('export_window_start') or meta.get('window_start', '')} 至 {meta.get('export_window_end') or meta.get('window_end', '')}")
    out.append(f"**研判人员**：SecOps Agent")
    out.append("")
    out.append("> 本报告由 IDS 导出告警清单（Excel）研判生成。以下统计与清单由脚本确定性渲染，攻击链还原 / 研判结论 / 应急建议由研判人员补写。")
    out.append("")

    # ---- §1 报告概述（对齐模板字段，离线项以 N/A/实际值填充）----
    out.append("---")
    out.append("")
    out.append("## 1. 报告概述")
    out.append("")
    by_lvl = st.get("by_level", {}); by_res = st.get("by_result", {})
    rows1 = [
        ["告警总数", str(st.get("total", 0))],
        ["外部攻击告警数", str(by_dim.get("外部攻击", 0))],
        ["内部攻击告警数", str(by_dim.get("横向攻击", 0))],
        ["外联攻击告警数", str(by_dim.get("外联攻击", 0))],
        ["攻击成功/失陷IP数", str(len(compromised))],
        ["涉及外部IP数", str(len(ext))],
        ["涉及内部主机数", str(len(victims))],
        ["精确总数（Excel全量）", str(st.get("total", 0))],
    ]
    rows1.append(["威胁级别分布", "；".join(f"{k} {v}" for k, v in by_lvl.items() if v) or "—"])
    rows1.append(["攻击结果分布", "；".join(f"{k} {v}" for k, v in by_res.items() if v) or "—"])
    out.append(md_table(["指标", "数值"], rows1))
    out.append("")

    # ---- §2 外部攻击研判 ----
    out.append("## 2. 外部攻击研判")
    out.append("")
    out.append("### 2.1 IP封禁建议（建议立即封禁）")
    out.append("")
    out.append(read_file_or_note(a.ban_ip_table,
                 "（未提供封禁表，处置以 `ban-ip-table-{date}.md` 为准。）"))
    out.append("")
    out.append("### 2.2 Domain封禁建议（建议立即封禁）")
    out.append("")
    out.append(read_file_or_note(a.ban_domain_table,
                 "（未提供域名封禁表，处置以 `ban-domain-table-{date}.md` 为准。）"))
    out.append("")
    out.append("### 2.3 IP威胁情报")
    out.append("")
    out.append(read_file_or_note(a.threat_intel_table,
                 "（威胁情报未启用/降级；详见 Step 2C 微步 enrich，公网不通时报告注明「威胁情报查询结果不可用」）"))
    out.append("")
    out.append("### 2.4 外部攻击趋势-按类型分布")
    out.append("")
    out.append(md_table(["二级告警类型", "次数"],
                        [[t, n] for t, n in external_by_lv2.items()] or [["—", "—"]]))
    out.append("")
    out.append("### 2.5 外部攻击趋势-按时间分布")
    out.append("")
    out.append(md_table(["时间", "告警数"],
                        [[h, n] for h, n in external_hourly.items()] or [["—", "—"]]))
    out.append("")

    # ---- §3 攻击成功/失陷IP研判 ----
    out.append("## 3. 攻击成功/失陷IP研判")
    out.append("")
    out.append("> 以下主机已被攻击成功或确认失陷（按 `受害IP` 聚合），建议立即进行应急响应。")
    out.append("")
    rows3 = []
    for c in compromised:
        rows3.append([c["ip"],
                      ", ".join(f"{k}{v}" for k, v in c.get("result", {}).items()),
                      ", ".join(c.get("sources", [])[:6]) or "—",
                      join_threat(c.get("top_threat", [])) or "—",
                      c.get("last") or "—"])
    out.append(md_table(["受害IP", "攻击结果", "来源", "主要威胁", "最近时间"], rows3 or [["—"] * 5]))
    out.append("")

    # ---- §4 内部攻击研判 ----
    out.append("## 4. 内部攻击研判")
    out.append("")
    out.append("> 以下数据统计源IP为局域网的内部攻击，横向移动为源和目的都是内网的子集。")
    out.append("")
    out.append("### 4.1 内部攻击统计")
    out.append("")
    rows41 = [
        ["横向攻击告警数", str(by_dim.get("横向攻击", 0))],
        ["外联攻击告警数", str(by_dim.get("外联攻击", 0))],
        ["横向移动源IP数", str(len(lateral_src))],
        ["横向移动目标IP数", str(len(lateral_dst))],
        ["外联发起主机数（受害/资产）", str(len(cls.get("tunnel_sources", [])))],
    ]
    out.append(md_table(["指标", "数值"], rows41))
    out.append("")
    out.append("### 4.2 内部攻击趋势-按类型分布")
    out.append("")
    out.append(md_table(["二级告警类型", "次数"],
                        [[t, n] for t, n in lateral_by_lv2.items()] or [["—", "—"]]))
    out.append("")
    out.append("### 4.3 横向移动源IP Top10")
    out.append("")
    rows43 = [[x["ip"], str(x["count"]), str(x["records"]),
               join_threat(x.get("top_threat", [])), str(x.get("victim_count", 0))]
              for x in lateral_src[:10]]
    out.append(md_table(["横向源IP", "总次数", "记录数", "主要威胁", "受害主机数"], rows43 or [["—"] * 5]))
    out.append("")
    out.append("### 4.4 横向移动目标IP Top10")
    out.append("")
    rows44 = [[x["ip"], str(x["count"]), str(x["records"]),
               join_threat(x.get("top_threat", [])), str(x.get("victim_count", 0))]
              for x in lateral_dst[:10]]
    out.append(md_table(["横向目标IP", "总次数", "记录数", "主要威胁", "受害主机数"], rows44 or [["—"] * 5]))
    out.append("")
    out.append("### 4.5 横向移动攻击趋势-按时间分布")
    out.append("")
    out.append(md_table(["时间", "告警数"],
                        [[h, n] for h, n in lateral_hourly.items()] or [["—", "—"]]))
    out.append("")

    # ---- §5 专项研判 ----
    out.append("## 5. 专项研判")
    out.append("")
    out.append("### 5.1 XFF 代理攻击")
    out.append("")
    out.append(f"> 检出含 XFF 代理行 {sum(1 for r in d.get('rows', []) if r.get('xff'))} 条；"
               f"外部真实客户端 {len(xff_clients)} 个，受害IP {len(xff_victims)} 个。"
               f"供研判溯源外部真实客户端IP（链末端非内网项）。")
    out.append("")
    out.append("#### XFF-外部真实客户端IP")
    out.append("")
    rows_xc = [[x["ip"], str(x["count"]), ", ".join(x.get("victims", [])[:6]) or "—",
                join_threat(x.get("top_threat", [])) or "—"] for x in xff_clients[:20]]
    out.append(md_table(["外部客户端IP", "次数", "受害IP", "主要威胁"], rows_xc or [["—"] * 4]))
    out.append("")
    out.append("#### XFF-受害IP")
    out.append("")
    rows_xv = [[x["ip"], str(x["count"]), ", ".join(x.get("clients", [])[:6]) or "—"] for x in xff_victims[:20]]
    out.append(md_table(["受害IP", "次数", "外部客户端IP"], rows_xv or [["—"] * 3]))
    out.append("")
    out.append("#### XFF-IP封禁建议表")
    out.append("")
    out.append(read_file_or_note(a.xff_ban_ip_table,
                 "（XFF 封禁建议由 judgment-xff 子技能产出；本报告未启用该子技能时此处为空）"))
    out.append("")
    out.append("#### XFF-IP威胁情报")
    out.append("")
    out.append(read_file_or_note(a.xff_threat_intel_table,
                 "（XFF 威胁情报未启用；详见 judgment-xff 子技能）"))
    out.append("")

    # 5.2 / 5.3 / 5.4 专项主题（从外部攻击源按关键词派生，确定性渲染）
    special = [
        ("5.2", "弱口令,暴力猜解,非授权访问/权限绕过攻击",
         ["弱口令", "暴力", "猜解", "未授权", "权限绕过", "默认口令", "非法访问", "口令"]),
        ("5.3", "远控木马/C2 外联攻击",
         ["远控", "木马", "后门", "C2", "反弹", "RAT", "Trojan", "AgentTesla",
          "AsyncRAT", "SilverFox", "NjRAT", "Gh0st", "Cobalt", "ToDesk",
          "CPolar", "Tailscale", "WireGuard", "OpenVPN"]),
        ("5.4", "挖矿/勒索攻击",
         ["挖矿", "勒索", "矿池", "矿工", "勒索软件", "WannaCry", "Miner", "CoinMiner", "XMRig"]),
    ]
    for sec_no, title, kws in special:
        out.append(f"### {sec_no} {title}")
        out.append("")
        hits = scan_keywords(ext, kws)
        if hits:
            out.append(md_table(["攻击源IP", "主要威胁", "次数"],
                                [[ip, thr, str(n)] for ip, thr, n in hits[:25]]))
        else:
            out.append(f"（本期未检出显著{title.split('，')[0]}类告警）")
        out.append("")

    # ---- §6 详细数据附录 ----
    out.append("## 6. 详细数据附录")
    out.append("")
    out.append("### 6.1 IP过滤结果")
    out.append("")
    wl = a.whitelist_count if a.whitelist_count is not None else st.get("whitelist_excluded", 0)
    thr = a.threshold_filtered_count if a.threshold_filtered_count is not None else 0
    valid = a.valid_external_count if a.valid_external_count is not None else len(ext)
    # 对齐 ES 版 gen-md-report：检出数=白名单剔除前的外部源数（含白名单），满足 检出=白名单+阈值+有效
    detected = len(ext) + wl
    out.append(f"- 本次检出外部攻击IP：{detected}")
    out.append(f"- 经白名单过滤{wl}个IP，阈值过滤{thr}个IP（攻击次数≤{a.min_attacks}），有效外部攻击IP：{valid}个")
    out.append("")
    out.append("### 6.2 外部攻击IP完整列表")
    out.append("")
    # 对齐 ES 版 5 列结构：最近告警时间 | 攻击IP | 攻击次数 | 归属地 | 攻击类型(次数)
    def join_attacks(x):
        lv2 = x.get("top_lv2", [])
        if not lv2:
            return "—"
        return ", ".join(f"{t[0]}({t[1]})" for t in lv2)
    rows62 = [[x.get("last") or "—", x["ip"], str(x["count"]),
               x.get("geo") or "—",
               join_attacks(x)] for x in ext[:80]]
    out.append(md_table(["最近告警时间", "攻击IP", "攻击次数", "归属地", "攻击类型(次数)"], rows62 or [["—"] * 5]))
    out.append("")

    # ---- §7 攻击链还原与研判结论（保留，LLM 补写）----
    out.append("## 7. 攻击链还原与研判结论 (SecOps Agent LLM 研判)")
    out.append("")
    out.append("> 结合 §2–§6 事实基座，还原核心攻击事件链（侦察→利用→植入→命令控制→横向/外联），给出失陷判定与应急响应优先级。")
    out.append("")
    for sub, hint in [
        ("7.1 研判概述", "一句话总括本期态势与最高风险。"),
        ("7.2 核心事件还原", "按核心事件①②③…组织：受害主机 / 疑似来源 / URI 或载荷特征 / 次数 / 时间线。"),
        ("7.3 IOC 提炼", "外联/隧道/恶意域名（区分合法公网 DNS 如 223.5.5.5 与恶意 C2）、公网攻击源、恶意 URI 特征。"),
        ("7.4 失陷/攻击成功主机分级", "按 P0/P1/P2 对失陷与攻击成功主机分级。"),
        ("7.5 应急响应优先级", "处置建议优先级（封禁/隔离/溯源/规则优化）。"),
    ]:
        out.append(f"### {sub}")
        out.append("")
        out.append(f"<!-- LLM-JUDGMENT: {hint} -->")
        out.append("")
        out.append("_（此处由研判人员基于事实基座补充）_")
        out.append("")

    # ---- §8 安全建议（模板固定四项）----
    out.append("## 8. 安全建议")
    out.append("")
    out.append("1. **跟踪处置**：对「封禁建议」 IP/域名 执行封禁或隔离。")
    out.append("2. **溯源排查**：对「攻击成功/失陷」 IP 进行溯源取证；重点排查内网横向移动与失陷的IDC主机/办公终端。")
    out.append("3. **规则优化**：根据攻击类型分布动向及时动态调整防守动作、调整IDS检测监控研判规则。")
    out.append("4. **应急联动**：持续监控、积极研判、跟踪处置，继续坚持`监控-研判-处置`联动机制。")
    out.append("")
    out.append("---")
    out.append("")
    out.append("**报告结束**")
    out.append("")
    out.append("---")
    out.append("")
    out.append("※ Powered by SecOps Agent Skill ※")
    out.append("内容由 AI 生成，请核实关键细节")

    # newline="\n" 保证跨平台均产出 LF（CRLF 会让 gen-html-report.js 的标题正则 ^#{1,4}\s+.+$ 失效）
    with open(a.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out))
    sys.stdout.write(f"[OK] skeleton written: {a.output}\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
