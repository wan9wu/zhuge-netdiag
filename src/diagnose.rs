//! 综合诊断引擎：汇总各检测环节结果，定位网络瓶颈所在环节并给出建议。
//!
//! 判定顺序（自下而上）：
//! 1. 本机网卡/网络接口层
//! 2. 本机 → 网关（本地网络段：Wi-Fi 信号、网线、路由器）
//! 3. 网关 → 公网（运营商接入段 / 骨干网）
//! 4. 逐跳链路中的丢包 / 时延突增节点
//! 5. DNS 解析
//! 6. 应用层 HTTP

use std::net::Ipv4Addr;

use crate::dns::DnsQueryResult;
use crate::env::AdapterInfo;
use crate::http::HttpResult;
use crate::quality::QualityStats;
use crate::trace::{HopStat, PingStats};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Error,
}

impl Level {
    pub fn tag(&self) -> &'static str {
        match self {
            Level::Ok => "[正常]",
            Level::Warn => "[注意]",
            Level::Error => "[异常]",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub level: Level,
    pub segment: String,
    pub detail: String,
    pub suggestion: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Diagnosis {
    pub findings: Vec<Finding>,
    /// 一句话瓶颈结论
    pub conclusion: String,
}

/// 诊断所需的全部输入。
pub struct Inputs<'a> {
    pub adapter: Option<&'a AdapterInfo>,
    #[allow(dead_code)]
    pub adapters: &'a [AdapterInfo],
    pub gateway_addr: Option<Ipv4Addr>,
    pub gateway: Option<&'a PingStats>,
    /// ARP 链路层交叉验证（路由器禁用 ping 时防误报）
    pub gateway_arp: Option<bool>,
    /// (地址, 名称, 统计)
    pub publics: &'a [(Ipv4Addr, &'static str, PingStats)],
    /// ICMP 失败节点的 TCP 采样质量
    pub publics_quality: &'a [(Ipv4Addr, QualityStats)],
    /// 网关段 TCP 采样质量
    pub gateway_quality: Option<&'a QualityStats>,
    /// 端到端 TCP 采样质量
    pub target_quality: Option<&'a QualityStats>,
    pub target: Ipv4Addr,
    pub target_stats: Option<&'a PingStats>,
    pub dns: &'a [DnsQueryResult],
    pub dns_domain: &'a str,
    pub system_dns: &'a Option<Vec<Ipv4Addr>>,
    pub hops: &'a [HopStat],
    pub http: Option<&'a HttpResult>,
}

fn finding(level: Level, segment: &str, detail: String, suggestion: Option<String>) -> Finding {
    Finding {
        level,
        segment: segment.to_string(),
        detail,
        suggestion,
    }
}

fn is_private(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

/// 给跳数贴上所属环节的标签。
fn seg_label(ip: Ipv4Addr, index: usize, total: usize) -> &'static str {
    if is_private(ip) || index == 0 {
        "本地网络段"
    } else if index + 1 == total {
        "目标侧"
    } else {
        "运营商网络"
    }
}

pub fn run(inp: &Inputs) -> Diagnosis {
    let mut d = Diagnosis::default();

    // ---------- 1. 网卡 / 接口层 ----------
    let adapter = match inp.adapter {
        Some(a) => a,
        None => {
            d.findings.push(finding(
                Level::Error,
                "本机网络接口",
                "未找到处于工作状态、拥有 IPv4 地址的网络适配器".into(),
                Some("检查网线是否插好 / Wi-Fi 是否已连接；在 设置 → 网络和 Internet → 高级网络设置 中查看被禁用的适配器并启用".into()),
            ));
            d.conclusion = "瓶颈定位：本机网络接口层 —— 没有可用的网络连接，链路诊断无法继续。".into();
            return d;
        }
    };
    let (local_ip, prefix) = adapter.ipv4.unwrap_or((Ipv4Addr::UNSPECIFIED, 0));
    d.findings.push(finding(
        Level::Ok,
        "本机网络接口",
        format!(
            "适配器 \"{}\"（{}）已获得 IPv4 {}/{}",
            adapter.friendly_name(),
            adapter.kind,
            local_ip,
            prefix
        ),
        None,
    ));

    // ---------- 2. 网关 ----------
    // 网关之后环节的可达性证据（交叉验证）：很多路由器/运营商会屏蔽 ICMP，
    // 此时 ping 全部丢失但上网正常，不能只凭 ICMP 下结论
    let icmp_cnt = inp.publics.iter().filter(|(_, _, s)| s.received > 0).count();
    let tcp_cnt = inp.publics_quality.iter().filter(|(_, q)| q.succeeded > 0).count();
    let reachable_cnt = inp
        .publics
        .iter()
        .filter(|(ip, _, s)| {
            s.received > 0 || inp.publics_quality.iter().any(|(i, q)| i == ip && q.succeeded > 0)
        })
        .count();
    let beyond_ok = reachable_cnt > 0
        || inp.target_stats.map(|s| s.received > 0).unwrap_or(false)
        || inp.http.map(|h| h.ok()).unwrap_or(false);

    let gateway_ok: bool;
    match (inp.gateway_addr, inp.gateway) {
        (None, _) => {
            d.findings.push(finding(
                Level::Error,
                "本地网络配置",
                "网卡没有默认网关，流量无法离开本机".into(),
                Some("将 IPv4 设为自动获取（DHCP）；若使用静态 IP 请补全网关配置；然后重启网卡或路由器重试".into()),
            ));
            d.conclusion = "瓶颈定位：本地网络配置 —— 缺少默认网关，流量无法离开本机。".into();
            return d;
        }
        (Some(gw), None) => {
            d.findings.push(finding(
                Level::Error,
                "本机→网关",
                format!("无法初始化 ICMP 检测（网关 {} 未探测）", gw),
                Some("请确认系统 ICMP 组件可用，或稍后重试".into()),
            ));
            gateway_ok = false;
        }
        (Some(gw), Some(s)) => {
            if s.received == 0 {
                if inp.gateway_arp == Some(true) || beyond_ok {
                    // ICMP 全丢但网关实际在线：路由器禁用 ping 应答或 ICMP 限速
                    let detail = if inp.gateway_arp == Some(true) {
                        format!(
                            "网关 {} 不响应 ICMP ping（{} 个探测全部丢失），但 ARP 显示网关在链路层在线",
                            gw, s.sent
                        )
                    } else {
                        format!(
                            "网关 {} 的 ICMP 探测全部丢失，但网关之后的公网可达，链路实际是通的",
                            gw
                        )
                    };
                    d.findings.push(finding(
                        Level::Warn,
                        "本机→网关",
                        detail,
                        Some("这通常是路由器禁用了 ICMP 应答或做了限速，不影响上网，无需处理".into()),
                    ));
                    gateway_ok = true;
                } else {
                    d.findings.push(finding(
                        Level::Error,
                        "本机→网关",
                        format!("网关 {} 完全不可达（{} 个 ICMP 探测全部丢失，ARP 也无应答）", gw, s.sent),
                        Some("检查网线 / Wi-Fi 连接状态与路由器电源；Wi-Fi 用户尝试重连或靠近路由器、更换信道；仍不行则重启光猫和路由器".into()),
                    ));
                    d.conclusion = format!(
                        "瓶颈定位：本地网络段（本机→网关 {}）。ICMP 与 ARP 均无法到达网关，问题几乎一定出在本地网络环境（信号、网线、路由器）。",
                        gw
                    );
                    return d;
                }
            } else {
                let loss = s.loss_pct();
                if loss > 5.0 || s.avg_ms > 50.0 {
                    if beyond_ok {
                        // 网关之后链路正常：大概率是路由器对 ICMP 限速，降级为提示
                        d.findings.push(finding(
                            Level::Warn,
                            "本机→网关",
                            format!(
                                "网关 ICMP 探测质量不佳：{}，但网关之后的公网可达（可能是路由器 ICMP 限速）",
                                crate::trace::fmt_stats(s)
                            ),
                            Some("若实际上网体验正常可忽略；否则检查 Wi-Fi 信号、网线与路由器负载".into()),
                        ));
                        gateway_ok = true;
                    } else {
                        d.findings.push(finding(
                            Level::Error,
                            "本机→网关",
                            format!("到网关的链路质量差：{}", crate::trace::fmt_stats(s)),
                            Some("本地链路质量问题：Wi-Fi 信号弱 / 干扰大、网线或水晶头接触不良、路由器负载过高。建议改用有线或更换 5GHz 频段、靠近路由器、重启路由器".into()),
                        ));
                        d.conclusion = format!(
                            "瓶颈定位：本地网络段（本机→网关 {}），丢包 {:.1}%、平均时延 {:.0}ms，瓶颈在本地链路。",
                            gw, loss, s.avg_ms
                        );
                        return d;
                    }
                } else {
                    d.findings.push(finding(
                        Level::Ok,
                        "本机→网关",
                        format!("网关 {} 连通良好：{}", gw, crate::trace::fmt_stats(s)),
                        None,
                    ));
                    gateway_ok = true;
                }
            }
        }
    }

    // ---------- 3. 公网可达性 ----------
    // 除 TCP 交叉验证外，HTTP / DNS 成功也是公网可达的铁证
    let app_evidence = inp.http.map(|h| h.ok()).unwrap_or(false)
        || inp.dns.iter().any(|r| r.success)
        || inp.system_dns.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
    if reachable_cnt == 0 && gateway_ok && !app_evidence {
        d.findings.push(finding(
            Level::Error,
            "运营商接入链路",
            "网关正常，但所有公网地址均不可达（ICMP 与 TCP 均失败）".into(),
            Some("本地网络到公网中断：检查光猫指示灯（LOS 红灯通常为光纤故障）、重启光猫与路由器；仍不行请联系运营商报修".into()),
        ));
        d.conclusion = "瓶颈定位：运营商接入链路 —— 本机与网关正常，但无法到达任何公网地址，疑似宽带断网或运营商侧故障。".into();
        return d;
    }
    if icmp_cnt == 0 && gateway_ok && (tcp_cnt > 0 || app_evidence) {
        // ICMP 被整体屏蔽但 TCP/应用层正常：不是断网，降级为提示
        d.findings.push(finding(
            Level::Warn,
            "公网可达性",
            "所有公网 ICMP 探测丢失，但 TCP 连接 / HTTP / DNS 验证公网实际可达".into(),
            Some("当前网络屏蔽了 ICMP（ping）流量，属路由器或运营商的过滤策略，不影响上网，无需处理".into()),
        ));
    } else if reachable_cnt < inp.publics.len() {
        let failed: Vec<String> = inp
            .publics
            .iter()
            .filter(|(ip, _, s)| {
                s.received == 0
                    && !inp.publics_quality.iter().any(|(i, q)| i == ip && q.succeeded > 0)
            })
            .map(|(ip, name, _)| format!("{} ({})", ip, name))
            .collect();
        if failed.is_empty() {
            d.findings.push(finding(
                Level::Ok,
                "公网可达性",
                format!("全部 {} 个公网地址可达（其中 {} 个经 TCP 交叉验证）", reachable_cnt, tcp_cnt),
                None,
            ));
        } else {
            d.findings.push(finding(
                Level::Warn,
                "公网可达性",
                format!("部分公网地址不可达：{}", failed.join("、")),
                None,
            ));
        }
    } else {
        d.findings.push(finding(
            Level::Ok,
            "公网可达性",
            format!("全部 {} 个公网地址可达", reachable_cnt),
            None,
        ));
    }

    // ---------- 4. 逐跳链路分析 ----------
    let target_reachable = inp
        .target_stats
        .map(|s| s.received > 0)
        .unwrap_or(false);
    match analyze_route(inp.hops, target_reachable, inp.target, beyond_ok || app_evidence) {
        RouteVerdict::Clean(msg) => {
            d.findings.push(finding(Level::Ok, "逐跳链路", msg, None));
        }
        RouteVerdict::Bottleneck { msg, suggestion } => {
            d.findings.push(finding(Level::Error, "逐跳链路", msg.clone(), Some(suggestion)));
            if d.conclusion.is_empty() {
                d.conclusion = format!("瓶颈定位：{}", msg);
            }
        }
        RouteVerdict::Unreachable { msg, suggestion } => {
            d.findings.push(finding(Level::Error, "逐跳链路", msg.clone(), Some(suggestion)));
            if d.conclusion.is_empty() {
                d.conclusion = format!("瓶颈定位：{}", msg);
            }
        }
    }

    // ---------- 网络质量（TCP 采样分段对比） ----------
    // 对比网关段与端到端的丢包/时延，定位质量瓶颈环节；
    // 即使 ICMP 被屏蔽，TCP 采样也能给出真实的丢包率与时延
    if let Some(t) = inp.target_quality {
        let g = inp.gateway_quality.filter(|q| q.succeeded > 0);
        let gw_loss = g.map(|q| q.loss_pct());
        let e2e_loss = t.loss_pct();

        if let Some(gl) = gw_loss {
            if gl >= 20.0 {
                d.findings.push(finding(
                    Level::Error,
                    "网络质量",
                    format!(
                        "本地段（本机→网关）TCP 丢包 {:.0}%（{}），丢包严重",
                        gl,
                        crate::quality::fmt_quality(g.unwrap())
                    ),
                    Some("丢包集中在本地段：Wi-Fi 信号弱/干扰大、网线接触不良或路由器过载。建议改用有线或 5GHz、靠近路由器、重启路由器".into()),
                ));
                if d.conclusion.is_empty() {
                    d.conclusion = format!("瓶颈定位：本地网络段 —— 网关段 TCP 采样丢包 {:.0}%，质量瓶颈在本地链路。", gl);
                }
            } else if gl > 5.0 {
                d.findings.push(finding(
                    Level::Warn,
                    "网络质量",
                    format!("本地段（本机→网关）TCP 丢包 {:.0}%，质量偏差", gl),
                    Some("关注 Wi-Fi 信号与路由器负载；若上网体验正常可忽略".into()),
                ));
            }
        }

        if e2e_loss >= 20.0 {
            let beyond = gw_loss.unwrap_or(0.0) < 5.0;
            d.findings.push(finding(
                Level::Error,
                "网络质量",
                format!(
                    "端到端 TCP 丢包 {:.0}%（{}）{}",
                    e2e_loss,
                    crate::quality::fmt_quality(t),
                    if beyond { "，而本地段质量良好，丢包发生在网关之后" } else { "" }
                ),
                if beyond {
                    Some("丢包在运营商网络或目标侧：建议联系运营商报修并附上本报告；若只有特定目标丢包，也可能是对方服务器繁忙".into())
                } else {
                    Some("整体丢包严重：先排除本地段问题（Wi-Fi/路由器），再联系运营商".into())
                },
            ));
            if d.conclusion.is_empty() {
                d.conclusion = format!(
                    "瓶颈定位：{} —— 端到端 TCP 采样丢包 {:.0}%。",
                    if beyond { "运营商网络/目标侧" } else { "链路丢包严重" },
                    e2e_loss
                );
            }
        } else if e2e_loss >= 5.0 {
            d.findings.push(finding(
                Level::Warn,
                "网络质量",
                format!("端到端 TCP 丢包 {:.0}%，质量偏差", e2e_loss),
                Some("间歇性丢包：若感知明显，建议在问题高发时段重新采样并联系运营商".into()),
            ));
        } else if let (Some(g), Some(gl)) = (g, gw_loss) {
            // 时延对比：网关段之外时延突增 → 运营商/目标侧引入的延迟
            if t.avg_ms - g.avg_ms > 30.0 && t.avg_ms > g.avg_ms * 1.8 {
                d.findings.push(finding(
                    Level::Warn,
                    "网络质量",
                    format!(
                        "时延主要在网关之后产生：本地段 {:.0}ms → 端到端 {:.0}ms",
                        g.avg_ms, t.avg_ms
                    ),
                    Some("额外时延来自运营商网络或目标侧；若影响体验可向运营商反馈".into()),
                ));
            } else {
                d.findings.push(finding(
                    Level::Ok,
                    "网络质量",
                    format!(
                        "TCP 采样质量良好：本地段丢包 {:.0}%、端到端丢包 {:.0}%，端到端时延 {:.0}ms",
                        gl, e2e_loss, t.avg_ms
                    ),
                    None,
                ));
            }
        } else if t.succeeded > 0 {
            d.findings.push(finding(
                Level::Ok,
                "网络质量",
                format!(
                    "端到端 TCP 采样质量良好：丢包 {:.0}%，时延 {:.0}ms（本地段以 ICMP 统计为准）",
                    e2e_loss, t.avg_ms
                ),
                None,
            ));
        }
    }

    // ---------- 5. DNS ----------
    let public_ip_ok = reachable_cnt > 0;
    let sys_ok = inp.system_dns.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
    let direct_ok: Vec<&DnsQueryResult> = inp.dns.iter().filter(|r| r.success).collect();
    if sys_ok {
        d.findings.push(finding(
            Level::Ok,
            "DNS 解析",
            format!(
                "系统解析 {} 正常（{}）",
                inp.dns_domain,
                inp.system_dns
                    .as_ref()
                    .map(|v| v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()
            ),
            None,
        ));
    } else if !direct_ok.is_empty() {
        d.findings.push(finding(
            Level::Error,
            "DNS 配置",
            format!(
                "系统 DNS 无法解析 {}，但直连公共 DNS（{}）可以解析",
                inp.dns_domain,
                direct_ok
                    .iter()
                    .map(|r| format!("{} {}", r.server, r.label))
                    .collect::<Vec<_>>()
                    .join("、")
            ),
            Some("当前系统配置的 DNS 服务器失效或被阻断。建议把 DNS 改为 223.5.5.5（阿里 DNS）或 119.29.29.29（DNSPod）".into()),
        ));
        if d.conclusion.is_empty() {
            d.conclusion = "瓶颈定位：DNS 配置 —— 系统配置的 DNS 服务器失效，而公共 DNS 可用，网页打不开是 DNS 的问题。".into();
        }
    } else if public_ip_ok {
        d.findings.push(finding(
            Level::Error,
            "DNS 解析",
            format!("所有 DNS 服务器查询 {} 均失败，但 IP 直连公网正常", inp.dns_domain),
            Some("DNS 查询被拦截或污染：更换 DNS 为 223.5.5.5 / 8.8.8.8；检查本机防火墙、安全软件或代理设置；路由器侧也可统一修改 DNS".into()),
        ));
        if d.conclusion.is_empty() {
            d.conclusion = "瓶颈定位：DNS 解析链路 —— 全部 DNS 查询失败，域名无法打开但 IP 直连正常。".into();
        }
    } else {
        d.findings.push(finding(
            Level::Warn,
            "DNS 解析",
            "DNS 查询失败（当前公网本身不可达，待网络恢复后再验证 DNS）".into(),
            None,
        ));
    }

    // ---------- 6. HTTP 应用层 ----------
    if let Some(h) = inp.http {
        if h.ok() {
            let mut detail = format!(
                "访问 {} 成功（HTTP {}），总耗时 {}ms",
                h.host,
                h.status_code.unwrap_or(0),
                h.elapsed_ms
            );
            if !h.note.is_empty() {
                detail = format!("{}；{}", detail, h.note);
            }
            d.findings.push(finding(
                if h.note.is_empty() { Level::Ok } else { Level::Warn },
                "应用层 HTTP",
                detail,
                if h.note.is_empty() { None } else { Some("若打开网页仍被跳转到认证页，请完成网络认证（如校园网 / 酒店 Wi-Fi 登录）".into()) },
            ));
        } else if public_ip_ok {
            d.findings.push(finding(
                Level::Error,
                "应用层 HTTP",
                format!(
                    "IP 层连通但 HTTP 访问 {} 失败（{}）",
                    h.host,
                    if h.note.is_empty() { "未获得有效响应".to_string() } else { h.note.clone() }
                ),
                Some("检查系统代理设置（设置 → 网络和 Internet → 代理）、防火墙 / 安全软件拦截，或确认所在网络是否需要网页认证".into()),
            ));
            if d.conclusion.is_empty() {
                d.conclusion = "瓶颈定位：应用层 / 代理配置 —— 网络链路正常但 HTTP 请求失败，多为代理、防火墙或 Web 认证问题。".into();
            }
        }
    }

    if d.conclusion.is_empty() {
        d.conclusion = "未发现明显瓶颈：本机到公网链路各环节检查正常。若问题间歇性出现，建议在问题发生时重新诊断，或针对具体应用 / 目标再测一次。".into();
    }
    d
}

enum RouteVerdict {
    Clean(String),
    Bottleneck { msg: String, suggestion: String },
    Unreachable { msg: String, suggestion: String },
}

/// 分析逐跳链路，找出丢包 / 时延突增 / 中断的位置。
/// `beyond_evidence`：ICMP 之外存在公网可达证据（TCP/HTTP/DNS），
/// ICMP 被屏蔽时逐跳数据会缺失，此时不能判定链路中断。
fn analyze_route(
    hops: &[HopStat],
    target_reachable: bool,
    target: Ipv4Addr,
    beyond_evidence: bool,
) -> RouteVerdict {
    if hops.is_empty() {
        if beyond_evidence {
            return RouteVerdict::Clean(
                "ICMP 被屏蔽，逐跳探测无数据，但 TCP / HTTP / DNS 验证链路实际可达".into(),
            );
        }
        return RouteVerdict::Unreachable {
            msg: format!("逐跳探测没有任何数据，目标 {} 不可达", target),
            suggestion: "检查本机出站流量是否被防火墙整体拦截".into(),
        };
    }

    // 链路中断：目标不可达，找最后一个有应答的跳
    if !target_reachable {
        if beyond_evidence && hops.iter().all(|h| h.received == 0) {
            return RouteVerdict::Clean(
                "ICMP 被屏蔽，逐跳探测无任何节点应答，但 TCP / HTTP / DNS 验证链路实际可达".into(),
            );
        }
        if beyond_evidence {
            // ICMP 不可靠（部分节点应答、目标无应答），但应用层证据显示链路可达：
            // 目标或其路径上的设备不回 ICMP，不断定为中断
            return RouteVerdict::Clean(format!(
                "目标 {} 不回应 ICMP，但 TCP / HTTP / DNS 验证链路实际可达（中间部分节点也不回 ICMP）",
                target
            ));
        }
        let last_good = hops.iter().rposition(|h| h.received > 0);
        let (msg, suggestion) = match last_good {
            None => (
                "链路从第 1 跳起即中断，没有任何中间节点应答".to_string(),
                "若网关 ping 正常，问题在网关之后（运营商侧或上级路由）；请联系运营商报修".to_string(),
            ),
            Some(i) => {
                let h = &hops[i];
                let addr = h.responder.map(|a| a.to_string()).unwrap_or_default();
                let label = seg_label(h.responder.unwrap_or(target), i, hops.len());
                (
                    format!(
                        "到目标 {} 的链路在第 {} 跳之后中断，最后可达节点为第 {} 跳 {}（{}）",
                        target,
                        h.ttl + 1,
                        h.ttl,
                        addr,
                        label
                    ),
                    if label == "本地网络段" {
                        "断点在本地网络段，检查本机路由器 / 上级路由的配置与连线".to_string()
                    } else {
                        "断点在运营商网络内，建议联系运营商报修并附上本报告".to_string()
                    },
                )
            }
        };
        return RouteVerdict::Unreachable { msg, suggestion };
    }

    // 目标可达：逐跳找丢包和时延突增
    let total = hops.len();
    let mut worst: Option<(usize, String)> = None;
    let mut prev_avg: Option<(f64, usize)> = None;
    for (i, h) in hops.iter().enumerate() {
        if h.received == 0 {
            prev_avg = None; // 静默节点，不作为时延比较基准
            continue;
        }
        let loss = h.loss_pct();
        let mut reason: Option<String> = None;

        if loss >= 20.0 {
            // 判断是否为 ICMP 限速假丢包：其后的跳都正常应答
            let later_ok = hops[i + 1..].iter().filter(|x| x.received > 0).all(|x| x.loss_pct() < 10.0);
            if later_ok && loss < 50.0 {
                // 可能是限速，仅当其后跳延迟无异常时降级处理：仍提示
                reason = Some(format!("丢包 {:.0}%（其后节点正常，也可能是该节点限速 ICMP）", loss));
            } else {
                reason = Some(format!("丢包 {:.0}%", loss));
            }
        } else if let Some((p, pi)) = prev_avg {
            if h.avg_ms as f64 - p > 30.0 && h.avg_ms as f64 > p * 1.8 {
                reason = Some(format!(
                    "时延突增：第 {} 跳 {:.0}ms → 第 {} 跳 {:.0}ms",
                    hops[pi].ttl, p, h.ttl, h.avg_ms
                ));
            }
        }

        if let Some(r) = reason {
            let addr = h.responder.map(|a| a.to_string()).unwrap_or_default();
            let label = seg_label(h.responder.unwrap_or(target), i, total);
            let desc = format!("第 {} 跳 {}（{}）{}", h.ttl, addr, label, r);
            if worst.is_none() {
                worst = Some((i, desc));
            }
        }
        prev_avg = Some((h.avg_ms, i));
    }

    match worst {
        Some((i, desc)) => {
            let h = &hops[i];
            let label = seg_label(h.responder.unwrap_or(target), i, total);
            let suggestion = match label {
                "本地网络段" => "问题在本地网络（本机、Wi-Fi、路由器或内网设备），建议重启路由器、改用有线或排除内网高流量设备".to_string(),
                "目标侧" => "瓶颈靠近目标服务器一侧，可能是对方服务繁忙或其入口带宽不足，本地链路基本正常".to_string(),
                _ => "问题在运营商网络内，本地链路正常，建议向运营商报修并附上本报告".to_string(),
            };
            RouteVerdict::Bottleneck {
                msg: desc,
                suggestion,
            }
        }
        None => RouteVerdict::Clean(format!(
            "到目标的 {} 跳链路未见明显丢包或时延突增，全程平均时延 {:.0}ms",
            total,
            hops.last().map(|h| h.avg_ms).unwrap_or(0.0)
        )),
    }
}
