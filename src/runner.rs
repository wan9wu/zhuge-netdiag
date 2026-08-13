//! 诊断执行器：按 7 个步骤完成完整诊断，通过事件回调报告进度，返回完整会话数据。
//!
//! 命令行版与图形界面版共用本模块，保证两个版本功能完全一致。

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::diagnose::Inputs;
use crate::http::HttpResult;
use crate::trace::PingStats;
use crate::{dns, env, http, quality, report, trace};

pub const DEFAULT_TARGET: &str = "223.5.5.5";
pub const DNS_TEST_DOMAIN: &str = "www.baidu.com";
pub const TOTAL_STEPS: u8 = 7;

/// 用于验证公网可达性的公共节点（IP 直连，排除 DNS 因素）
pub const PUBLIC_CHECKS: [(Ipv4Addr, &str); 3] = [
    (Ipv4Addr::new(223, 5, 5, 5), "阿里 DNS"),
    (Ipv4Addr::new(119, 29, 29, 29), "DNSPod"),
    (Ipv4Addr::new(8, 8, 8, 8), "Google DNS"),
];

/// 一次诊断的运行参数。
#[derive(Clone, Debug)]
pub struct RunOpts {
    /// 诊断目标（IPv4 或域名）
    pub target: String,
    /// 每跳探测次数
    pub count: u32,
    /// 单次探测超时（毫秒）
    pub timeout_ms: u32,
    /// 最大跳数
    pub max_hops: u8,
    /// TCP 质量采样次数（可加大以捕捉间歇性丢包）
    pub quality_count: u32,
}

impl Default for RunOpts {
    fn default() -> Self {
        Self {
            target: DEFAULT_TARGET.into(),
            count: 8,
            timeout_ms: 1500,
            max_hops: 30,
            quality_count: 20,
        }
    }
}

/// 诊断过程中的进度事件。
#[derive(Clone, Debug)]
pub enum Event {
    Step { n: u8, total: u8, title: String },
    Log(String),
}

fn emit_step(out: &mut dyn FnMut(Event), n: u8, title: &str) {
    out(Event::Step {
        n,
        total: TOTAL_STEPS,
        title: title.to_string(),
    });
}

fn emit_log(out: &mut dyn FnMut(Event), msg: impl Into<String>) {
    out(Event::Log(msg.into()));
}

fn resolve_first_v4(domain: &str) -> Option<Ipv4Addr> {
    (domain, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|sa| match sa {
            SocketAddr::V4(v) => Some(*v.ip()),
            _ => None,
        })
}

/// 执行完整诊断流程，返回包含全部原始数据与诊断结论的会话。
pub fn run_diagnosis(opts: &RunOpts, out: &mut dyn FnMut(Event)) -> report::Session {
    let mut s = report::Session {
        time: report::timestamp(),
        target_input: opts.target.clone(),
        count: opts.count,
        timeout_ms: opts.timeout_ms,
        quality_count: opts.quality_count,
        dns_domain: DNS_TEST_DOMAIN.into(),
        ..Default::default()
    };

    // 解析目标
    let target: Ipv4Addr = match opts.target.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => {
            emit_log(out, format!("目标 \"{}\" 是域名，尝试解析 ...", opts.target));
            match resolve_first_v4(&opts.target) {
                Some(ip) => {
                    emit_log(out, format!("解析成功: {}", ip));
                    ip
                }
                None => {
                    emit_log(out, "警告: 无法解析目标域名，这本身说明 DNS 可能存在问题");
                    emit_log(out, format!("改用默认目标 {} 继续诊断", DEFAULT_TARGET));
                    DEFAULT_TARGET.parse().unwrap()
                }
            }
        }
    };
    s.target = target;

    // ---------- [1/7] 本地网络环境 ----------
    emit_step(out, 1, "检测本地网络环境");
    s.adapters = env::enumerate();
    if s.adapters.is_empty() {
        emit_log(out, "警告: 未读取到任何网络适配器");
    }
    for a in &s.adapters {
        let ip = a
            .ipv4
            .map(|(ip, p)| format!("{}/{}", ip, p))
            .unwrap_or_else(|| "无 IPv4".into());
        emit_log(
            out,
            format!(
                "- {} \"{}\"：{}，IPv4 {}，网关 {}，状态 {}",
                a.kind,
                a.friendly_name(),
                a.description,
                ip,
                a.gateways
                    .iter()
                    .map(|g| g.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                if a.up { "已连接" } else { "未连接" }
            ),
        );
    }
    s.primary = env::pick_primary(&s.adapters).cloned();
    match &s.primary {
        Some(a) => emit_log(out, format!("主用适配器: \"{}\"（{}）", a.friendly_name(), a.kind)),
        None => emit_log(out, "警告: 未找到可用的主用网络适配器"),
    }

    // ---------- [2/7] 网关连通性 ----------
    emit_step(out, 2, "检查网关连通性");
    s.gateway_addr = s.primary.as_ref().and_then(|a| a.gateways.first().copied());
    if let Some(gw) = s.gateway_addr {
        emit_log(out, format!("向网关 {} 发送 {} 个 ICMP 探测 ...", gw, opts.count));
        match trace::ping_stats(gw, opts.count, opts.timeout_ms) {
            Ok(st) => {
                emit_log(out, trace::fmt_stats(&st));
                s.gateway = Some(st);
            }
            Err(e) => emit_log(out, format!("无法初始化 ICMP 检测: {}", e)),
        }
        // ARP 链路层交叉验证：很多路由器禁用 ICMP ping 应答，
        // 此时 ping 全部丢失但网络实际可用，需靠 ARP 防止误报
        let (arp_ok, arp_mac) = crate::arp::probe(gw);
        s.gateway_arp = Some(arp_ok);
        if let Some(mac) = &arp_mac {
            emit_log(out, format!("ARP 检测网关 {}: 链路层可达（MAC {}）", gw, mac));
        } else if s.gateway.as_ref().map(|g| g.received == 0).unwrap_or(true) {
            emit_log(out, format!("ARP 检测网关 {}: 同样无应答", gw));
        }
        // 网关段 TCP 采样测质：ICMP 全丢时改测 TCP 握手，得到本地段丢包/时延
        if s.gateway.as_ref().map(|g| g.received == 0).unwrap_or(false) {
            let qc = opts.quality_count;
            emit_log(out, format!("TCP 采样测量网关段质量（{} 次采样）...", qc));
            let q = quality::tcp_quality(
                SocketAddr::from((gw, 9)),
                qc,
                Duration::from_millis(1200),
                200,
                |done, _| {
                    if done % 10 == 0 || done == qc {
                        emit_log(out, format!("网关段 TCP 采样进度 {}/{}", done, qc));
                    }
                },
            );
            emit_log(out, format!("网关段 TCP 采样: {}", quality::fmt_quality(&q)));
            s.gateway_quality = Some(q);
        }
    } else {
        emit_log(out, "未发现默认网关，跳过");
    }

    // ---------- [3/7] 公网可达性 ----------
    emit_step(out, 3, "检查公网连通性（IP 直连，排除 DNS 因素）");
    for (ip, name) in PUBLIC_CHECKS {
        match trace::ping_stats(ip, 4, opts.timeout_ms) {
            Ok(st) => {
                emit_log(out, format!("{} ({}): {}", ip, name, trace::fmt_stats(&st)));
                s.publics.push((ip, name, st));
            }
            Err(e) => emit_log(out, format!("{} ({}): 探测失败: {}", ip, name, e)),
        }
    }
    // 目标自身的统计
    let mut target_stats: Option<PingStats> = None;
    if let Some((_, _, st)) = s.publics.iter().find(|(ip, _, _)| *ip == target) {
        target_stats = Some(st.clone());
    } else {
        match trace::ping_stats(target, opts.count, opts.timeout_ms) {
            Ok(st) => {
                emit_log(out, format!("目标 {}: {}", target, trace::fmt_stats(&st)));
                target_stats = Some(st);
            }
            Err(e) => emit_log(out, format!("目标 {}: 探测失败: {}", target, e)),
        }
    }
    s.target_stats = target_stats;

    // TCP 交叉验证 + 分段采样测质：ICMP 可能被路由器/运营商整体屏蔽（ping 全丢但上网正常）。
    // 对 ICMP 失败的公共节点用重复 TCP 连接采样丢包率与时延
    for (ip, _, st) in &s.publics {
        if st.received > 0 {
            continue;
        }
        let q = quality::tcp_quality(
            SocketAddr::from((*ip, 53)),
            4,
            Duration::from_millis(1200),
            150,
            |_, _| {},
        );
        emit_log(
            out,
            format!(
                "TCP 采样 {} :53: {}",
                ip,
                if q.succeeded > 0 {
                    format!("可达，{}", quality::fmt_quality(&q))
                } else {
                    "连接失败".to_string()
                }
            ),
        );
        s.publics_quality.push((*ip, q));
    }
    // 端到端 TCP 采样测质：无论 ICMP 是否可用都测，反映真实上网路径的质量
    let qc = opts.quality_count;
    emit_log(out, format!("TCP 采样测量到目标 {} 的端到端质量（{} 次采样）...", target, qc));
    let q = quality::tcp_quality(
        SocketAddr::from((target, 80)),
        qc,
        Duration::from_millis(1500),
        200,
        |done, _| {
            if done % 10 == 0 || done == qc {
                emit_log(out, format!("端到端 TCP 采样进度 {}/{}", done, qc));
            }
        },
    );
    emit_log(out, format!("端到端 TCP 采样: {}", quality::fmt_quality(&q)));
    s.target_quality = Some(q);

    // ---------- [4/7] DNS 解析 ----------
    emit_step(out, 4, "检查 DNS 解析");
    let mut servers: Vec<(Ipv4Addr, String)> = Vec::new();
    if let Some(a) = &s.primary {
        for d in &a.dns_servers {
            servers.push((*d, format!("系统 DNS - {}", a.friendly_name())));
        }
    }
    servers.push((Ipv4Addr::new(223, 5, 5, 5), "阿里 DNS".into()));
    servers.push((Ipv4Addr::new(8, 8, 8, 8), "Google DNS".into()));
    servers.dedup_by(|a, b| a.0 == b.0);
    for (srv, label) in &servers {
        let r = dns::query(*srv, DNS_TEST_DOMAIN, label, Duration::from_secs(3));
        if r.success {
            emit_log(
                out,
                format!(
                    "{} ({}) 解析 {}: 成功（{}ms）-> {}",
                    srv,
                    label,
                    DNS_TEST_DOMAIN,
                    r.elapsed_ms,
                    r.answers
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        } else {
            emit_log(
                out,
                format!(
                    "{} ({}) 解析 {}: 失败（{}）",
                    srv,
                    label,
                    DNS_TEST_DOMAIN,
                    r.error.as_deref().unwrap_or("未知错误")
                ),
            );
        }
        s.dns.push(r);
    }
    match dns::resolve_system(DNS_TEST_DOMAIN, Duration::from_secs(5)) {
        Ok(v) => {
            emit_log(
                out,
                format!(
                    "系统解析器解析 {}: 成功 -> {}",
                    DNS_TEST_DOMAIN,
                    v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
                ),
            );
            s.system_dns = Some(v);
        }
        Err(e) => emit_log(out, format!("系统解析器解析 {}: 失败（{}）", DNS_TEST_DOMAIN, e)),
    }

    // ---------- [5/7] 逐跳链路 ----------
    emit_step(
        out,
        5,
        &format!("逐跳链路探测（目标 {}，每跳 {} 次探测）", target, opts.count),
    );
    s.hops = trace::traceroute(target, opts.count, opts.timeout_ms, opts.max_hops);
    if s.hops.is_empty() {
        emit_log(out, "未获得任何链路数据");
    } else {
        emit_log(out, "跳数  节点地址            应答/发出  丢包率   时延 平均/最小/最大 (ms)");
        for (i, h) in s.hops.iter().enumerate() {
            let addr = h
                .responder
                .map(|a| a.to_string())
                .unwrap_or_else(|| "*".to_string());
            let delay = if h.received == 0 {
                "-".to_string()
            } else {
                format!("{:.1} / {} / {}", h.avg_ms, h.min_ms, h.max_ms)
            };
            let silent_ok = h.received == 0 && s.hops[i + 1..].iter().any(|x| x.received > 0);
            let note = if h.reached_dest > 0 {
                "  <- 目标"
            } else if silent_ok {
                "  (不回应 ICMP，但其后节点可达)"
            } else {
                ""
            };
            emit_log(
                out,
                format!(
                    "{:<4}  {:<16}  {}/{}  {:.0}%  {}{}",
                    h.ttl,
                    addr,
                    h.received,
                    h.sent,
                    h.loss_pct(),
                    delay,
                    note
                ),
            );
        }
    }

    // ---------- [6/7] HTTP 应用层 ----------
    emit_step(out, 6, "检查应用层 HTTP 连通性");
    let mut endpoints: Vec<(String, String, String)> = http::HTTP_CHECKS
        .iter()
        .map(|(h, p, e)| (h.to_string(), p.to_string(), e.to_string()))
        .collect();
    // 目标是域名时直接验证它的可访问性（最贴合用户实际感知，国内环境最可靠）
    if opts.target.parse::<Ipv4Addr>().is_err() {
        endpoints.push((opts.target.clone(), "/".into(), String::new()));
    }
    let mut picked: Option<HttpResult> = None;
    let mut first_fail: Option<HttpResult> = None;
    for (host, path, expect) in &endpoints {
        emit_log(out, format!("访问 http://{}{} ...", host, path));
        let hr = http::http_check(host, path, expect, Duration::from_secs(8));
        match hr.status_code {
            Some(c) => emit_log(out, format!("HTTP {}，耗时 {}ms", c, hr.elapsed_ms)),
            None => emit_log(out, format!("失败：{}", hr.note)),
        }
        if !hr.note.is_empty() && hr.status_code.is_some() {
            emit_log(out, format!("备注：{}", hr.note));
        }
        if hr.ok() {
            picked = Some(hr);
            break; // 任一端点成功即应用层可用
        }
        if first_fail.is_none() {
            first_fail = Some(hr);
        }
    }
    s.http = picked.or(first_fail);

    // ---------- [7/7] 综合诊断 ----------
    emit_step(out, 7, "综合分析，定位瓶颈");
    let inputs = Inputs {
        adapter: s.primary.as_ref(),
        adapters: &s.adapters,
        gateway_addr: s.gateway_addr,
        gateway: s.gateway.as_ref(),
        gateway_arp: s.gateway_arp,
        publics: &s.publics,
        publics_quality: &s.publics_quality,
        gateway_quality: s.gateway_quality.as_ref(),
        target_quality: s.target_quality.as_ref(),
        target: s.target,
        target_stats: s.target_stats.as_ref(),
        dns: &s.dns,
        dns_domain: &s.dns_domain,
        system_dns: &s.system_dns,
        hops: &s.hops,
        http: s.http.as_ref(),
    };
    s.diagnosis = Some(crate::diagnose::run(&inputs));
    s
}
