//! 诊断报告生成：汇总本次诊断的全部数据，渲染为文本报告（控制台输出 + 保存文件）。

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::diagnose::Diagnosis;
use crate::dns::DnsQueryResult;
use crate::env::AdapterInfo;
use crate::http::HttpResult;
use crate::quality::QualityStats;
use crate::trace::{fmt_stats, HopStat, PingStats};

/// 一次诊断会话的全部原始数据。
pub struct Session {
    pub time: String,
    pub target: Ipv4Addr,
    pub target_input: String,
    pub count: u32,
    pub timeout_ms: u32,
    pub quality_count: u32,
    pub adapters: Vec<AdapterInfo>,
    pub primary: Option<AdapterInfo>,
    pub gateway_addr: Option<Ipv4Addr>,
    pub gateway: Option<PingStats>,
    /// ARP 链路层交叉验证结果（防路由器禁用 ping 导致误报）
    pub gateway_arp: Option<bool>,
    pub publics: Vec<(Ipv4Addr, &'static str, PingStats)>,
    /// ICMP 失败的公共节点的 TCP 采样质量
    pub publics_quality: Vec<(Ipv4Addr, QualityStats)>,
    /// 网关段 TCP 采样质量（ICMP 全丢时测得）
    pub gateway_quality: Option<QualityStats>,
    /// 端到端 TCP 采样质量
    pub target_quality: Option<QualityStats>,
    pub target_stats: Option<PingStats>,
    pub dns: Vec<DnsQueryResult>,
    pub dns_domain: String,
    pub system_dns: Option<Vec<Ipv4Addr>>,
    pub hops: Vec<HopStat>,
    pub http: Option<HttpResult>,
    pub diagnosis: Option<Diagnosis>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            time: String::new(),
            target: Ipv4Addr::UNSPECIFIED,
            target_input: String::new(),
            count: 0,
            timeout_ms: 0,
            quality_count: 0,
            adapters: Vec::new(),
            primary: None,
            gateway_addr: None,
            gateway: None,
            gateway_arp: None,
            publics: Vec::new(),
            publics_quality: Vec::new(),
            gateway_quality: None,
            target_quality: None,
            target_stats: None,
            dns: Vec::new(),
            dns_domain: String::new(),
            system_dns: None,
            hops: Vec::new(),
            http: None,
            diagnosis: None,
        }
    }
}

/// 控制台打印诊断结论区。
pub fn print_conclusion(s: &Session) {
    let Some(d) = &s.diagnosis else { return };
    println!();
    println!("==============================================================");
    println!("                         诊断结论");
    println!("==============================================================");
    for f in &d.findings {
        println!("  {} {}：{}", f.level.tag(), f.segment, f.detail);
        if let Some(sug) = &f.suggestion {
            println!("         建议：{}", sug);
        }
    }
    println!("--------------------------------------------------------------");
    println!("  >> {}", d.conclusion);
    println!("==============================================================");
}

/// 渲染完整文本报告。
pub fn render(s: &Session) -> String {
    let mut t = String::new();
    let _ = writeln!(t, "# 诸葛网络问题诊断报告");
    let _ = writeln!(t);
    let _ = writeln!(t, "- 诊断时间：{}", s.time);
    let _ = writeln!(t, "- 诊断目标：{}（{}）", s.target, s.target_input);
    let _ = writeln!(t, "- 参数：每跳探测 {} 次，单次超时 {}ms，质量采样 {} 次", s.count, s.timeout_ms, s.quality_count);
    let _ = writeln!(t);

    // 1. 本地环境
    let _ = writeln!(t, "## 1. 本地网络环境");
    if s.adapters.is_empty() {
        let _ = writeln!(t, "- 未读取到任何网络适配器");
    }
    for a in &s.adapters {
        let ip = a
            .ipv4
            .map(|(ip, p)| format!("{}/{}", ip, p))
            .unwrap_or_else(|| "无 IPv4".into());
        let gw = if a.gateways.is_empty() {
            "无".to_string()
        } else {
            a.gateways
                .iter()
                .map(|g| g.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let dns = if a.dns_servers.is_empty() {
            "无".to_string()
        } else {
            a.dns_servers
                .iter()
                .map(|g| g.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mark = if s.primary.as_ref().map(|p| p.name.as_str()) == Some(a.name.as_str()) {
            "（主用）"
        } else {
            ""
        };
        let _ = writeln!(
            t,
            "- {} \"{}\"{}：状态={}，IPv4={}，网关={}，DNS={}",
            a.kind,
            a.friendly_name(),
            mark,
            if a.up { "已连接" } else { "未连接" },
            ip,
            gw,
            dns
        );
        if !a.description.is_empty() {
            let _ = writeln!(t, "  - 设备：{}", a.description);
        }
    }
    let _ = writeln!(t);

    // 2. 网关
    let _ = writeln!(t, "## 2. 网关连通性");
    match (s.gateway_addr, &s.gateway) {
        (Some(gw), Some(st)) => {
            let _ = writeln!(t, "- 网关 {}：{}", gw, fmt_stats(st));
            if st.received == 0 {
                match s.gateway_arp {
                    Some(true) => {
                        let _ = writeln!(t, "  - ARP 交叉验证：网关在链路层可达（路由器可能禁用了 ICMP ping 应答，不影响上网）");
                    }
                    Some(false) => {
                        let _ = writeln!(t, "  - ARP 交叉验证：网关同样无应答");
                    }
                    None => {}
                }
                if let Some(q) = &s.gateway_quality {
                    let _ = writeln!(t, "  - 网关段 TCP 采样：{}", crate::quality::fmt_quality(q));
                }
            }
        }
        (Some(gw), None) => {
            let _ = writeln!(t, "- 网关 {}：未能探测", gw);
        }
        (None, _) => {
            let _ = writeln!(t, "- 未发现默认网关");
        }
    }
    let _ = writeln!(t);

    // 3. 公网可达性
    let _ = writeln!(t, "## 3. 公网可达性");
    for (ip, name, st) in &s.publics {
        if st.received == 0 {
            let q = s
                .publics_quality
                .iter()
                .find(|(i, _)| i == ip)
                .map(|(_, q)| {
                    if q.succeeded > 0 {
                        format!("（TCP 采样：{}）", crate::quality::fmt_quality(q))
                    } else {
                        "（TCP 采样：不可达）".to_string()
                    }
                })
                .unwrap_or_default();
            let _ = writeln!(t, "- {}（{}）：{}{}", ip, name, fmt_stats(st), q);
        } else {
            let _ = writeln!(t, "- {}（{}）：{}", ip, name, fmt_stats(st));
        }
    }
    if let Some(ts) = &s.target_stats {
        let _ = writeln!(t, "- 目标 {}：{}", s.target, fmt_stats(ts));
    }
    if let Some(q) = &s.target_quality {
        let _ = writeln!(t, "- 端到端 TCP 采样（目标 {} :80）：{}", s.target, crate::quality::fmt_quality(q));
    }
    let _ = writeln!(t);

    // 4. DNS
    let _ = writeln!(t, "## 4. DNS 解析（域名 {}）", s.dns_domain);
    match &s.system_dns {
        Some(v) => {
            let _ = writeln!(t, "- 系统解析器：成功 -> {}", v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
        }
        None => {
            let _ = writeln!(t, "- 系统解析器：失败");
        }
    }
    for r in &s.dns {
        if r.success {
            let _ = writeln!(
                t,
                "- {}（{}）：成功，{}ms -> {}",
                r.server,
                r.label,
                r.elapsed_ms,
                r.answers.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
            );
        } else {
            let _ = writeln!(
                t,
                "- {}（{}）：失败（{}）",
                r.server,
                r.label,
                r.error.as_deref().unwrap_or("未知错误")
            );
        }
    }
    let _ = writeln!(t);

    // 5. 逐跳链路
    let _ = writeln!(t, "## 5. 逐跳链路探测");
    if s.hops.is_empty() {
        let _ = writeln!(t, "- 无数据");
    } else {
        let _ = writeln!(t, "| 跳数 | 节点地址 | 应答/发出 | 丢包率 | 时延 平均/最小/最大 (ms) |");
        let _ = writeln!(t, "|---|---|---|---|---|");
        for h in &s.hops {
            let addr = h.responder.map(|a| a.to_string()).unwrap_or_else(|| "*".into());
            let delay = if h.received == 0 {
                "-".to_string()
            } else {
                format!("{:.1} / {} / {}", h.avg_ms, h.min_ms, h.max_ms)
            };
            let _ = writeln!(
                t,
                "| {} | {} | {}/{} | {:.0}% | {} |",
                h.ttl,
                addr,
                h.received,
                h.sent,
                h.loss_pct(),
                delay
            );
        }
    }
    let _ = writeln!(t);

    // 6. HTTP
    let _ = writeln!(t, "## 6. 应用层 HTTP 连通性");
    if let Some(h) = &s.http {
        let status = h
            .status_code
            .map(|c| format!("HTTP {}", c))
            .unwrap_or_else(|| "无有效响应".into());
        let _ = writeln!(t, "- {}：{}，耗时 {}ms", h.host, status, h.elapsed_ms);
        if !h.note.is_empty() {
            let _ = writeln!(t, "  - 备注：{}", h.note);
        }
    } else {
        let _ = writeln!(t, "- 未执行");
    }
    let _ = writeln!(t);

    // 7. 结论
    let _ = writeln!(t, "## 7. 诊断结论");
    if let Some(d) = &s.diagnosis {
        for f in &d.findings {
            let _ = writeln!(t, "- {} {}：{}", f.level.tag(), f.segment, f.detail);
            if let Some(sug) = &f.suggestion {
                let _ = writeln!(t, "  - 建议：{}", sug);
            }
        }
        let _ = writeln!(t);
        let _ = writeln!(t, "**{}**", d.conclusion);
    }
    let _ = writeln!(t);
    let _ = writeln!(t, "---");
    let _ = writeln!(
        t,
        "本报告由 诸葛网络问题诊断器 v{} 自动生成（MIT 开源协议）。",
        env!("CARGO_PKG_VERSION")
    );
    t
}

/// 默认报告保存路径：当前目录下 `网络诊断报告_<时间戳>.md`。
pub fn default_report_path() -> String {
    format!("网络诊断报告_{}.md", timestamp())
}

/// 本地时间戳字符串（YYYYMMDD_HHMMSS）。
#[cfg(windows)]
pub fn timestamp() -> String {
    #[repr(C)]
    struct SystemTime {
        w_year: u16,
        w_month: u16,
        w_day_of_week: u16,
        w_day: u16,
        w_hour: u16,
        w_minute: u16,
        w_second: u16,
        w_milliseconds: u16,
    }
    extern "system" {
        fn GetLocalTime(lp: *mut SystemTime);
    }
    let mut st = SystemTime {
        w_year: 0,
        w_month: 0,
        w_day_of_week: 0,
        w_day: 0,
        w_hour: 0,
        w_minute: 0,
        w_second: 0,
        w_milliseconds: 0,
    };
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:04}{:02}{:02}_{:02}{:02}{:02}",
        st.w_year, st.w_month, st.w_day, st.w_hour, st.w_minute, st.w_second
    )
}

#[cfg(not(windows))]
pub fn timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".into())
}
