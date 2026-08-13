//! 链路检测模块：ping 统计与逐跳路由探测（traceroute）。
//!
//! 逐跳探测原理：发送 TTL 从 1 递增的 ICMP 回显请求，路径上第 N 跳路由器
//! 在 TTL 耗尽时按 RFC 792 回送 "Time Exceeded" 报文，由此暴露每一跳节点。
//! 对每一跳发送多个探测包，统计丢包率与时延，用于定位瓶颈。

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::icmp::{Pinger, IP_SUCCESS};

pub const PAYLOAD: &[u8] = b"zhuge-netdiag";

/// 一组 ping 探测的统计结果。
#[derive(Clone, Debug, Default)]
pub struct PingStats {
    pub sent: u32,
    pub received: u32,
    pub min_ms: u32,
    pub max_ms: u32,
    pub avg_ms: f64,
}

impl PingStats {
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.received) as f64 / self.sent as f64 * 100.0
        }
    }
}

pub fn fmt_stats(s: &PingStats) -> String {
    if s.received == 0 {
        format!("收到 0/{} 个应答，丢包 100%", s.sent)
    } else {
        format!(
            "收到 {}/{} 个应答，丢包 {:.1}%，平均 {:.1}ms（最小 {} / 最大 {}ms）",
            s.received,
            s.sent,
            s.loss_pct(),
            s.avg_ms,
            s.min_ms,
            s.max_ms
        )
    }
}

fn stats_from(rtts: &[u32], sent: u32) -> PingStats {
    if rtts.is_empty() {
        return PingStats {
            sent,
            received: 0,
            ..Default::default()
        };
    }
    let min = *rtts.iter().min().unwrap();
    let max = *rtts.iter().max().unwrap();
    let avg = rtts.iter().map(|r| *r as f64).sum::<f64>() / rtts.len() as f64;
    PingStats {
        sent,
        received: rtts.len() as u32,
        min_ms: min,
        max_ms: max,
        avg_ms: avg,
    }
}

/// 对目标做 `count` 次完整 TTL 的 ping 统计。
pub fn ping_stats(addr: Ipv4Addr, count: u32, timeout_ms: u32) -> std::io::Result<PingStats> {
    let pinger = Pinger::new()?;
    let mut rtts = Vec::new();
    for _ in 0..count {
        if let Ok(r) = pinger.ping(addr, 255, timeout_ms, PAYLOAD) {
            if r.status == IP_SUCCESS {
                rtts.push(r.rtt_ms);
            }
        }
    }
    Ok(stats_from(&rtts, count))
}

/// 单跳的统计结果。
#[derive(Clone, Debug)]
pub struct HopStat {
    pub ttl: u8,
    /// 该跳主要应答地址（ECMP 多路径时取出现最多的）
    pub responder: Option<Ipv4Addr>,
    /// 所有出现过的应答地址
    #[allow(dead_code)]
    pub responders: Vec<Ipv4Addr>,
    pub sent: u32,
    pub received: u32,
    pub min_ms: u32,
    pub max_ms: u32,
    pub avg_ms: f64,
    /// 该 TTL 下到达最终目标的次数（>0 表示此处即路径终点）
    pub reached_dest: u32,
}

impl HopStat {
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.received) as f64 / self.sent as f64 * 100.0
        }
    }
}

/// 对目标执行逐跳探测：TTL 从 1 递增到 max_hops，每跳探测 count 次。
///
/// 串行逐跳探测（与系统 tracert 一致），避免并发 ICMP 操作带来的兼容性问题；
/// 一旦某跳到达目标即提前结束。
pub fn traceroute(target: Ipv4Addr, count: u32, timeout_ms: u32, max_hops: u8) -> Vec<HopStat> {
    let mut hops: Vec<HopStat> = Vec::new();
    for ttl in 1..=max_hops {
        if let Some(stat) = probe_hop(target, ttl, count, timeout_ms) {
            let reached = stat.reached_dest > 0;
            hops.push(stat);
            if reached {
                break;
            }
        }
    }
    hops
}

fn probe_hop(target: Ipv4Addr, ttl: u8, count: u32, timeout_ms: u32) -> Option<HopStat> {
    let pinger = Pinger::new().ok()?;
    let mut votes: HashMap<Ipv4Addr, u32> = HashMap::new();
    let mut rtts: Vec<u32> = Vec::new();
    let mut received = 0u32;
    let mut reached = 0u32;
    for _ in 0..count {
        if let Ok(r) = pinger.ping(target, ttl, timeout_ms, PAYLOAD) {
            let for_hop = r.is_hop_reply();
            let for_dest = r.status == IP_SUCCESS;
            if for_hop || for_dest {
                received += 1;
                if for_dest {
                    reached += 1;
                }
                *votes.entry(r.responder).or_insert(0) += 1;
                rtts.push(r.rtt_ms);
            }
        }
    }
    let responder = votes.iter().max_by_key(|(_, v)| **v).map(|(k, _)| *k);
    let mut responders: Vec<Ipv4Addr> = votes.keys().copied().collect();
    responders.sort();
    let stats = stats_from(&rtts, count);
    Some(HopStat {
        ttl,
        responder,
        responders,
        sent: count,
        received,
        min_ms: stats.min_ms,
        max_ms: stats.max_ms,
        avg_ms: stats.avg_ms,
        reached_dest: reached,
    })
}

/// 打印逐跳链路表。
pub fn print_table(hops: &[HopStat]) {
    println!(
        "    {:<4} {:<17} {:<8} {:<7} {}",
        "跳数", "节点地址", "应答/发出", "丢包率", "时延 平均/最小/最大 (ms)"
    );
    for (i, h) in hops.iter().enumerate() {
        let addr = h
            .responder
            .map(|a| a.to_string())
            .unwrap_or_else(|| "*".to_string());
        let delay = if h.received == 0 {
            "-".to_string()
        } else {
            format!("{:.1} / {} / {}", h.avg_ms, h.min_ms, h.max_ms)
        };
        let silent_ok = h.received == 0
            && hops[i + 1..].iter().any(|x| x.received > 0);
        let note = if h.reached_dest > 0 {
            "  <- 目标"
        } else if silent_ok {
            "  (不回应 ICMP，但其后节点可达)"
        } else {
            ""
        };
        println!(
            "    {:<4} {:<17} {:<8} {:<7} {}{}",
            h.ttl,
            addr,
            format!("{}/{}", h.received, h.sent),
            format!("{:.0}%", h.loss_pct()),
            delay,
            note
        );
    }
}
