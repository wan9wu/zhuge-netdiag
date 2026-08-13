//! TCP 采样网络质量测量。
//!
//! ICMP 被屏蔽时，基于 ICMP 的丢包/时延统计不可用。本模块通过反复发起
//! TCP 连接采样链路质量：握手耗时（SYN → SYN-ACK 或 RST）即 RTT，
//! 连接超时计为丢包。由此在纯 TCP 环境下也能测出分段丢包率与时延，
//! 用于对比定位瓶颈环节（本地段 / 运营商段 / 目标侧）。

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// TCP 采样质量统计。
#[derive(Clone, Debug, Default)]
pub struct QualityStats {
    pub sent: u32,
    pub succeeded: u32,
    pub min_ms: u64,
    pub max_ms: u64,
    pub avg_ms: f64,
}

impl QualityStats {
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.succeeded) as f64 * 100.0 / self.sent as f64
        }
    }

    fn record(&mut self, elapsed: Duration) {
        let ms = elapsed.as_millis().max(1) as u64;
        if self.succeeded == 1 || ms < self.min_ms {
            self.min_ms = ms;
        }
        if ms > self.max_ms {
            self.max_ms = ms;
        }
        let n = self.succeeded as f64;
        self.avg_ms = self.avg_ms * (n - 1.0) / n + ms as f64 / n;
    }
}

pub fn fmt_quality(s: &QualityStats) -> String {
    if s.succeeded == 0 {
        format!("{} 次采样均无有效样本", s.sent)
    } else {
        format!(
            "采样成功 {}/{}，丢包 {:.0}%，时延 平均 {:.0} / 最小 {} / 最大 {} ms",
            s.succeeded,
            s.sent,
            s.loss_pct(),
            s.avg_ms,
            s.min_ms,
            s.max_ms
        )
    }
}

/// 对指定地址重复发起 TCP 连接采样质量。
///
/// 连接成功或收到 RST（连接被拒绝）都证明主机可达并计入有效样本；
/// 只有超时 / 无响应才计为丢包。每完成一个样本回调 `on_sample(已完成数, 当前统计)`。
pub fn tcp_quality(
    addr: SocketAddr,
    count: u32,
    timeout: Duration,
    interval_ms: u64,
    mut on_sample: impl FnMut(u32, &QualityStats),
) -> QualityStats {
    let mut st = QualityStats::default();
    for i in 0..count {
        let start = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => {
                st.succeeded += 1;
                st.record(start.elapsed());
            }
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                // 收到 RST：端口关闭但主机可达，握手耗时同样是有效 RTT 样本
                st.succeeded += 1;
                st.record(start.elapsed());
            }
            Err(_) => {
                // 超时或被静默丢弃，计为丢包样本
            }
        }
        st.sent += 1;
        on_sample(st.sent, &st);
        if i + 1 < count {
            std::thread::sleep(Duration::from_millis(interval_ms));
        }
    }
    st
}
