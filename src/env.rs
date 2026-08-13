//! 本地网络环境检测：枚举网卡、IPv4 地址、默认网关与 DNS 服务器。

use std::net::{IpAddr, Ipv4Addr};

/// 单个网络适配器的关键信息。
#[derive(Clone, Debug)]
pub struct AdapterInfo {
    /// 系统适配器名称（如 {GUID} 或 \DEVICE\TCPIP_...）
    pub name: String,
    /// 友好名称（如 "以太网"、"WLAN"）
    pub friendly: String,
    /// 设备描述
    pub description: String,
    /// 类型（以太网 / Wi-Fi / ...）
    pub kind: String,
    /// 是否处于连接状态
    pub up: bool,
    /// IPv4 地址与前缀长度
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// 默认网关列表
    pub gateways: Vec<Ipv4Addr>,
    /// DNS 服务器列表
    pub dns_servers: Vec<Ipv4Addr>,
}

impl AdapterInfo {
    pub fn friendly_name(&self) -> &str {
        if self.friendly.is_empty() {
            &self.name
        } else {
            &self.friendly
        }
    }
}

/// 枚举本机所有非环回网络适配器。
pub fn enumerate() -> Vec<AdapterInfo> {
    let adapters = match ipconfig::get_adapters() {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for a in &adapters {
        if matches!(a.if_type(), ipconfig::IfType::SoftwareLoopback) {
            continue;
        }
        let kind = match a.if_type() {
            ipconfig::IfType::EthernetCsmacd => "以太网".to_string(),
            ipconfig::IfType::Ieee80211 => "Wi-Fi".to_string(),
            ipconfig::IfType::Ppp => "PPP 拨号".to_string(),
            ipconfig::IfType::Tunnel => "隧道".to_string(),
            t => format!("{:?}", t),
        };
        // 从 ip_addresses 取主机 IPv4，再从 prefixes 匹配前缀长度
        let ipv4 = a.ip_addresses().iter().find_map(|addr| match *addr {
            IpAddr::V4(v) => {
                let prefix = a
                    .prefixes()
                    .iter()
                    .find(|(p, _)| *p == IpAddr::V4(v))
                    .map(|(_, len)| *len as u8)
                    .unwrap_or(24);
                Some((v, prefix))
            }
            _ => None,
        });
        out.push(AdapterInfo {
            name: a.adapter_name().to_string(),
            friendly: a.friendly_name().to_string(),
            description: a.description().to_string(),
            kind,
            up: matches!(a.oper_status(), ipconfig::OperStatus::IfOperStatusUp),
            ipv4,
            gateways: a
                .gateways()
                .iter()
                .filter_map(|g| match *g {
                    IpAddr::V4(v) => Some(v),
                    _ => None,
                })
                .collect(),
            dns_servers: a
                .dns_servers()
                .iter()
                .filter_map(|d| match *d {
                    IpAddr::V4(v) => Some(v),
                    _ => None,
                })
                .collect(),
        });
    }
    // 已连接且有 IPv4 的适配器排前面
    out.sort_by(|x, y| {
        y.up.cmp(&x.up)
            .then(y.ipv4.is_some().cmp(&x.ipv4.is_some()))
            .then(y.gateways.len().cmp(&x.gateways.len()))
    });
    out
}

/// 挑选主用适配器：已连接、有 IPv4、有默认网关；退而求其次只要有 IPv4。
pub fn pick_primary(adapters: &[AdapterInfo]) -> Option<&AdapterInfo> {
    adapters
        .iter()
        .find(|a| a.up && a.ipv4.is_some() && !a.gateways.is_empty())
        .or_else(|| adapters.iter().find(|a| a.up && a.ipv4.is_some()))
}
