//! ARP（链路层）可达性检测。
//!
//! 许多家用路由器默认禁用 ICMP ping 应答，此时 ping 网关会全部丢失，
//! 但网络实际是通的。ARP 是局域网通信的必要环节、无法被这类设置关闭，
//! 因此在 ICMP 探测失败时用 SendARP 交叉验证网关是否真正在线，避免误报。
//!
//! SendARP 是 Windows 系统公开文档化的 API（iphlpapi.dll），无需管理员权限。

use std::net::Ipv4Addr;

const NO_ERROR: u32 = 0;

#[link(name = "iphlpapi")]
extern "system" {
    fn SendARP(dest_ip: u32, src_ip: u32, mac_addr: *mut u8, mac_len: *mut u32) -> u32;
}

/// 对指定地址发送 ARP 请求，返回 (是否可达, MAC 地址字符串)。
pub fn probe(ip: Ipv4Addr) -> (bool, Option<String>) {
    let dest = u32::from_ne_bytes(ip.octets());
    let mut mac = [0u8; 8];
    let mut len: u32 = 6;
    let r = unsafe { SendARP(dest, 0, mac.as_mut_ptr(), &mut len) };
    if r == NO_ERROR && len >= 6 {
        let mac_str = mac[..len as usize]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("-");
        (true, Some(mac_str))
    } else {
        (false, None)
    }
}
