//! ICMP 检测模块。
//!
//! 基于 Windows 系统自带的 ICMP API（icmp.dll 的 IcmpSendEcho，微软公开文档化的接口）
//! 实现 ping 与 TTL 受限探测。ICMP（RFC 792）是互联网的公开基础协议，
//! 该方式无需原始套接字、无需管理员权限，普通用户即可运行。
#![allow(dead_code)]

use std::ffi::c_void;
use std::io;
use std::net::Ipv4Addr;

type Handle = isize;
const INVALID_HANDLE_VALUE: Handle = -1;
const WAIT_TIMEOUT: u32 = 0x0000_0102;
const WAIT_OBJECT_0: u32 = 0;

// ---- ICMP 状态码（来自 winsock 头文件 icmpapi 定义） ----
pub const IP_SUCCESS: u32 = 0;
pub const IP_DEST_NET_UNREACHABLE: u32 = 11002;
pub const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
pub const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
pub const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
pub const IP_PACKET_TOO_BIG: u32 = 11009;
pub const IP_REQ_TIMED_OUT: u32 = 11010;
pub const IP_BAD_ROUTE: u32 = 11012;
pub const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
pub const IP_TTL_EXPIRED_REASSEM: u32 = 11014;

pub fn status_desc(status: u32) -> &'static str {
    match status {
        IP_SUCCESS => "到达目标",
        IP_DEST_NET_UNREACHABLE => "目标网络不可达",
        IP_DEST_HOST_UNREACHABLE => "目标主机不可达",
        IP_DEST_PROT_UNREACHABLE => "协议不可达",
        IP_DEST_PORT_UNREACHABLE => "端口不可达",
        IP_PACKET_TOO_BIG => "报文过大需要分片",
        IP_REQ_TIMED_OUT => "请求超时",
        IP_BAD_ROUTE => "路由错误",
        IP_TTL_EXPIRED_TRANSIT => "TTL 在传输中过期（中间节点应答）",
        IP_TTL_EXPIRED_REASSEM => "TTL 在重组中过期",
        _ => "其它 ICMP 状态",
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IpOptionInformation {
    ttl: u8,
    tos: u8,
    flags: u8,
    options_size: u8,
    options_data: *mut u8,
}

#[repr(C)]
struct IcmpEchoReply {
    status: u32,
    address: u32,
    round_trip_time: u32,
    data_size: u16,
    reserved: u16,
    data: *mut c_void,
    options: IpOptionInformation,
}

#[link(name = "icmp")]
extern "system" {
    fn IcmpCreateFile() -> Handle;
    fn IcmpCloseHandle(handle: Handle) -> i32;
    fn IcmpSendEcho2(
        handle: Handle,
        event: Handle,
        apc_routine: *const c_void,
        apc_context: *const c_void,
        destination: u32,
        request_data: *const c_void,
        request_size: u16,
        request_options: *const IpOptionInformation,
        reply_buffer: *mut u8,
        reply_size: u32,
        timeout: u32,
    ) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateEventW(
        attrs: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> Handle;
    fn ResetEvent(handle: Handle) -> i32;
    fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
}

/// 一次探测的应答。
#[derive(Clone, Copy, Debug)]
pub struct Reply {
    /// ICMP 状态码（IP_* 常量）
    pub status: u32,
    /// 应答方地址（可能是目标本身，也可能是 TTL 过期的中间路由器）
    pub responder: Ipv4Addr,
    /// 往返时延（毫秒）。系统 API 精度为 1ms。
    pub rtt_ms: u32,
    /// 是否超时无应答
    pub timed_out: bool,
}

impl Reply {
    fn timeout() -> Self {
        Self {
            status: IP_REQ_TIMED_OUT,
            responder: Ipv4Addr::UNSPECIFIED,
            rtt_ms: 0,
            timed_out: true,
        }
    }

    /// 该应答是否来自指定 TTL 对应的中间节点（TTL 过期报文）
    pub fn is_hop_reply(&self) -> bool {
        self.status == IP_TTL_EXPIRED_TRANSIT || self.status == IP_TTL_EXPIRED_REASSEM
    }
}

/// ICMP 探测器。每个实例持有一个 icmp.dll 句柄；跨线程使用时请每线程创建独立实例。
pub struct Pinger {
    handle: Handle,
    event: Handle,
}

impl Pinger {
    pub fn new() -> io::Result<Self> {
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // 手动复位事件，用于 IcmpSendEcho2 异步等待
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event == 0 {
            unsafe { IcmpCloseHandle(handle) };
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle, event })
    }

    /// 发送一次 ICMP 回显请求。
    ///
    /// - `dst`: 目标地址
    /// - `ttl`: IP 生存时间（逐跳探测时逐次 +1；普通 ping 用 255）
    /// - `timeout_ms`: 等待应答的超时时间
    pub fn ping(&self, dst: Ipv4Addr, ttl: u8, timeout_ms: u32, payload: &[u8]) -> io::Result<Reply> {
        let options = IpOptionInformation {
            ttl,
            tos: 0,
            flags: 0,
            options_size: 0,
            options_data: std::ptr::null_mut(),
        };
        // 应答缓冲区至少需要 sizeof(ICMP_ECHO_REPLY) + 8 字节
        let mut buf = vec![0u8; std::mem::size_of::<IcmpEchoReply>() + payload.len() + 8];
        let dest = u32::from_ne_bytes(dst.octets());
        // 手动复位事件必须在发送前清零，否则上一次的信号会导致等待立即返回
        unsafe { ResetEvent(self.event) };
        let count = unsafe {
            IcmpSendEcho2(
                self.handle,
                self.event,
                std::ptr::null(),
                std::ptr::null(),
                dest,
                payload.as_ptr() as *const c_void,
                payload.len() as u16,
                &options,
                buf.as_mut_ptr(),
                buf.len() as u32,
                timeout_ms,
            )
        };
        if count == 0 {
            let err = unsafe { GetLastError() } as i32;
            if std::env::var_os("ZHUGE_DEBUG").is_some() {
                eprintln!("[debug] dst={} ttl={} count=0 err={}", dst, ttl, err);
            }
            if err == 997 {
                // ERROR_IO_PENDING：等待事件或超时
                let wait = unsafe { WaitForSingleObject(self.event, timeout_ms) };
                if wait != WAIT_OBJECT_0 {
                    return Ok(Reply::timeout());
                }
                self.read_reply(&buf)
            } else {
                // ERROR_IO_TIMEOUT(1460) 或其它错误：无有效应答
                Ok(Reply::timeout())
            }
        } else {
            self.read_reply(&buf)
        }
    }

    /// 从应答缓冲区解析第一条 ICMP_ECHO_REPLY。
    fn read_reply(&self, buf: &[u8]) -> io::Result<Reply> {
        if buf.len() < std::mem::size_of::<IcmpEchoReply>() {
            return Ok(Reply::timeout());
        }
        let reply = unsafe { &*(buf.as_ptr() as *const IcmpEchoReply) };
        let b = reply.address.to_ne_bytes();
        Ok(Reply {
            status: reply.status,
            responder: Ipv4Addr::new(b[0], b[1], b[2], b[3]),
            rtt_ms: reply.round_trip_time,
            timed_out: false,
        })
    }
}

impl Drop for Pinger {
    fn drop(&mut self) {
        unsafe {
            IcmpCloseHandle(self.handle);
            CloseHandle(self.event);
        }
    }
}
