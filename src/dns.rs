//! DNS 解析检测模块。
//!
//! 直接按 DNS 协议（RFC 1035）通过 UDP 53 端口向指定 DNS 服务器发送 A 记录查询，
//! 用于判断"是 DNS 服务器的问题还是网络链路的问题"；同时提供系统解析器测试。

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// 一次 DNS 查询的结果。
#[derive(Clone, Debug)]
pub struct DnsQueryResult {
    pub server: Ipv4Addr,
    #[allow(dead_code)]
    pub domain: String,
    pub label: String,
    pub success: bool,
    pub answers: Vec<Ipv4Addr>,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

/// 向指定 DNS 服务器发送 A 记录查询。
pub fn query(server: Ipv4Addr, domain: &str, label: &str, timeout: Duration) -> DnsQueryResult {
    let start = Instant::now();
    let mut r = DnsQueryResult {
        server,
        domain: domain.to_string(),
        label: label.to_string(),
        success: false,
        answers: Vec::new(),
        elapsed_ms: 0,
        error: None,
    };

    let id: u16 = 0x5A5A;
    let packet = build_query(id, domain);

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            r.error = Some(format!("无法创建 UDP 套接字: {}", e));
            return r;
        }
    };
    let _ = socket.set_read_timeout(Some(timeout));
    let _ = socket.set_write_timeout(Some(timeout));

    if let Err(e) = socket.send_to(&packet, (server, 53)) {
        r.error = Some(format!("发送查询失败: {}", e));
        return r;
    }

    let mut buf = [0u8; 1024];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => match parse_response(&buf[..n], id) {
            Ok(answers) if !answers.is_empty() => {
                r.success = true;
                r.answers = answers;
            }
            Ok(_) => r.error = Some("服务器应答中没有 A 记录".into()),
            Err(e) => r.error = Some(e),
        },
        Err(e) => {
            r.error = Some(if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                format!("查询超时（{}ms 无应答）", timeout.as_millis())
            } else {
                format!("接收应答失败: {}", e)
            });
        }
    }
    r.elapsed_ms = start.elapsed().as_millis() as u64;
    r
}

/// 构造一条标准的 DNS A 记录查询报文。
fn build_query(id: u16, domain: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // 标准查询，置 RD（期望递归）
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    q.extend_from_slice(&[0u8; 8]); // ANCOUNT / NSCOUNT / ARCOUNT = 0
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    q
}

/// 解析 DNS 应答报文，提取所有 A 记录。
fn parse_response(buf: &[u8], id: u16) -> Result<Vec<Ipv4Addr>, String> {
    if buf.len() < 12 {
        return Err("应答报文过短".into());
    }
    let rid = u16::from_be_bytes([buf[0], buf[1]]);
    if rid != id {
        return Err("应答事务 ID 不匹配".into());
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return Err("收到的不是应答报文".into());
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("DNS 服务器返回错误码 {}（3=域名不存在，5=拒绝）", rcode));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)? + 4; // 跳过 QTYPE + QCLASS
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            answers.push(Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]));
        }
        pos += rdlen;
    }
    Ok(answers)
}

/// 跳过 DNS 名称字段（支持压缩指针），返回其后位置。
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        if pos >= buf.len() {
            return Err("名称字段越界".into());
        }
        let b = buf[pos];
        if b & 0xC0 == 0xC0 {
            return Ok(pos + 2); // 压缩指针占 2 字节
        }
        if b == 0 {
            return Ok(pos + 1);
        }
        pos += 1 + b as usize;
    }
}

/// 测试系统解析器（getaddrinfo，受系统 hosts / DNS 策略影响）。
pub fn resolve_system(domain: &str, timeout: Duration) -> Result<Vec<Ipv4Addr>, String> {
    let d = domain.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = (d.as_str(), 80u16)
            .to_socket_addrs()
            .map(|it| {
                it.filter_map(|sa| match sa {
                    SocketAddr::V4(v) => Some(*v.ip()),
                    _ => None,
                })
                .collect::<Vec<_>>()
            })
            .map_err(|e| e.to_string());
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(v)) if !v.is_empty() => Ok(v),
        Ok(Ok(_)) => Err("系统解析未返回 IPv4 地址".into()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(format!("系统解析超时（{}ms）", timeout.as_millis())),
    }
}
