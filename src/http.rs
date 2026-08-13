//! 应用层 HTTP 连通性检测。
//!
//! 用标准 HTTP/1.1 明文请求探测公网 Web 服务，用于区分"网络层通但应用层不通"
//! 的情况（如代理配置错误、防火墙拦截、Web 认证/强制门户）。

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// 内置 HTTP 连通性探测端点（host, 路径, 预期内容）。
/// 国外探测点在国内可能被屏蔽/劫持，因此任一端点成功即视为应用层可用；
/// 全部失败时还会回退到直接验证用户填的目标域名。
pub const HTTP_CHECKS: [(&str, &str, &str); 3] = [
    ("www.msftconnecttest.com", "/connect.txt", "Microsoft Connect Test"),
    ("captive.apple.com", "/hotspot-detect.html", "Success"),
    ("detectportal.firefox.com", "/success.txt", "success"),
];

#[derive(Clone, Debug)]
pub struct HttpResult {
    pub host: String,
    pub connected: bool,
    pub status_code: Option<u16>,
    pub elapsed_ms: u64,
    pub note: String,
}

impl HttpResult {
    pub fn ok(&self) -> bool {
        matches!(self.status_code, Some(c) if (200..400).contains(&c))
    }
}

/// 对 `host` 的 80 端口发起一次 HTTP GET 请求并解析状态码。
/// `expect` 非空时校验响应体包含预期内容（防劫持/认证页）；为空时只看状态码。
pub fn http_check(host: &str, path: &str, expect: &str, timeout: Duration) -> HttpResult {
    let start = Instant::now();
    let mut r = HttpResult {
        host: host.to_string(),
        connected: false,
        status_code: None,
        elapsed_ms: 0,
        note: String::new(),
    };

    let addr = match (host, 80u16).to_socket_addrs() {
        Ok(mut it) => match it.find(|a| a.is_ipv4()) {
            Some(a) => a,
            None => {
                r.note = "域名解析无 IPv4 结果".into();
                return r;
            }
        },
        Err(e) => {
            r.note = format!("域名解析失败: {}", e);
            return r;
        }
    };

    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            r.note = format!("TCP 连接 {} 失败: {}", addr, e);
            return r;
        }
    };
    r.connected = true;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: zhuge-netdiag\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host
    );
    if let Err(e) = stream.write_all(req.as_bytes()) {
        r.note = format!("发送 HTTP 请求失败: {}", e);
        r.elapsed_ms = start.elapsed().as_millis() as u64;
        return r;
    }

    let mut buf = vec![0u8; 4096];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n]);
            if let Some(line) = text.lines().next() {
                let mut parts = line.split_whitespace();
                let _ver = parts.next();
                if let Some(code) = parts.next().and_then(|c| c.parse::<u16>().ok()) {
                    r.status_code = Some(code);
                }
            }
            // 预期内容不符通常意味着被重定向到认证页或被代理劫持
            if !expect.is_empty() && !text.contains(expect) {
                r.note = "响应内容与预期不符，可能被重定向到 Web 认证页（强制门户）或被代理劫持".into();
            }
        }
        Ok(_) => r.note = "收到空响应".into(),
        Err(e) => r.note = format!("读取响应失败: {}", e),
    }
    r.elapsed_ms = start.elapsed().as_millis() as u64;
    r
}
