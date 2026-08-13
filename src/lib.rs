//! 诸葛网络问题诊断器核心库。
//!
//! 提供本地网络环境检测、网关/公网连通性检查、DNS 解析检查、
//! ICMP 逐跳链路探测、HTTP 应用层检查与瓶颈定位诊断，
//! 供命令行版（zhuge-netdiag.exe）与图形界面版（zhuge-netdiag-gui.exe）共享。

pub mod arp;
pub mod diagnose;
pub mod dns;
pub mod env;
pub mod http;
pub mod icmp;
pub mod quality;
pub mod report;
pub mod runner;
pub mod trace;
