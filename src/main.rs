//! 诸葛网络问题诊断器（zhuge-netdiag）—— 命令行版
//!
//! 自动检测本机网络环境，找到本机到公网的链路，逐级检查各节点连接情况，
//! 深入分析后指出网络瓶颈所在环节（如丢包率过高、时延突增、DNS 失效等）。
//!
//! 仅依赖公开标准协议：ICMP（RFC 792）、IP TTL、DNS（RFC 1035）、HTTP/1.1。
//! 图形界面版见 zhuge-netdiag-gui.exe，两者共享同一套诊断核心（zhuge_netdiag 库）。

use zhuge_netdiag::{report, runner};

#[derive(Debug, Clone)]
struct CliOpts {
    run: runner::RunOpts,
    report_path: Option<String>,
}

fn print_help() {
    println!(
        r#"诸葛网络问题诊断器 v{} —— 开源网络链路诊断工具（MIT 协议）

用法:
  zhuge-netdiag [选项]

选项:
  --target <IP或域名>   诊断目标（默认 {}）
  --count <N>           每跳探测次数（默认 8，范围 1..=64）
  --samples <N>         质量采样次数（默认 20，范围 1..=1000，可加大以捕捉间歇性丢包）
  --timeout <毫秒>      单次探测超时（默认 1500）
  --hops <N>            最大跳数（默认 30）
  --report <路径>       报告保存路径（默认自动命名）
  --quick               快速模式（探测次数减半、超时缩短）
  -h, --help            显示本帮助

示例:
  zhuge-netdiag
  zhuge-netdiag --target www.baidu.com --count 10
  zhuge-netdiag --samples 100
  zhuge-netdiag --quick --report C:\temp\report.md
"#,
        env!("CARGO_PKG_VERSION"),
        runner::DEFAULT_TARGET
    );
}

fn parse_args() -> Result<CliOpts, String> {
    let mut cli = CliOpts {
        run: runner::RunOpts::default(),
        report_path: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--quick" => {
                cli.run.count = 4;
                cli.run.timeout_ms = 1000;
                cli.run.quality_count = 4;
            }
            "--target" => cli.run.target = it.next().ok_or("--target 需要一个参数")?,
            "--samples" => {
                cli.run.quality_count = it
                    .next()
                    .ok_or("--samples 需要一个参数")?
                    .parse()
                    .map_err(|_| "--samples 必须是数字")?
            }
            "--count" => {
                cli.run.count = it
                    .next()
                    .ok_or("--count 需要一个参数")?
                    .parse()
                    .map_err(|_| "--count 必须是数字")?
            }
            "--timeout" => {
                cli.run.timeout_ms = it
                    .next()
                    .ok_or("--timeout 需要一个参数")?
                    .parse()
                    .map_err(|_| "--timeout 必须是数字")?
            }
            "--hops" => {
                cli.run.max_hops = it
                    .next()
                    .ok_or("--hops 需要一个参数")?
                    .parse()
                    .map_err(|_| "--hops 必须是数字")?
            }
            "--report" => cli.report_path = Some(it.next().ok_or("--report 需要一个参数")?),
            other => return Err(format!("未知参数: {}（使用 --help 查看用法）", other)),
        }
    }
    if cli.run.count == 0 || cli.run.count > 64 {
        return Err("--count 必须在 1..=64 范围内".into());
    }
    if cli.run.quality_count == 0 || cli.run.quality_count > 1000 {
        return Err("--samples 必须在 1..=1000 范围内".into());
    }
    if cli.run.timeout_ms < 100 {
        return Err("--timeout 不能小于 100ms".into());
    }
    Ok(cli)
}

fn banner() {
    println!("==============================================================");
    println!("     诸葛网络问题诊断器  v{}", env!("CARGO_PKG_VERSION"));
    println!("     开源网络诊断工具（MIT 协议）· 仅使用公开标准协议");
    println!("==============================================================");
}

/// 将控制台输出切换为 UTF-8，避免中文乱码。
#[cfg(windows)]
fn setup_console_utf8() {
    extern "system" {
        fn SetConsoleOutputCP(cp: u32) -> i32;
    }
    unsafe {
        SetConsoleOutputCP(65001);
    }
}

fn main() {
    #[cfg(windows)]
    setup_console_utf8();

    let cli = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
    };

    banner();

    let session = runner::run_diagnosis(&cli.run, &mut |ev| match ev {
        runner::Event::Step { n, total, title } => println!("\n[{}/{}] {} ...", n, total, title),
        runner::Event::Log(line) => println!("    {}", line),
    });

    report::print_conclusion(&session);

    // 保存报告
    let path = cli
        .report_path
        .clone()
        .unwrap_or_else(report::default_report_path);
    match std::fs::write(&path, report::render(&session)) {
        Ok(_) => println!("\n诊断报告已保存: {}", path),
        Err(e) => eprintln!("\n报告保存失败（{}）: {}", path, e),
    }
}
