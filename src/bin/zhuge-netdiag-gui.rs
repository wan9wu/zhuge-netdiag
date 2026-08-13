//! 诸葛网络问题诊断器 —— 图形界面版（zhuge-netdiag-gui.exe）
//!
//! 与命令行版共享同一套诊断核心（zhuge_netdiag 库），功能完全一致：
//! 本地环境检测、网关/公网连通性、DNS 解析、逐跳链路探测、HTTP 检查、瓶颈定位。
//! 诊断在后台线程运行，界面实时显示进度；完成后可查看结论、保存或复制报告。

use std::sync::mpsc;
use std::time::Duration;

use eframe::egui;
use zhuge_netdiag::diagnose::Level;
use zhuge_netdiag::{report, runner};

/// 后台诊断线程发回 UI 的消息。
enum TaskMsg {
    Event(runner::Event),
    Done(report::Session),
}

#[derive(PartialEq)]
enum View {
    Log,
    Report,
}

struct DiagApp {
    // 参数
    target: String,
    count: u32,
    timeout_ms: u32,
    max_hops: u8,
    quality_count: u32,
    // 运行状态
    running: bool,
    current_step: String,
    events: Vec<String>,
    rx: Option<mpsc::Receiver<TaskMsg>>,
    // 结果
    session: Option<report::Session>,
    report_text: String,
    view: View,
    save_path: String,
    status_msg: String,
}

impl Default for DiagApp {
    fn default() -> Self {
        Self {
            target: runner::DEFAULT_TARGET.into(),
            count: 8,
            timeout_ms: 1500,
            max_hops: 30,
            quality_count: 20,
            running: false,
            current_step: String::new(),
            events: Vec::new(),
            rx: None,
            session: None,
            report_text: String::new(),
            view: View::Log,
            save_path: String::new(),
            status_msg: String::new(),
        }
    }
}

/// 加载系统中文字体（微软雅黑），否则 egui 默认字体无法显示中文。
fn setup_cjk_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes).into());
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .insert(0, "cjk".to_owned());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

impl eframe::App for DiagApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 拉取后台线程消息
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    TaskMsg::Event(runner::Event::Step { n, total, title }) => {
                        self.current_step = format!("[{}/{}] {}", n, total, title);
                        self.events.push(format!("{} ...", self.current_step));
                    }
                    TaskMsg::Event(runner::Event::Log(line)) => {
                        self.events.push(format!("    {}", line));
                    }
                    TaskMsg::Done(session) => {
                        self.report_text = report::render(&session);
                        self.save_path = report::default_report_path();
                        self.session = Some(session);
                        self.running = false;
                        self.view = View::Report;
                        self.status_msg = "诊断完成".into();
                    }
                }
            }
        }
        if self.running {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(4.0);
                ui.heading(format!(
                    "诸葛网络问题诊断器 v{}（图形界面版）",
                    env!("CARGO_PKG_VERSION")
                ));
                ui.label("开源网络诊断工具（MIT 协议）· 仅使用公开标准协议：ICMP / IP TTL / DNS / HTTP");
                ui.add_space(4.0);
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("诊断目标:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.target)
                        .desired_width(180.0)
                        .hint_text("IP 或域名"),
                );
                ui.label("每跳探测:");
                ui.add(egui::DragValue::new(&mut self.count));
                ui.label("质量采样:");
                ui.add(egui::DragValue::new(&mut self.quality_count));
                ui.label("超时(ms):");
                ui.add(egui::DragValue::new(&mut self.timeout_ms));
                ui.label("最大跳数:");
                ui.add(egui::DragValue::new(&mut self.max_hops));
                ui.add_space(8.0);
                if self.running {
                    ui.spinner();
                    ui.label(&self.current_step);
                } else {
                    if ui
                        .add_enabled(true, egui::Button::new("开始诊断"))
                        .clicked()
                    {
                        self.start(ctx);
                    }
                    if self.session.is_some() && ui.button("保存报告").clicked() {
                        self.save_report();
                    }
                    if self.session.is_some() && ui.button("复制报告").clicked() {
                        ctx.copy_text(self.report_text.clone());
                        self.status_msg = "报告已复制到剪贴板".into();
                    }
                }
            });
            if !self.status_msg.is_empty() {
                ui.colored_label(egui::Color32::from_rgb(40, 120, 40), &self.status_msg);
            }
            ui.separator();
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // 视图切换
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.view, View::Log, "实时日志");
                ui.selectable_value(&mut self.view, View::Report, "诊断报告");
            });
            ui.separator();

            match self.view {
                View::Log => self.draw_log(ui),
                View::Report => self.draw_report(ui),
            }
        });
    }
}

impl DiagApp {
    fn start(&mut self, ctx: &egui::Context) {
        // 参数校验与收紧
        self.count = self.count.clamp(1, 64);
        self.quality_count = self.quality_count.clamp(1, 1000);
        if self.timeout_ms < 100 {
            self.timeout_ms = 1000;
        }
        if self.max_hops == 0 {
            self.max_hops = 30;
        }
        let target = if self.target.trim().is_empty() {
            runner::DEFAULT_TARGET.to_string()
        } else {
            self.target.trim().to_string()
        };
        let opts = runner::RunOpts {
            target,
            count: self.count,
            timeout_ms: self.timeout_ms,
            max_hops: self.max_hops,
            quality_count: self.quality_count,
        };

        self.events.clear();
        self.session = None;
        self.report_text.clear();
        self.status_msg = format!("正在诊断 {} ...", opts.target);
        self.view = View::Log;
        self.running = true;
        self.current_step = "准备中".into();

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        std::thread::spawn(move || {
            let session = runner::run_diagnosis(&opts, &mut |ev| {
                let _ = tx.send(TaskMsg::Event(ev));
            });
            let _ = tx.send(TaskMsg::Done(session));
        });
        ctx.request_repaint();
    }

    fn save_report(&mut self) {
        let path = if self.save_path.trim().is_empty() {
            report::default_report_path()
        } else {
            self.save_path.trim().to_string()
        };
        match std::fs::write(&path, &self.report_text) {
            Ok(_) => {
                self.save_path = path.clone();
                self.status_msg = format!("报告已保存: {}", path);
            }
            Err(e) => self.status_msg = format!("报告保存失败（{}）: {}", path, e),
        }
    }

    fn draw_log(&mut self, ui: &mut egui::Ui) {
        if self.events.is_empty() && !self.running {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.label("在上方设置诊断目标与参数，然后点击\"开始诊断\"。");
                ui.label("程序将自动完成 7 个步骤：本地环境 → 网关 → 公网 → DNS → 逐跳链路 → HTTP → 瓶颈分析。");
            });
            return;
        }
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.events {
                    ui.monospace(line);
                }
                if self.running {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("诊断进行中 ...");
                    });
                }
            });
    }

    fn draw_report(&mut self, ui: &mut egui::Ui) {
        let Some(session) = &self.session else {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.label("暂无诊断结果，请先运行一次诊断。");
            });
            return;
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            // 结论卡片
            if let Some(d) = &session.diagnosis {
                ui.group(|ui| {
                    ui.heading("诊断结论");
                    ui.add_space(4.0);
                    for f in &d.findings {
                        let color = match f.level {
                            Level::Ok => egui::Color32::from_rgb(30, 130, 60),
                            Level::Warn => egui::Color32::from_rgb(200, 140, 0),
                            Level::Error => egui::Color32::from_rgb(200, 40, 40),
                        };
                        ui.horizontal_wrapped(|ui| {
                            ui.label(egui::RichText::new(f.level.tag()).color(color).strong());
                            ui.label(egui::RichText::new(&f.segment).strong());
                            ui.label(&f.detail);
                        });
                        if let Some(sug) = &f.suggestion {
                            ui.label(format!("        建议：{}", sug));
                        }
                    }
                    ui.add_space(4.0);
                    ui.separator();
                    ui.label(egui::RichText::new(&d.conclusion).strong());
                });
                ui.add_space(8.0);
            }

            // 保存路径
            ui.horizontal(|ui| {
                ui.label("报告保存路径:");
                ui.add(egui::TextEdit::singleline(&mut self.save_path).desired_width(360.0));
            });
            ui.add_space(8.0);

            // 完整报告文本（与命令行版输出一致）
            ui.heading("完整报告");
            ui.separator();
            ui.add(
                egui::TextEdit::multiline(&mut self.report_text.as_str())
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 720.0])
            .with_min_inner_size([760.0, 520.0])
            .with_title(format!(
                "诸葛网络问题诊断器 v{}（图形界面版）",
                env!("CARGO_PKG_VERSION")
            )),
        ..Default::default()
    };
    eframe::run_native(
        "诸葛网络问题诊断器",
        options,
        Box::new(|cc| {
            setup_cjk_fonts(&cc.egui_ctx);
            Ok(Box::new(DiagApp::default()))
        }),
    )
}
