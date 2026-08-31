#![cfg_attr(windows, windows_subsystem = "windows")]

use deobf::{
    analyze_only, default_protected_output, protect_file, run_embedded_stub, run_protected,
    unprotect_file, EngineOptions, RuntimeKind,
};
use iced::widget::{
    button, checkbox, column, container, pick_list, row, scrollable, text, text_input, Space,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Task, Theme};
use rfd::FileDialog;
use std::path::PathBuf;

fn main() -> iced::Result {
    if let Some(result) = run_embedded_stub() {
        match result {
            Ok(code) => std::process::exit(code),
            Err(err) => {
                eprintln!("DEOBF runtime: {err:#}");
                std::process::exit(1);
            }
        }
    }

    iced::application("DEOBF — Protection Studio", App::update, App::view)
        .theme(|_| deobf_theme())
        .window_size(iced::Size::new(1280.0, 840.0))
        .run_with(|| (App::default(), Task::none()))
}

fn deobf_theme() -> Theme {
    Theme::custom(
        String::from("DEOBF"),
        iced::theme::Palette {
            background: Color::from_rgb8(22, 22, 26),
            text: Color::from_rgb8(226, 226, 232),
            primary: Color::from_rgb8(47, 129, 247),
            success: Color::from_rgb8(35, 134, 54),
            danger: Color::from_rgb8(218, 54, 51),
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Project,
    Options,
    Runtime,
    Restore,
}
impl Page {
    fn label(self) -> &'static str {
        match self {
            Self::Project => "Project",
            Self::Options => "Options",
            Self::Runtime => "Runtime",
            Self::Restore => "Restore",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    Safe,
    Balanced,
    Maximum,
}
impl Profile {
    const ALL: [Self; 3] = [Self::Safe, Self::Balanced, Self::Maximum];
    fn name(self) -> &'static str {
        match self {
            Self::Safe => "Safe",
            Self::Balanced => "Balanced",
            Self::Maximum => "Maximum",
        }
    }
    fn engine(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Balanced => "balanced",
            Self::Maximum => "maximum",
        }
    }
    fn caps(self) -> Caps {
        match self {
            Self::Safe => Caps {
                strip_debug: false,
                protect_strings: false,
                rename_symbols: false,
                control_flow: false,
                resources: true,
                anti_tamper: true,
            },
            Self::Balanced | Self::Maximum => Caps {
                strip_debug: true,
                protect_strings: true,
                rename_symbols: true,
                control_flow: true,
                resources: true,
                anti_tamper: true,
            },
        }
    }
}
impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Copy)]
struct Caps {
    strip_debug: bool,
    protect_strings: bool,
    rename_symbols: bool,
    control_flow: bool,
    resources: bool,
    anti_tamper: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunAs {
    Pe,
    Jar,
    Python,
}
impl RunAs {
    const ALL: [Self; 3] = [Self::Pe, Self::Jar, Self::Python];
    fn kind(self) -> RuntimeKind {
        match self {
            Self::Pe => RuntimeKind::Pe,
            Self::Jar => RuntimeKind::Jar,
            Self::Python => RuntimeKind::Python,
        }
    }
}
impl std::fmt::Display for RunAs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pe => "Windows EXE",
            Self::Jar => "Java JAR",
            Self::Python => "Python",
        })
    }
}

struct App {
    page: Page,
    input: String,
    output: String,
    password: String,
    lock_with_password: bool,
    profile: Profile,
    run_as: RunAs,
    interpreter: String,
    verify: bool,
    integrity: bool,
    analysis: String,
    log: Vec<String>,
    busy: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            page: Page::Project,
            input: String::new(),
            output: String::new(),
            password: String::new(),
            lock_with_password: false,
            profile: Profile::Balanced,
            run_as: RunAs::Pe,
            interpreter: String::new(),
            verify: true,
            integrity: true,
            analysis: String::new(),
            log: vec![
                "DEOBF Protection Studio ready. Protect is one click; no password required.".into(),
            ],
            busy: false,
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    Navigate(Page),
    PickInput,
    PickOutput,
    InputChanged(String),
    OutputChanged(String),
    PasswordChanged(String),
    LockToggled(bool),
    ProfileChanged(Profile),
    RunAsChanged(RunAs),
    InterpreterChanged(String),
    VerifyToggled(bool),
    IntegrityToggled(bool),
    Analyze,
    Protect,
    Restore,
    Run,
}

impl App {
    fn log_line(&mut self, line: impl Into<String>) {
        let line = line.into();
        self.log.push(line);
        if self.log.len() > 200 {
            let extra = self.log.len() - 200;
            self.log.drain(..extra);
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Navigate(page) => self.page = page,
            Message::PickInput => {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.input = path.display().to_string();
                    self.output = default_protected_output(&path).display().to_string();
                    self.analysis.clear();
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        self.run_as = if ext.eq_ignore_ascii_case("jar") {
                            RunAs::Jar
                        } else if ext.eq_ignore_ascii_case("py") || ext.eq_ignore_ascii_case("pyc")
                        {
                            RunAs::Python
                        } else {
                            RunAs::Pe
                        };
                    }
                    self.log_line(format!("Selected {}", path.display()));
                    self.log_line(format!("Default output {}", self.output));
                }
            }
            Message::PickOutput => {
                if let Some(path) = FileDialog::new().save_file() {
                    self.output = path.display().to_string();
                    self.log_line(format!("Output set to {}", path.display()));
                }
            }
            Message::InputChanged(v) => self.input = v,
            Message::OutputChanged(v) => self.output = v,
            Message::PasswordChanged(v) => self.password = v,
            Message::LockToggled(v) => {
                self.lock_with_password = v;
                self.log_line(if v {
                    "Extra password lock enabled (optional)."
                } else {
                    "Extra password lock off — packer-style auto-run."
                });
            }
            Message::ProfileChanged(v) => {
                self.profile = v;
                self.log_line(format!("Profile: {}", v.name()));
            }
            Message::RunAsChanged(v) => self.run_as = v,
            Message::InterpreterChanged(v) => self.interpreter = v,
            Message::VerifyToggled(v) => self.verify = v,
            Message::IntegrityToggled(v) => self.integrity = v,
            Message::Analyze => self.analyze(),
            Message::Protect => self.protect(),
            Message::Restore => self.restore(),
            Message::Run => self.run(),
        }
        Task::none()
    }

    fn analyze(&mut self) {
        if self.input.is_empty() {
            self.log_line("Choose an input file first.");
            return;
        }
        match std::fs::read(&self.input)
            .map_err(|e| e.to_string())
            .and_then(|d| analyze_only(&d).map_err(|e| format!("{e:#}")))
        {
            Ok(a) => {
                self.analysis = format!(
                    "Type: {}\nArchitecture: {}\nExecutable: {}\nDebug markers: {}\nArchive: {}",
                    a.kind,
                    a.architecture,
                    a.executable,
                    a.has_debug_markers,
                    a.has_archive_signature
                );
                self.log_line(format!("Analyzed {} ({})", self.input, a.kind));
            }
            Err(e) => {
                self.analysis = format!("Analysis failed: {e}");
                self.log_line(format!("Analysis failed: {e}"));
            }
        }
    }

    fn protect_pass(&self) -> Result<&[u8], &'static str> {
        if self.lock_with_password {
            if self.password.len() < 12 {
                return Err(
                    "Extra password lock is on: password must contain at least 12 characters.",
                );
            }
            Ok(self.password.as_bytes())
        } else {
            Ok(b"")
        }
    }

    fn restore_pass(&self) -> &[u8] {
        if self.password.len() >= 12 {
            self.password.as_bytes()
        } else {
            b""
        }
    }

    fn protect(&mut self) {
        if self.input.is_empty() || self.output.is_empty() {
            self.log_line("Choose input and output paths.");
            return;
        }
        let pass = match self.protect_pass() {
            Ok(pass) => pass.to_vec(),
            Err(msg) => {
                self.log_line(msg);
                return;
            }
        };
        self.busy = true;
        self.log_line(format!("Protecting {} → {}", self.input, self.output));
        let result = protect_file(
            &PathBuf::from(&self.input),
            &PathBuf::from(&self.output),
            &pass,
            &EngineOptions {
                profile: self.profile.engine().into(),
                verify: self.verify,
                add_integrity: self.integrity,
            },
        );
        match result {
            Ok(r) => {
                self.log_line(format!(
                "Protect complete. {} → {} bytes. Double-click / open the output to run (PE, JAR, Python; no password).{}",
                r.input_size,
                r.output_size,
                if pass.is_empty() { "" } else { " Extra password lock is on — use Runtime / deobf run for JAR and Python." }
            ))
            }
            Err(e) => self.log_line(format!("Protection failed: {e:#}")),
        }
        self.busy = false;
    }

    fn restore(&mut self) {
        if self.input.is_empty() || self.output.is_empty() {
            self.log_line("Choose package and restore output.");
            return;
        }
        self.busy = true;
        self.log_line("Restoring authenticated payload…");
        self.log_line(
            match unprotect_file(
                &PathBuf::from(&self.input),
                &PathBuf::from(&self.output),
                self.restore_pass(),
            ) {
                Ok(()) => "Authenticated payload restored.".into(),
                Err(e) => format!("Restore failed: {e:#}"),
            },
        );
        self.busy = false;
    }

    fn run(&mut self) {
        if self.input.is_empty() {
            self.log_line("Choose a protected file to run.");
            return;
        }
        self.busy = true;
        let interpreter = if self.interpreter.trim().is_empty() {
            None
        } else {
            Some(self.interpreter.trim())
        };
        let result = run_protected(
            &PathBuf::from(&self.input),
            self.restore_pass(),
            self.run_as.kind(),
            interpreter,
            &[],
        );
        self.log_line(match result {
            Ok(status) => format!("Protected {} process exited with {status}.", self.run_as),
            Err(e) => format!("Runtime failed: {e:#}"),
        });
        self.busy = false;
    }

    fn view(&self) -> Element<'_, Message> {
        let sidebar = self.sidebar();
        let header = row![
            column![
                text("Project workspace").size(22),
                text("Protect software you own. Output keeps the original extension. No password by default.").size(13),
            ]
            .spacing(4)
            .width(Length::Fill),
            container(text(if self.busy { "WORKING" } else { "READY" }).size(13)).padding(10),
        ]
        .align_y(Alignment::Center);

        let body = match self.page {
            Page::Project => self.project_page(),
            Page::Options => self.options_page(),
            Page::Runtime => self.runtime_page(),
            Page::Restore => self.restore_page(),
        };

        let log_lines = if self.log.is_empty() {
            column![text(" ").size(13)]
        } else {
            column(
                self.log
                    .iter()
                    .rev()
                    .take(40)
                    .rev()
                    .map(|line| Element::from(text(line.as_str()).size(13)))
                    .collect::<Vec<_>>(),
            )
            .spacing(3)
        };
        let log_panel = container(
            column![
                text("LOG").size(12),
                scrollable(log_lines).height(Length::Fill),
            ]
            .spacing(8),
        )
        .padding(14)
        .width(Length::Fill)
        .height(170)
        .style(|_theme| panel_style(Color::from_rgb8(14, 14, 18)));

        let main = column![header, body, Space::with_height(8.0), log_panel]
            .spacing(16)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill);

        row![sidebar, main]
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn sidebar(&self) -> Element<'_, Message> {
        let brand = row![
            container(text("D").size(20))
                .padding(8)
                .style(|_t| panel_style(Color::from_rgb8(47, 129, 247))),
            column![text("DEOBF").size(22), text("Protection Studio").size(12)].spacing(0),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let mut nav = column![].spacing(4);
        for page in [Page::Project, Page::Options, Page::Runtime, Page::Restore] {
            let label = page.label();
            let btn = if self.page == page {
                button(text(label).size(15))
                    .on_press(Message::Navigate(page))
                    .width(Length::Fill)
                    .style(button::primary)
            } else {
                button(text(label).size(15))
                    .on_press(Message::Navigate(page))
                    .width(Length::Fill)
                    .style(button::secondary)
            };
            nav = nav.push(btn);
        }

        container(
            column![
                brand,
                Space::with_height(18.0),
                nav,
                Space::with_height(Length::Fill),
                text("Output naming").size(12),
                text(".exe stays .exe").size(12),
                text(".jar stays .jar").size(12),
                text(".py stays .py").size(12),
                Space::with_height(8.0),
                button(text("Protect").size(16))
                    .on_press(Message::Protect)
                    .width(Length::Fill)
                    .style(button::success)
                    .padding(12),
            ]
            .spacing(8)
            .padding(16),
        )
        .width(230)
        .height(Length::Fill)
        .style(|_theme| panel_style(Color::from_rgb8(16, 16, 20)))
        .into()
    }

    fn file_fields(&self) -> Element<'_, Message> {
        column![
            labeled_input(
                "Input file",
                &self.input,
                "Browse",
                Message::InputChanged,
                Message::PickInput
            ),
            labeled_input(
                "Output file",
                &self.output,
                "Save as",
                Message::OutputChanged,
                Message::PickOutput
            ),
            checkbox(
                "Optional extra password lock (off by default)",
                self.lock_with_password
            )
            .on_toggle(Message::LockToggled),
            row![
                column![
                    text("Password (only if extra lock is on, or for legacy restore)").size(13),
                    text_input("Leave empty for auto-run", &self.password)
                        .secure(true)
                        .on_input(Message::PasswordChanged),
                ]
                .spacing(6)
                .width(Length::Fill),
                column![
                    text("Profile").size(13),
                    pick_list(
                        &Profile::ALL[..],
                        Some(self.profile),
                        Message::ProfileChanged
                    )
                    .width(Length::Fill),
                ]
                .spacing(6)
                .width(Length::FillPortion(1)),
            ]
            .spacing(16),
        ]
        .spacing(12)
        .into()
    }

    fn project_page(&self) -> Element<'_, Message> {
        let analysis = container(
            column![
                text("ANALYSIS").size(12),
                text(if self.analysis.is_empty() {
                    "No file analyzed yet. Select an input and press Analyze."
                } else {
                    &self.analysis
                })
                .size(14),
            ]
            .spacing(8),
        )
        .padding(16)
        .width(Length::Fill)
        .style(|_t| panel_style(Color::from_rgb8(28, 28, 34)));

        column![
            self.file_fields(),
            row![
                button(text("Analyze"))
                    .on_press(Message::Analyze)
                    .style(button::secondary),
                button(text("Protect"))
                    .on_press(Message::Protect)
                    .style(button::success),
            ]
            .spacing(10),
            analysis,
        ]
        .spacing(14)
        .into()
    }

    fn options_page(&self) -> Element<'_, Message> {
        let caps = self.profile.caps();
        column![
            text("Protection options").size(18),
            text("These flags follow the selected profile. Names are DEOBF terms, not third-party product options.")
                .size(13),
            container(
                column![
                    checkbox("Strip debug metadata", caps.strip_debug),
                    checkbox("Conceal strings", caps.protect_strings),
                    checkbox("Rename identifiers", caps.rename_symbols),
                    checkbox("Control-flow transforms", caps.control_flow),
                    checkbox("Resource packaging", caps.resources),
                    checkbox("Integrity / anti-tamper digest", caps.anti_tamper),
                    Space::with_height(10.0),
                    checkbox("Verify after protect", self.verify).on_toggle(Message::VerifyToggled),
                    checkbox("Authenticated container (XChaCha20-Poly1305; Argon2id only if extra lock is on)", self.integrity)
                        .on_toggle(Message::IntegrityToggled),
                    checkbox("Windows runtime stub for PE (double-click to run, no password)", true),
                    checkbox("Self-running JAR / Python loaders (java -jar / python, no password)", true),
                    checkbox("Keep original file extension", true),
                    checkbox("Embed auto-key in overlay (packer-style)", !self.lock_with_password),
                ]
                .spacing(10),
            )
            .padding(18)
            .width(Length::Fill)
            .style(|_t| panel_style(Color::from_rgb8(28, 28, 34))),
            text("Not implemented: code virtualization, debugger killing, or AV/EDR evasion.").size(12),
        ]
        .spacing(12)
        .into()
    }

    fn runtime_page(&self) -> Element<'_, Message> {
        column![
            text("Run a protected file").size(18),
            self.file_fields(),
            row![
                column![
                    text("Launch as").size(13),
                    pick_list(&RunAs::ALL[..], Some(self.run_as), Message::RunAsChanged).width(Length::Fill),
                ]
                .spacing(6)
                .width(Length::Fill),
                column![
                    text("Interpreter (JAR / Python)").size(13),
                    text_input("java / python", &self.interpreter).on_input(Message::InterpreterChanged),
                ]
                .spacing(6)
                .width(Length::Fill),
            ]
            .spacing(16),
            button(text("Run protected")).on_press(Message::Run).style(button::primary),
            text("PE, JAR, and Python Protect output is self-running with no password. Double-click the file, or run `java -jar` / `python`. This Runtime page still launches extra-lock / legacy packages. Password is only needed for those.")
                .size(13),
        ]
        .spacing(12)
        .into()
    }

    fn restore_page(&self) -> Element<'_, Message> {
        column![
            text("Restore original bytes").size(18),
            self.file_fields(),
            button(text("Restore")).on_press(Message::Restore).style(button::secondary),
            text("Auto-keyed files restore without a password. Legacy passworded .deobf / extra-lock packages still need the password field.")
                .size(13),
        ]
        .spacing(12)
        .into()
    }
}

fn labeled_input<'a>(
    label: &'a str,
    value: &'a str,
    browse: &'a str,
    on_input: fn(String) -> Message,
    on_browse: Message,
) -> Element<'a, Message> {
    column![
        text(label).size(13),
        row![
            text_input(label, value)
                .on_input(on_input)
                .width(Length::Fill),
            button(text(browse))
                .on_press(on_browse)
                .style(button::secondary),
        ]
        .spacing(10),
    ]
    .spacing(6)
    .into()
}

fn panel_style(color: Color) -> container::Style {
    container::Style {
        background: Some(Background::Color(color)),
        text_color: Some(Color::from_rgb8(226, 226, 232)),
        border: Border {
            color: Color::from_rgb8(42, 42, 50),
            width: 1.0,
            radius: 6.0.into(),
        },
        shadow: iced::Shadow::default(),
    }
}
