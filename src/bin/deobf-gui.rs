#![cfg_attr(windows, windows_subsystem = "windows")]

use iced::widget::{button, column, container, pick_list, row, text, text_input};
use iced::{Element, Length, Task, Theme};
use rfd::FileDialog;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() -> iced::Result {
    iced::application("DEOBF — Windows Protection", App::update, App::view)
        .theme(|_| Theme::Dark)
        .window_size(iced::Size::new(1080.0, 720.0))
        .run_with(|| (App::default(), Task::none()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    Safe,
    Balanced,
    Maximum,
}

impl Profile {
    const ALL: [Profile; 3] = [Profile::Safe, Profile::Balanced, Profile::Maximum];
    fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "Safe",
            Self::Balanced => "Balanced",
            Self::Maximum => "Maximum",
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Default)]
struct App {
    input: String,
    output: String,
    password: String,
    profile: Option<Profile>,
    analysis: Option<String>,
    status: String,
    busy: bool,
}

#[derive(Debug, Clone)]
enum Message {
    PickInput,
    PickOutput,
    InputChanged(String),
    OutputChanged(String),
    PasswordChanged(String),
    ProfileChanged(Profile),
    Analyze,
    Protect,
    Unprotect,
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PickInput => {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.input = path.display().to_string();
                    self.analysis = None;
                    self.status = "File selected. Click Analyze to inspect it.".into();
                }
            }
            Message::PickOutput => {
                if let Some(path) = FileDialog::new().set_file_name("protected.deobf").save_file() {
                    self.output = path.display().to_string();
                }
            }
            Message::InputChanged(v) => self.input = v,
            Message::OutputChanged(v) => self.output = v,
            Message::PasswordChanged(v) => self.password = v,
            Message::ProfileChanged(v) => self.profile = Some(v),
            Message::Analyze => self.analyze(),
            Message::Protect => self.protect(),
            Message::Unprotect => self.unprotect(),
        }
        Task::none()
    }

    fn analyze(&mut self) {
        let path = PathBuf::from(&self.input);
        match std::fs::read(&path) {
            Ok(data) => match deobf::analyze_only(&data) {
                Ok(a) => {
                    self.analysis = Some(format!(
                        "Type: {}\nArchitecture: {}\nExecutable: {}\nDebug markers: {}\nArchive signature: {}\nSize: {} bytes",
                        a.kind, a.architecture, a.executable, a.has_debug_markers,
                        a.has_archive_signature, data.len()
                    ));
                    self.status = "Analysis complete.".into();
                }
                Err(e) => self.status = format!("Analysis failed: {e:#}"),
            },
            Err(e) => self.status = format!("Cannot read input: {e}"),
        }
    }

    fn sibling_cli() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        let name = if cfg!(windows) { "deobf.exe" } else { "deobf" };
        let cli = dir.join(name);
        cli.exists().then_some(cli)
    }

    fn run_cli(&mut self, command: &str) {
        if self.input.is_empty() || self.output.is_empty() {
            self.status = "Choose both input and output files.".into();
            return;
        }
        if self.password.len() < 12 {
            self.status = "Password must contain at least 12 characters.".into();
            return;
        }
        let Some(cli) = Self::sibling_cli() else {
            self.status = "deobf.exe was not found beside the GUI executable.".into();
            return;
        };

        self.busy = true;
        self.status = format!("Running {command}…");
        let mut child = Command::new(cli);
        child
            .arg(command)
            .arg(&self.input)
            .arg("--output")
            .arg(&self.output)
            .arg("--password")
            .arg(&self.password)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        match child.output() {
            Ok(result) if result.status.success() => {
                self.status = format!("{command} completed successfully.");
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                self.status = format!("{command} failed: {}", stderr.trim());
            }
            Err(e) => self.status = format!("Could not start core: {e}"),
        }
        self.busy = false;
    }

    fn protect(&mut self) {
        self.run_cli("protect");
    }

    fn unprotect(&mut self) {
        self.run_cli("unprotect");
    }

    fn view(&self) -> Element<'_, Message> {
        let profile = self.profile.unwrap_or(Profile::Balanced);
        let analysis = self.analysis.as_deref().unwrap_or("No file analyzed yet.");

        let header = row![
            column![text("DEOBF").size(38), text("Windows Protection Studio").size(16)]
                .spacing(3),
            container(text("READY").size(13)).padding(8),
        ]
        .spacing(Length::Fill)
        .align_y(iced::Alignment::Center);

        let input = row![
            text_input("Input file", &self.input)
                .on_input(Message::InputChanged)
                .width(Length::Fill),
            button(text("Browse")).on_press(Message::PickInput),
        ]
        .spacing(10);

        let output = row![
            text_input("Output file", &self.output)
                .on_input(Message::OutputChanged)
                .width(Length::Fill),
            button(text("Save as")).on_press(Message::PickOutput),
        ]
        .spacing(10);

        let security = column![
            text("Protection profile"),
            pick_list(&Profile::ALL[..], self.profile.or(Some(Profile::Balanced)), Message::ProfileChanged),
            text("Password"),
            text_input("Minimum 12 characters", &self.password)
                .secure(true)
                .on_input(Message::PasswordChanged),
        ]
        .spacing(9);

        let actions = row![
            button(text("Analyze")).on_press_maybe((!self.input.is_empty()).then_some(Message::Analyze)),
            button(text("Protect")).on_press_maybe((!self.busy).then_some(Message::Protect)),
            button(text("Unprotect")).on_press_maybe((!self.busy).then_some(Message::Unprotect)),
        ]
        .spacing(10);

        let analysis_panel = container(column![text("ANALYSIS").size(13), text(analysis).size(15)].spacing(10))
            .width(Length::Fill)
            .padding(20);
        let status_panel = container(text(&self.status).size(14))
            .width(Length::Fill)
            .padding(16);

        container(
            column![
                header,
                text("PROTECTION WORKSPACE").size(13),
                input,
                output,
                security,
                actions,
                analysis_panel,
                status_panel,
            ]
            .spacing(18)
            .padding(36),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
}
