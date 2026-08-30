#![cfg_attr(windows, windows_subsystem = "windows")]

use deobf::{analyze_only, protect, verify_compatible, EngineOptions};
use iced::widget::{button, column, container, pick_list, row, text, text_input};
use iced::{Element, Length, Task, Theme};
use rfd::FileDialog;
use std::path::PathBuf;
use std::process::Command;

fn main() -> iced::Result {
    iced::application("DEOBF — Windows Protection Studio", App::update, App::view)
        .theme(|_| Theme::Dark)
        .window_size(iced::Size::new(1100.0, 760.0))
        .run_with(|| (App::default(), Task::none()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile { Safe, Balanced, Maximum }

impl Profile {
    const ALL: [Profile; 3] = [Profile::Safe, Profile::Balanced, Profile::Maximum];
    fn as_str(self) -> &'static str {
        match self { Self::Safe => "Safe", Self::Balanced => "Balanced", Self::Maximum => "Maximum" }
    }
    fn engine_name(self) -> &'static str {
        match self { Self::Safe => "safe", Self::Balanced => "balanced", Self::Maximum => "maximum" }
    }
}
impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }
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
    PickInput, PickOutput, InputChanged(String), OutputChanged(String), PasswordChanged(String),
    ProfileChanged(Profile), Analyze, Protect, Restore, Verify,
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PickInput => {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.input = path.display().to_string();
                    self.analysis = None;
                    if self.output.is_empty() {
                        self.output = protected_output(&path).display().to_string();
                    }
                    self.status = "File selected. Analyze it before protection.".into();
                }
            }
            Message::PickOutput => {
                if let Some(path) = FileDialog::new().save_file() { self.output = path.display().to_string(); }
            }
            Message::InputChanged(value) => self.input = value,
            Message::OutputChanged(value) => self.output = value,
            Message::PasswordChanged(value) => self.password = value,
            Message::ProfileChanged(value) => self.profile = Some(value),
            Message::Analyze => self.analyze(),
            Message::Protect => self.protect(),
            Message::Restore => self.restore(),
            Message::Verify => self.verify(),
        }
        Task::none()
    }

    fn analyze(&mut self) {
        let path = PathBuf::from(&self.input);
        match std::fs::read(&path) {
            Ok(data) => match analyze_only(&data) {
                Ok(a) => {
                    self.analysis = Some(format!(
                        "Type: {}\nArchitecture: {}\nExecutable: {}\nDebug markers: {}\nArchive signature: {}\nSize: {} bytes",
                        a.kind, a.architecture, a.executable, a.has_debug_markers, a.has_archive_signature, data.len()
                    ));
                    self.status = "Analysis complete.".into();
                }
                Err(error) => self.status = format!("Analysis failed: {error:#}"),
            },
            Err(error) => self.status = format!("Cannot read input: {error}"),
        }
    }

    fn protect(&mut self) {
        if self.password.len() < 12 { self.status = "Password must contain at least 12 characters.".into(); return; }
        if self.input.is_empty() || self.output.is_empty() { self.status = "Choose input and output files.".into(); return; }
        self.busy = true;
        let profile = self.profile.unwrap_or(Profile::Balanced);
        let input = PathBuf::from(&self.input);
        let output = PathBuf::from(&self.output);
        let result = std::fs::read(&input)
            .map_err(anyhow::Error::from)
            .and_then(|data| {
                let options = EngineOptions { profile: profile.engine_name().to_owned(), verify: true, add_integrity: true };
                let (protected, report) = protect(data, &options)?;
                std::fs::write(&output, protected)?;
                Ok(report)
            });
        match result {
            Ok(report) => self.status = format!(
                "Encrypted package created: {} → {} bytes, {} pass(es), authenticated integrity enabled.",
                report.input_size, report.output_size, report.passes.len()
            ),
            Err(error) => self.status = format!("Protection failed: {error:#}"),
        }
        self.busy = false;
    }

    fn restore(&mut self) {
        if self.password.len() < 12 { self.status = "Password must contain at least 12 characters.".into(); return; }
        if self.input.is_empty() || self.output.is_empty() { self.status = "Choose package and restore output.".into(); return; }
        self.busy = true;
        let cli = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("deobf.exe")));
        let result = cli.filter(|p| p.exists()).ok_or_else(|| anyhow::anyhow!("deobf.exe was not found next to the GUI"))
            .and_then(|exe| {
                let status = Command::new(exe)
                    .arg("unprotect")
                    .arg(&self.input)
                    .arg("--output")
                    .arg(&self.output)
                    .arg("--password")
                    .arg(&self.password)
                    .status()?;
                if status.success() { Ok(()) } else { anyhow::bail!("restore process exited with {status}") }
            });
        self.status = match result {
            Ok(()) => "Original payload restored and authenticated successfully.".into(),
            Err(error) => format!("Restore failed: {error:#}"),
        };
        self.busy = false;
    }

    fn verify(&mut self) {
        if self.password.len() < 12 { self.status = "Password must contain at least 12 characters.".into(); return; }
        if self.input.is_empty() { self.status = "Choose a legacy compatibility file.".into(); return; }
        self.busy = true;
        self.status = match verify_compatible(&PathBuf::from(&self.input), self.password.as_bytes()) {
            Ok(manifest) => format!("Legacy metadata OK — {} bytes, {} profile, hash verified.", manifest.original_size, manifest.profile),
            Err(error) => format!("Legacy metadata verification failed: {error:#}"),
        };
        self.busy = false;
    }

    fn view(&self) -> Element<'_, Message> {
        let analysis = self.analysis.as_deref().unwrap_or("No file analyzed yet.");
        let profile = self.profile.unwrap_or(Profile::Balanced);
        let header = row![
            column![text("DEOBF").size(38), text("Windows Protection Studio").size(16)].spacing(3),
            container(text(if self.busy { "WORKING" } else { "READY" }).size(13)).padding(8)
        ].spacing(24).align_y(iced::Alignment::Center);
        let input = row![
            text_input("Input file / .deobf package", &self.input).on_input(Message::InputChanged).width(Length::Fill),
            button(text("Browse")).on_press(Message::PickInput)
        ].spacing(10);
        let output = row![
            text_input("Output file", &self.output).on_input(Message::OutputChanged).width(Length::Fill),
            button(text("Save as")).on_press(Message::PickOutput)
        ].spacing(10);
        let security = row![
            column![text("Protection profile"), pick_list(&Profile::ALL[..], Some(profile), Message::ProfileChanged).width(Length::Fill)].spacing(7).width(Length::Fill),
            column![text("Password"), text_input("Minimum 12 characters", &self.password).secure(true).on_input(Message::PasswordChanged)].spacing(7).width(Length::Fill)
        ].spacing(20);
        let actions = row![
            button(text("Analyze")).on_press_maybe((!self.input.is_empty() && !self.busy).then_some(Message::Analyze)),
            button(text("Protect → encrypted package")).on_press_maybe((!self.input.is_empty() && !self.busy).then_some(Message::Protect)),
            button(text("Restore original")).on_press_maybe((!self.input.is_empty() && !self.busy).then_some(Message::Restore)),
            button(text("Verify legacy")).on_press_maybe((!self.input.is_empty() && !self.busy).then_some(Message::Verify))
        ].spacing(10);
        let analysis_panel = container(column![text("ANALYSIS").size(13), text(analysis).size(15)].spacing(10)).width(Length::Fill).padding(20);
        let status_panel = container(text(&self.status).size(14)).width(Length::Fill).padding(16);
        container(column![header, text("PROTECTION WORKSPACE").size(13), input, output, security, actions, analysis_panel, status_panel].spacing(18).padding(36))
            .width(Length::Fill).height(Length::Fill).into()
    }
}

fn protected_output(input: &PathBuf) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("protected");
    parent.join(format!("{stem}.deobf"))
}
