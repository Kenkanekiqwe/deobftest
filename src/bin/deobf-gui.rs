#![cfg_attr(windows, windows_subsystem = "windows")]

use deobf::{analyze_only, protect_file, run_protected, unprotect_file, EngineOptions, RuntimeKind};
use iced::widget::{button, column, container, pick_list, row, text, text_input};
use iced::{Element, Length, Task, Theme};
use rfd::FileDialog;
use std::path::PathBuf;

fn main() -> iced::Result {
    iced::application("DEOBF — Windows Protection Studio", App::update, App::view)
        .theme(|_| Theme::Dark)
        .window_size(iced::Size::new(1120.0, 780.0))
        .run_with(|| (App::default(), Task::none()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile { Safe, Balanced, Maximum }
impl Profile {
    const ALL: [Self; 3] = [Self::Safe, Self::Balanced, Self::Maximum];
    fn name(self) -> &'static str { match self { Self::Safe => "Safe", Self::Balanced => "Balanced", Self::Maximum => "Maximum" } }
    fn engine(self) -> &'static str { match self { Self::Safe => "safe", Self::Balanced => "balanced", Self::Maximum => "maximum" } }
}
impl std::fmt::Display for Profile { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.name()) } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunAs { Pe, Jar, Python }
impl RunAs {
    const ALL: [Self; 3] = [Self::Pe, Self::Jar, Self::Python];
    fn kind(self) -> RuntimeKind { match self { Self::Pe => RuntimeKind::Pe, Self::Jar => RuntimeKind::Jar, Self::Python => RuntimeKind::Python } }
}
impl std::fmt::Display for RunAs { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(match self { Self::Pe => "Windows EXE", Self::Jar => "Java JAR", Self::Python => "Python" }) } }

#[derive(Default)]
struct App {
    input: String,
    output: String,
    password: String,
    profile: Option<Profile>,
    run_as: Option<RunAs>,
    interpreter: String,
    analysis: String,
    status: String,
    busy: bool,
}

#[derive(Debug, Clone)]
enum Message {
    PickInput, PickOutput, InputChanged(String), OutputChanged(String), PasswordChanged(String),
    ProfileChanged(Profile), RunAsChanged(RunAs), InterpreterChanged(String), Analyze, Protect, Restore, Run,
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PickInput => {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.input = path.display().to_string();
                    self.analysis.clear();
                    if self.output.is_empty() { self.output = protected_output(&path).display().to_string(); }
                    self.status = "File selected. Run Analyze before protection.".into();
                }
            }
            Message::PickOutput => if let Some(path) = FileDialog::new().save_file() { self.output = path.display().to_string(); },
            Message::InputChanged(v) => self.input = v,
            Message::OutputChanged(v) => self.output = v,
            Message::PasswordChanged(v) => self.password = v,
            Message::ProfileChanged(v) => self.profile = Some(v),
            Message::RunAsChanged(v) => self.run_as = Some(v),
            Message::InterpreterChanged(v) => self.interpreter = v,
            Message::Analyze => self.analyze(),
            Message::Protect => self.protect(),
            Message::Restore => self.restore(),
            Message::Run => self.run(),
        }
        Task::none()
    }

    fn analyze(&mut self) {
        match std::fs::read(&self.input).map_err(|e| e.to_string()).and_then(|d| analyze_only(&d).map_err(|e| format!("{e:#}"))) {
            Ok(a) => self.analysis = format!("Type: {}\nArchitecture: {}\nExecutable: {}\nDebug markers: {}\nArchive: {}", a.kind, a.architecture, a.executable, a.has_debug_markers, a.has_archive_signature),
            Err(e) => self.analysis = format!("Analysis failed: {e}"),
        }
        self.status = "Analysis complete.".into();
    }

    fn protect(&mut self) {
        if self.password.len() < 12 { self.status = "Password must contain at least 12 characters.".into(); return; }
        if self.input.is_empty() || self.output.is_empty() { self.status = "Choose input and output.".into(); return; }
        self.busy = true;
        let profile = self.profile.unwrap_or(Profile::Balanced);
        let result = protect_file(&PathBuf::from(&self.input), &PathBuf::from(&self.output), self.password.as_bytes(), &EngineOptions { profile: profile.engine().into(), verify: true, add_integrity: true });
        self.status = match result { Ok(r) => format!("Protected package created. {} → {} bytes. Authenticated encryption + integrity enabled.", r.input_size, r.output_size), Err(e) => format!("Protection failed: {e:#}") };
        self.busy = false;
    }

    fn restore(&mut self) {
        if self.password.len() < 12 { self.status = "Password must contain at least 12 characters.".into(); return; }
        if self.input.is_empty() || self.output.is_empty() { self.status = "Choose package and restore output.".into(); return; }
        self.busy = true;
        self.status = match unprotect_file(&PathBuf::from(&self.input), &PathBuf::from(&self.output), self.password.as_bytes()) { Ok(()) => "Authenticated payload restored successfully.".into(), Err(e) => format!("Restore failed: {e:#}") };
        self.busy = false;
    }

    fn run(&mut self) {
        if self.password.len() < 12 { self.status = "Password must contain at least 12 characters.".into(); return; }
        if self.input.is_empty() { self.status = "Choose a .deobf package.".into(); return; }
        self.busy = true;
        let kind = self.run_as.unwrap_or(RunAs::Pe);
        let interpreter = if self.interpreter.trim().is_empty() { None } else { Some(self.interpreter.trim()) };
        let result = run_protected(&PathBuf::from(&self.input), self.password.as_bytes(), kind.kind(), interpreter, &[]);
        self.status = match result { Ok(status) => format!("Protected {} process exited with {status}.", kind), Err(e) => format!("Runtime failed: {e:#}") };
        self.busy = false;
    }

    fn view(&self) -> Element<'_, Message> {
        let profile = self.profile.unwrap_or(Profile::Balanced);
        let run_as = self.run_as.unwrap_or(RunAs::Pe);
        let header = row![column![text("DEOBF").size(40), text("Windows Protection Studio").size(16)].spacing(2), container(text(if self.busy { "WORKING" } else { "READY" })).padding(8)].spacing(24).align_y(iced::Alignment::Center);
        let input = row![text_input("Input file or .deobf package", &self.input).on_input(Message::InputChanged).width(Length::Fill), button(text("Browse")).on_press(Message::PickInput)].spacing(10);
        let output = row![text_input("Output file", &self.output).on_input(Message::OutputChanged).width(Length::Fill), button(text("Save as")).on_press(Message::PickOutput)].spacing(10);
        let settings = row![column![text("Protection"), pick_list(&Profile::ALL[..], Some(profile), Message::ProfileChanged).width(Length::Fill)].spacing(6).width(Length::Fill), column![text("Password"), text_input("Minimum 12 characters", &self.password).secure(true).on_input(Message::PasswordChanged)].spacing(6).width(Length::Fill)].spacing(18);
        let runtime = row![column![text("Run protected as"), pick_list(&RunAs::ALL[..], Some(run_as), Message::RunAsChanged).width(Length::Fill)].spacing(6).width(Length::Fill), column![text("Interpreter (JAR/Python)"), text_input("java / python", &self.interpreter).on_input(Message::InterpreterChanged)].spacing(6).width(Length::Fill)].spacing(18);
        let actions = row![button(text("Analyze")).on_press(Message::Analyze), button(text("Protect")).on_press(Message::Protect), button(text("Restore")).on_press(Message::Restore), button(text("Run protected")).on_press(Message::Run)].spacing(10);
        let analysis = container(column![text("ANALYSIS").size(13), text(if self.analysis.is_empty() { "No file analyzed yet." } else { &self.analysis })].spacing(8)).width(Length::Fill).padding(18);
        let status = container(text(&self.status).size(14)).width(Length::Fill).padding(16);
        container(column![header, text("PROTECTION WORKSPACE").size(13), input, output, settings, runtime, actions, analysis, status].spacing(16).padding(32)).width(Length::Fill).height(Length::Fill).into()
    }
}

fn protected_output(input: &PathBuf) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("protected");
    parent.join(format!("{stem}.deobf"))
}
