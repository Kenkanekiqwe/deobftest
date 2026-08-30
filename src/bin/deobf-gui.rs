#![cfg_attr(windows, windows_subsystem = "windows")]

use iced::widget::{button, column, container, row, text, text_input};
use iced::{Element, Length, Task, Theme};
use std::path::PathBuf;

fn main() -> iced::Result {
    iced::application("Deobf — Windows Protection", App::update, App::view)
        .theme(|_| Theme::Dark)
        .window_size(iced::Size::new(980.0, 680.0))
        .run_with(|| (App::default(), Task::none()))
}

#[derive(Default)]
struct App {
    input: String,
    output: String,
    password: String,
    status: String,
    busy: bool,
}

#[derive(Debug, Clone)]
enum Message {
    InputChanged(String),
    OutputChanged(String),
    PasswordChanged(String),
    Protect,
    Unprotect,
    Inspect,
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::InputChanged(v) => self.input = v,
            Message::OutputChanged(v) => self.output = v,
            Message::PasswordChanged(v) => self.password = v,
            Message::Protect => {
                self.busy = true;
                self.status = "Protection requested. Core integration is next.".into();
                self.busy = false;
            }
            Message::Unprotect => {
                self.busy = true;
                self.status = "Unprotection requested. Core integration is next.".into();
                self.busy = false;
            }
            Message::Inspect => {
                let p = PathBuf::from(&self.input);
                self.status = if p.exists() {
                    format!("Ready: {}", p.display())
                } else {
                    "Select an existing input file.".into()
                };
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let header = column![
            text("DEOBF").size(36),
            text("Windows protection workspace").size(16),
        ]
        .spacing(4);

        let files = column![
            text("INPUT FILE").size(13),
            text_input("C:\\path\\to\\file", &self.input).on_input(Message::InputChanged),
            text("OUTPUT FILE").size(13),
            text_input("C:\\path\\to\\protected.deobf", &self.output)
                .on_input(Message::OutputChanged),
        ]
        .spacing(10);

        let security = column![
            text("PASSWORD").size(13),
            text_input("Password", &self.password)
                .secure(true)
                .on_input(Message::PasswordChanged),
            text("Format: authenticated DEOBF container • Windows target").size(13),
        ]
        .spacing(10);

        let actions = row![
            button(text("Protect")).on_press(Message::Protect),
            button(text("Unprotect")).on_press(Message::Unprotect),
            button(text("Inspect")).on_press(Message::Inspect),
        ]
        .spacing(12);

        let status = container(text(&self.status).size(14))
            .width(Length::Fill)
            .padding(18);

        container(
            column![header, files, security, actions, status]
                .spacing(26)
                .padding(42),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
}
