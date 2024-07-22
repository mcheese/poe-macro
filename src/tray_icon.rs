// create and handle tray icon and its menu

use crate::helper::*;
use crate::HotkeyThread;
use tray_icon::{menu::*, Icon, TrayIcon, TrayIconBuilder};
use winit::event_loop::{ControlFlow, EventLoop};

pub struct MyTrayIcon {
    event_loop: EventLoop<()>,
    _tray_icon: TrayIcon,
}

impl MyTrayIcon {
    pub fn build() -> MyResult<Self> {
        let event_loop = EventLoop::builder().build()?;
        event_loop.set_control_flow(ControlFlow::Wait);

        let tray_menu = Menu::with_items(&[
            &MenuItem::with_id("cmd", "Toggle console", true, None),
            &MenuItem::with_id("exit", "Exit", true, None),
        ])?;

        let icon_bytes = include_bytes!("../icon32.rgba");
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip("POE-Macro")
            .with_icon(Icon::from_rgba(icon_bytes.to_vec(), 32, 32)?)
            .build()?;

        Ok(Self {
            event_loop,
            _tray_icon: tray_icon,
        })
    }

    pub fn run(self, hotkeys: HotkeyThread) -> MyResult<()> {
        let menu_channel = MenuEvent::receiver();
        let mut hotkeys = Some(hotkeys);
        #[allow(deprecated)]
        self.event_loop.run(move |_event, event_loop| {
            if let Ok(e) = menu_channel.try_recv() {
                match e.id.0.as_str() {
                    "exit" => {
                        println!("[exit]");
                        event_loop.exit();
                        if let Some(hk) = hotkeys.take() {
                            if let Err(e) = hk.stop() {
                                error_toast(e.to_string().as_str(), "in hotkey thread");
                            }
                        }
                    }
                    "cmd" => {
                        println!("[toogle cmd]");
                        unsafe {
                            use windows::Win32::System::Console::GetConsoleWindow;
                            use windows::Win32::UI::WindowsAndMessaging::*;
                            let cmd = GetConsoleWindow();
                            let _ = ShowWindow(
                                cmd,
                                SHOW_WINDOW_CMD(if IsWindowVisible(cmd).as_bool() { 0 } else { 1 }),
                            );
                        }
                    }
                    id => println!("{:?}", id),
                }
            }
        })?;

        Ok(())
    }
}
