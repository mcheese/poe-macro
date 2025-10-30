#![windows_subsystem = "windows"]

mod config;
mod helper;
mod tray_icon;

use helper::*;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::UI::Input::KeyboardAndMouse::*;

fn main() {
    exit_on_error!(run());
}

fn run() -> MyResult<()> {
    // alloc new console and hide it, to allow toggle later
    unsafe {
        use windows::Win32::System::Console::*;
        use windows::Win32::UI::WindowsAndMessaging::*;
        AllocConsole()?;
        ShowWindow(GetConsoleWindow(), SHOW_WINDOW_CMD(0));
    }

    println!("POE-Macro");

    // permission needed to disconnect
    exit_on_error!(enable_debug_priv());

    let tray_icon = tray_icon::MyTrayIcon::build()?;
    let hotkey_thread = HotkeyThread::build()?;

    info_toast("Running!", "");

    exit_on_error!(tray_icon.run(hotkey_thread));

    info_toast("Closing!", "bye");

    Ok(())
}

struct HotkeyThread {
    thread_id: Arc<AtomicU32>,
    thread_handle: std::thread::JoinHandle<windows::core::Result<()>>,
}

impl HotkeyThread {
    fn build() -> MyResult<Self> {
        let thread_id = Arc::new(AtomicU32::new(0));
        let thread_handle = {
            let thread_id_clone = thread_id.clone();
            std::thread::spawn(move || hotkey_thread(thread_id_clone))
        };

        Ok(Self {
            thread_id,
            thread_handle,
        })
    }

    fn stop(self) -> MyResult<()> {
        post_quit_message(self.thread_id.load(Ordering::Relaxed))?;
        match self.thread_handle.join() {
            Ok(res) => res?,
            Err(_) => return Err("worker thread panicked".into()),
        }
        Ok(())
    }
}

fn post_quit_message(thread_id: u32) -> MyResult<()> {
    use windows::Win32::UI::WindowsAndMessaging::*;

    if thread_id == 0 {
        return Err("invalid thread ID".into());
    }

    unsafe {
        PostThreadMessageA(thread_id, WM_QUIT, WPARAM::default(), LPARAM::default())?;
    };

    Ok(())
}

fn hotkey_thread(thread_id_atomic: Arc<AtomicU32>) -> windows::core::Result<()> {
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::*;

    let thread_id = unsafe { GetCurrentThreadId() };
    thread_id_atomic.store(thread_id, Ordering::Relaxed);

    let first_text_macro_id = config::DISCONNECT_KEYBINDS.len();

    // register keybinds
    for (i, key) in config::DISCONNECT_KEYBINDS.iter().enumerate() {
        unsafe {
            RegisterHotKey(HWND(0), i as _, HOT_KEY_MODIFIERS(0), key.0 as _)?;
        }
    }
    for (i, (key, _)) in config::TEXT_MACROS.iter().enumerate() {
        unsafe {
            RegisterHotKey(
                HWND(0),
                (i + first_text_macro_id) as _,
                HOT_KEY_MODIFIERS(0),
                key.0 as _,
            )?;
        }
    }

    // message loop, ends on WM_QUIT
    let mut msg = MSG::default();
    while unsafe { GetMessageW(&mut msg, HWND(0), WM_NULL, WM_HOTKEY).as_bool() } {
        if msg.message != WM_HOTKEY {
            continue;
        }

        let hotkey_id = msg.wParam.0;

        if hotkey_id < first_text_macro_id {
            match disconnect() {
                Err(e) => {
                    println!("[DISCONNECT] error: {}", e.to_string());
                    error_toast(e.to_string().as_str(), "during disconnect");
                }
                _ => {
                    println!("[DISCONNECT]");
                }
            }
        } else {
            if window_is_poe() {
                if let Some((_, text)) = config::TEXT_MACROS.get(hotkey_id - first_text_macro_id) {
                    send_command(text);
                    println!("[COMMAND] {}", text);
                }
            } else {
                println!("[COMMAND] skipped, POE not focused");
            }
        }

        // resend the key
        if let Some(k) = if hotkey_id < first_text_macro_id {
            config::DISCONNECT_KEYBINDS.get(hotkey_id)
        } else {
            config::TEXT_MACROS
                .get(hotkey_id - first_text_macro_id)
                .map(|(k, _)| k)
        } {
            // un-register the hotkey to avoid recursion
            if unsafe { UnregisterHotKey(HWND(0), hotkey_id as _).is_ok() } {
                send_input_vk(*k);
                unsafe {
                    RegisterHotKey(HWND(0), hotkey_id as _, HOT_KEY_MODIFIERS(0), k.0 as _)?;
                }
            }
        }
    }
    // message loop ended, clean up

    // unregister keybinds
    for (i, _) in config::DISCONNECT_KEYBINDS.iter().enumerate() {
        unsafe {
            _ = UnregisterHotKey(HWND(0), i as _);
        }
    }
    for (i, _) in config::TEXT_MACROS.iter().enumerate() {
        unsafe {
            _ = UnregisterHotKey(HWND(0), (i + first_text_macro_id) as _);
        }
    }

    Ok(())
}

fn send_command(text: &str) {
    send_input_vk(VK_RETURN);
    for ch in text.chars() {
        match char_to_vk(ch) {
            None => println!("[COMMAND] unsupported char: {}", ch),
            Some(vk) => send_input_vk(vk),
        }
    }
    send_input_vk(VK_RETURN);
}

fn window_is_poe() -> bool {
    use windows::Win32::Globalization::lstrcmpiA;
    use windows::Win32::UI::WindowsAndMessaging::*;

    let fg_window = unsafe { GetForegroundWindow() };
    if fg_window.0 == 0 {
        return false;
    } else {
        let mut buf: [u8; 256] = [0; 256];
        let len = unsafe { GetWindowTextA(fg_window, &mut buf) };
        buf[255] = 0; // ensure null termination
        return len > 0 && unsafe { lstrcmpiA(PCSTR(buf.as_ptr()), config::POE_WINDOW_TITLE) == 0 };
    }
}

fn char_to_vk(ch: char) -> Option<VIRTUAL_KEY> {
    match ch {
        'a' | 'A' => Some(VK_A),
        'b' | 'B' => Some(VK_B),
        'c' | 'C' => Some(VK_C),
        'd' | 'D' => Some(VK_D),
        'e' | 'E' => Some(VK_E),
        'f' | 'F' => Some(VK_F),
        'g' | 'G' => Some(VK_G),
        'h' | 'H' => Some(VK_H),
        'i' | 'I' => Some(VK_I),
        'j' | 'J' => Some(VK_J),
        'k' | 'K' => Some(VK_K),
        'l' | 'L' => Some(VK_L),
        'm' | 'M' => Some(VK_M),
        'n' | 'N' => Some(VK_N),
        'o' | 'O' => Some(VK_O),
        'p' | 'P' => Some(VK_P),
        'q' | 'Q' => Some(VK_Q),
        'r' | 'R' => Some(VK_R),
        's' | 'S' => Some(VK_S),
        't' | 'T' => Some(VK_T),
        'u' | 'U' => Some(VK_U),
        'v' | 'V' => Some(VK_V),
        'w' | 'W' => Some(VK_W),
        'x' | 'X' => Some(VK_X),
        'y' | 'Y' => Some(VK_Y),
        'z' | 'Z' => Some(VK_Z),
        '0' => Some(VK_0),
        '1' => Some(VK_1),
        '2' => Some(VK_2),
        '3' => Some(VK_3),
        '4' => Some(VK_4),
        '5' => Some(VK_5),
        '6' => Some(VK_6),
        '7' => Some(VK_7),
        '8' => Some(VK_8),
        '9' => Some(VK_9),
        ' ' => Some(VK_SPACE),
        '/' => Some(VK_OEM_2), // US layout
        '.' => Some(VK_OEM_PERIOD),
        ',' => Some(VK_OEM_COMMA),
        ';' => Some(VK_OEM_1),
        '\'' => Some(VK_OEM_7),
        '[' => Some(VK_OEM_4),
        ']' => Some(VK_OEM_6),
        '\\' => Some(VK_OEM_5),
        '-' => Some(VK_OEM_MINUS),
        '=' => Some(VK_OEM_PLUS),
        _ => None,
    }
}

fn send_input_vk(vk: VIRTUAL_KEY) {
    // key down
    let down = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: KEYBD_EVENT_FLAGS(0),
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };

    // key up
    let up = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0,
                dwFlags: KEYEVENTF_KEYUP,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };

    let mut inputs = [down, up];

    _ = unsafe { SendInput(&mut inputs, size_of::<INPUT>() as i32) };
}

fn disconnect() -> MyResult<()> {
    let pids = find_pids()?;
    close_connections(&pids)?;
    Ok(())
}

// get all PIDs using a name from PROCESS_NAMES
fn find_pids() -> MyResult<Vec<u32>> {
    use std::mem::size_of;
    use windows::Win32::Globalization::lstrcmpiA;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    let mut pids: Vec<u32> = vec![];

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut process = PROCESSENTRY32::default();
        process.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut process).is_ok() {
            while Process32Next(snapshot, &mut process).is_ok() {
                let name = PCSTR(process.szExeFile.as_ptr() as _);
                // using windows compare function to avoid reencoding the string
                if config::PROCESS_NAMES
                    .iter()
                    .any(|&s| lstrcmpiA(s, name) == 0)
                {
                    pids.push(process.th32ProcessID);
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    Ok(pids)
}

// close all connections of all passed PIDs
fn close_connections(pids: &[u32]) -> MyResult<()> {
    use windows::Win32::{NetworkManagement::IpHelper::*, System::Memory::*};

    unsafe {
        // get TCP table
        let mut bytes_required: u32 = 32000; // ~2000 bytes while testing, overshoot it
        let mut buffer = LocalAlloc(LPTR, bytes_required as _)?;
        let mut err = GetTcpTable2(Some(buffer.0 as *mut _), &mut bytes_required, false);

        // retry getting table with adjusted size
        if err == ERROR_INSUFFICIENT_BUFFER.0 {
            _ = LocalFree(buffer);
            buffer = LocalAlloc(LPTR, bytes_required as _)?;
            err = GetTcpTable2(Some(buffer.0 as *mut _), &mut bytes_required, false);
        }

        if err != 0 {
            return Err(std::io::Error::from_raw_os_error(err as i32).into());
        }

        // cast around to get correct size row array
        let header = &*(buffer.0 as *const MIB_TCPTABLE2);
        let rows = std::slice::from_raw_parts(header.table.as_ptr(), header.dwNumEntries as _);

        for row in rows {
            // look for pid
            if pids.contains(&row.dwOwningPid) {
                // create equivalent row with state = DELETE_TCB
                // need to create new row because we need a different type
                let changed_row = MIB_TCPROW_LH {
                    Anonymous: MIB_TCPROW_LH_0 {
                        State: MIB_TCP_STATE_DELETE_TCB,
                    },
                    dwLocalAddr: row.dwLocalAddr,
                    dwLocalPort: row.dwLocalPort,
                    dwRemoteAddr: row.dwRemoteAddr,
                    dwRemotePort: row.dwRemotePort,
                };

                // set the connection row, changing state to DELETE_TCB, closing connection
                SetTcpEntry(&changed_row);
            }
        }

        _ = LocalFree(buffer);
    }

    Ok(())
}

// Enables the SeDebugPrivilege for the current process, allowing it to debug and manipulate other processes.
fn enable_debug_priv() -> MyResult<()> {
    use std::mem::size_of;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: LUID::default(),
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        LookupPrivilegeValueA(
            PCSTR::null(),
            s!("SeDebugPrivilege"),
            &mut tp.Privileges[0].Luid,
        )?;

        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;

        AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            size_of::<TOKEN_PRIVILEGES>() as _,
            None,
            None,
        )?;

        CloseHandle(token)?;
    }

    Ok(())
}
