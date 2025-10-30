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
        self.thread_handle.join().expect("worker thread panicked")?;
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
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    let thread_id = unsafe { GetCurrentThreadId() };
    thread_id_atomic.store(thread_id, Ordering::Relaxed);

    // register keybinds
    for (i, key) in config::DISCONNECT_KEYBINDS.iter().enumerate() {
        unsafe {
            RegisterHotKey(HWND(0), i as _, HOT_KEY_MODIFIERS(0), key.0 as _)?;
        }
    }

    // message loop, ends on WM_QUIT
    let mut msg = MSG::default();
    while unsafe { GetMessageW(&mut msg, HWND(0), WM_NULL, WM_HOTKEY).as_bool() } {
        let hotkey_id = msg.wParam.0;

        match disconnect() {
            Err(e) => {
                println!("[DISCONNECT] error: {}", e.to_string());
                error_toast(e.to_string().as_str(), "during disconnect");
            }
            _ => {
                println!("[DISCONNECT]");
            }
        }

        // resend the key
        if let Some(k) = config::DISCONNECT_KEYBINDS.get(hotkey_id) {
            // un-register the hotkey to avoid recursion
            if unsafe { UnregisterHotKey(HWND(0), hotkey_id as _).is_ok() } {
                let _ = send_input_vk(*k);
                unsafe {
                    RegisterHotKey(HWND(0), hotkey_id as _, HOT_KEY_MODIFIERS(0), k.0 as _)?;
                }
            }
        }
    }
    // message loop ended, clean up

    // unregister keybinds
    for i in 0..config::DISCONNECT_KEYBINDS.len() {
        unsafe {
            UnregisterHotKey(HWND(0), i as _)?;
        }
    }

    Ok(())
}

fn send_input_vk(vk: windows::Win32::UI::Input::KeyboardAndMouse::VIRTUAL_KEY) -> MyResult<()> {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

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

    // SendInput returns number of events successfully inserted
    let sent = unsafe { SendInput(&mut inputs, size_of::<INPUT>() as i32) };
    if sent != inputs.len() as u32 {
        return Err("SendInput failed to send all events".into());
    }

    Ok(())
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
