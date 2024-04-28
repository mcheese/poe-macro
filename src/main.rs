use std::error;
use windows::core::*;
use windows::Win32::Foundation::*;

// process image names to disconnect
// saving names in cringe format instead of converting results later
const PROCESS_NAMES: &[PCSTR] = &[
    PCSTR("PathOfExile.exe\0".as_ptr()),
    PCSTR("PathOfExileSteam.exe\0".as_ptr()),
];

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

fn main() -> Result<()> {
    println!("hello");

    if let Err(err) = enable_debug_priv() {
        error_and_exit(format!("Enable Debug Privilege\n\n{}", err.to_string()));
    }

    if let Err(err) = disconnect() {
        error_and_exit(format!("Disconnecting\n\n{}", err.to_string()));
    }

    println!("goodbye");

    Ok(())
}

fn disconnect() -> Result<()> {
    let pids = find_pids()?;
    close_connections(&pids)?;
    Ok(())
}

// display and error messagebox and exit
fn error_and_exit(message: String) -> () {
    use windows::Win32::UI::WindowsAndMessaging::*;

    unsafe {
        MessageBoxA(None, PCSTR(message.as_ptr()), s!("POE-Macro"), MB_ICONERROR);
    }

    std::process::exit(-1);
}

// get all PIDs using a name from PROCESS_NAMES
fn find_pids() -> Result<Vec<u32>> {
    use std::mem::size_of;
    use windows::Win32::Globalization::lstrcmpA;
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
                if PROCESS_NAMES.iter().any(|&s| lstrcmpA(s, name) == 0) {
                    pids.push(process.th32ProcessID);
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    Ok(pids)
}

// close all connections of all passed PIDs
fn close_connections(pids: &[u32]) -> Result<()> {
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

fn enable_debug_priv() -> Result<()> {
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

    let privilege = "SeDebugPrivilege\0";

    unsafe {
        LookupPrivilegeValueA(
            PCSTR::null(),
            PCSTR(privilege.as_ptr()),
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
