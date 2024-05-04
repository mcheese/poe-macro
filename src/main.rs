use std::error;
use windows::core::*;
use windows::Win32::Foundation::*;

// process image names to disconnect
// save as PCSTR to avoid converting later
const PROCESS_NAMES: &[PCSTR] = &[s!("PathOfExile.exe"), s!("PathOfExileSteam.exe")];

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

// exit with notification on error
macro_rules! report_error {
    ($e:expr) => {
        if let Err(err) = $e {
            error_and_exit(
                err.to_string(),
                format!(
                    "in: {} @ {}:{}:{}",
                    stringify!($e),
                    file!(),
                    line!(),
                    column!()
                ),
            );
        } else {
        }
    };
}

fn main() -> Result<()> {
    println!("hello");

    report_error!(enable_debug_priv());

    report_error!(disconnect());

    println!("goodbye");

    Ok(())
}

fn disconnect() -> Result<()> {
    let pids = find_pids()?;
    close_connections(&pids)?;
    Ok(())
}

// display notification and exit
fn error_and_exit(text1: String, text2: String) -> () {
    use winrt_notification::{Duration, Toast};
    Toast::new(Toast::POWERSHELL_APP_ID)
        .title("POE-Macro Error")
        .text1(text1.as_str())
        .text2(text2.as_str())
        .duration(Duration::Long)
        .show()
        .expect("notification failed");

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
