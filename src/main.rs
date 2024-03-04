use std::error;
use windows::core::PCSTR;
use windows::Win32::Foundation::*;

// process image names to disconnect
// saving names in cringe format instead of converting results later
const PROCESS_NAMES: &[PCSTR] = &[
    PCSTR::from_raw("PathOfExile.exe\0".as_ptr()),
    PCSTR::from_raw("PathOfExileSteam.exe\0".as_ptr()),
];

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

fn main() -> Result<()> {
    println!("hello");

    if !enable_debug_priv() {
        println!("failed to set SeDebugPrivilege");
    }

    let pids = find_pids();
    close_connections(&pids)?;

    println!("goodbye");

    Ok(())
}

// get all PIDs using a name from PROCESS_NAMES
fn find_pids() -> Vec<u32> {
    use std::mem::size_of;
    use std::mem::zeroed;
    use windows::Win32::Globalization::lstrcmpA;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    let mut pids: Vec<u32> = vec![];

    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();

        let mut process = zeroed::<PROCESSENTRY32>();
        process.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h, &mut process).is_ok() {
            loop {
                if Process32Next(h, &mut process).is_ok() {
                    let name = PCSTR::from_raw(process.szExeFile.as_ptr() as _);
                    // using windows compare function to avoid reencoding the string
                    if PROCESS_NAMES.iter().any(|&s| lstrcmpA(s, name) == 0) {
                        pids.push(process.th32ProcessID);
                    }
                } else {
                    break;
                }
            }
        }

        let _ = CloseHandle(h);
    }

    pids
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

fn enable_debug_priv() -> bool {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut h: HANDLE = HANDLE(0);
        let _ = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut h,
        );

        let la = LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 0,
                HighPart: 0,
            },
            Attributes: SE_PRIVILEGE_ENABLED,
        };

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [la],
        };

        let privilege = "SeDebugPrivilege\0";

        let mut ret = false;

        if LookupPrivilegeValueA(
            PCSTR(null_mut()),
            PCSTR(privilege.as_ptr()),
            &mut tp.Privileges[0].Luid,
        )
        .is_ok()
        {
            if AdjustTokenPrivileges(
                h,
                BOOL(0),
                Some(&tp),
                size_of::<TOKEN_PRIVILEGES>() as _,
                None,
                None,
            )
            .is_ok()
            {
                ret = true;
            }
        }
        let _ = CloseHandle(h);

        ret
    }
}
