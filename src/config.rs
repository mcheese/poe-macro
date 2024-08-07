// config values
//  - TODO: use actual config file

use windows::core::{s, PCSTR};
use windows::Win32::UI::Input::KeyboardAndMouse::*;

// disconnect bindings as Virtual-Key Codes
//  https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
pub const DISCONNECT_KEYBINDS: &'static [VIRTUAL_KEY] = &[
    VK_OEM_3, // `~ Key
    VK_OEM_5, // \| Key (same button as VK_OEM_3 on german layout)
];

// process image names to disconnect
// save as PCSTR to avoid converting later
pub const PROCESS_NAMES: &'static [PCSTR] = &[
    s!("PathOfExile.exe"),      // standalone
    s!("PathOfExileSteam.exe"), // steam
];
