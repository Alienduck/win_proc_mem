// src/memory_scanner.rs

use windows_sys::Win32::{Foundation::HANDLE, System::Threading::*};

pub fn get_process(pid: u32) -> HANDLE {
    unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) }
}
