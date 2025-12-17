#![windows_subsystem = "windows"]

use std::fs::File;
use std::io::Write;

use process_spoofer::{spoof_arguments, spoof_ppid, apply_process_mitigation_policy, process_hollowing, get_current_filename};
use windows::{core::s, Win32::{Foundation::HWND, UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE}}};
use std::io::prelude::*;

fn main() {
    let filename = get_current_filename();
    if filename.contains("msedge.exe") {
        let mut file = File::create("C:\\temp\\foo.txt").expect("Could not create file");
        let _ = file.write_all(b"Hello, world!");
        return
    }
    //spoof_arguments();
    //spoof_ppid(6556);
    //apply_process_mitigation_policy();
    process_hollowing(filename);
}
