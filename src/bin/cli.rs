use clap::Parser;
use inquire::{Select, Text};
use std::ffi::{OsString, c_void};
use std::fmt;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::{
    Foundation::*,
    System::Diagnostics::Debug::*,
    System::{Memory::*, ProcessStatus::*, Threading::*},
};

/// Args of the command line
#[derive(Parser)]
struct Args {
    /// Name of the process target
    #[arg(short, long)]
    process_name: String,
}

/// Type of the memory scan
#[derive(Debug, Clone, Copy, PartialEq)]
enum ScanType {
    I32,
    I64,
    F32,
    F64,
}

/// Implementation of typing display
impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanType::I32 => write!(f, "i32 (Entier 4 octets)"),
            ScanType::I64 => write!(f, "i64 (Entier 8 octets)"),
            ScanType::F32 => write!(f, "f32 (Float - Vie/Munitions)"),
            ScanType::F64 => write!(f, "f64 (Double précision)"),
        }
    }
}

impl ScanType {
    /// Return the size in bytes of the selected type
    fn size(&self) -> usize {
        match self {
            ScanType::I32 => 4,
            ScanType::I64 => 8,
            ScanType::F32 => 4,
            ScanType::F64 => 8,
        }
    }

    /// Try to parse a string in a vector of bytes
    fn parse_input_to_bytes(&self, input: &str) -> Result<Vec<u8>, String> {
        match self {
            ScanType::I32 => input
                .parse::<i32>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|_| "Ce n'est pas un i32 valide".to_string()),
            ScanType::I64 => input
                .parse::<i64>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|_| "Ce n'est pas un i64 valide".to_string()),
            ScanType::F32 => input
                .parse::<f32>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|_| "Ce n'est pas un f32 valide".to_string()),
            ScanType::F64 => input
                .parse::<f64>()
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|_| "Ce n'est pas un f64 valide".to_string()),
        }
    }
}

/// Convert a table of u16 (Wide Char Windows) in String Rust
fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
        .to_string_lossy()
        .into_owned()
}

/// Find the PID of a process with his name (with or without .exe)
fn find_pid_by_name(name: &str) -> Option<u32> {
    let mut processes = [0u32; 1024];
    let mut needed = 0u32;
    unsafe {
        EnumProcesses(
            processes.as_mut_ptr(),
            (processes.len() * 4) as u32,
            &mut needed,
        )
        .ok()?;
    }
    let count = needed as usize / 4;

    for &pid in &processes[..count] {
        if pid == 0 {
            continue;
        }
        let handle_res =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) };
        let handle = match handle_res {
            Ok(h) => h,
            Err(_) => continue,
        };
        if handle.is_invalid() {
            continue;
        }

        let mut name_buf = [0u16; 260];
        let size = unsafe { GetModuleBaseNameW(handle, HMODULE::default(), &mut name_buf) };
        unsafe {
            let _ = CloseHandle(handle);
        };

        if size > 0 {
            let proc_name = wide_to_string(&name_buf);
            if proc_name.eq_ignore_ascii_case(name)
                || proc_name.eq_ignore_ascii_case(&format!("{}.exe", name))
            {
                return Some(pid);
            }
        }
    }
    None
}

fn main() {
    let args = Args::parse();

    let pid = match find_pid_by_name(&args.process_name) {
        Some(pid) => pid,
        None => {
            println!("Processus introuvable.");
            return;
        }
    };
    println!("PID ciblé : {}", pid);

    let access_rights =
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    let handle = match unsafe { OpenProcess(access_rights, false, pid) } {
        Ok(res) => res,
        Err(_) => {
            println!("Impossible d'ouvrir le processus (Droits Admin requis ?).");
            return;
        }
    };

    let mut found_addresses: Vec<usize> = Vec::new();
    let mut is_first_scan = true;

    let scan_types = vec![ScanType::I32, ScanType::F32, ScanType::I64, ScanType::F64];
    let current_type = Select::new("Quel type de données scanner ?", scan_types)
        .prompt()
        .unwrap_or(ScanType::I32);

    println!("Scanner configuré pour : {:?}", current_type);

    loop {
        let prompt_msg = if is_first_scan {
            format!(
                "Premier Scan ({:?}) - Entrez la valeur exacte :",
                current_type
            )
        } else {
            format!(
                "Next Scan ({:?} | {} adresses) - Valeur, 'write', 'reset', 'debug' :",
                current_type,
                found_addresses.len()
            )
        };

        let input = Text::new(&prompt_msg).prompt();

        let input_str = match input {
            Ok(s) => s,
            Err(_) => break, // Handle ESC or ^+C
        };
        let command = input_str.trim();

        if command.eq_ignore_ascii_case("q") || command.eq_ignore_ascii_case("quit") {
            break;
        }
        if command.eq_ignore_ascii_case("reset") {
            found_addresses.clear();
            is_first_scan = true;
            println!("Scanner réinitialisé.");
            continue;
        }
        if command.eq_ignore_ascii_case("debug") && !is_first_scan {
            if found_addresses.is_empty() {
                println!("La liste est vide.");
                continue;
            }
            println!("Aperçu des 5 premières adresses :");
            for &addr in found_addresses.iter().take(5) {
                let mut buffer = vec![0u8; current_type.size()];
                let mut read = 0;
                let status = unsafe {
                    ReadProcessMemory(
                        handle,
                        addr as *const _,
                        buffer.as_mut_ptr() as _,
                        buffer.len(),
                        Some(&mut read),
                    )
                };
                println!(
                    "Addr 0x{:X} -> ReadOk: {:?}, Bytes: {:?}",
                    addr,
                    status.is_ok(),
                    buffer
                );
            }
            continue;
        }

        if command.eq_ignore_ascii_case("write") {
            if found_addresses.is_empty() {
                println!("Aucune adresse trouvée pour écrire.");
                continue;
            }

            let val_input = Text::new("Nouvelle valeur à injecter :").prompt();
            if let Ok(val) = val_input {
                if let Ok(bytes) = current_type.parse_input_to_bytes(val.trim()) {
                    let mut count = 0;
                    for &addr in &found_addresses {
                        let mut written = 0;
                        if unsafe {
                            WriteProcessMemory(
                                handle,
                                addr as *const _,
                                bytes.as_ptr() as *const _,
                                bytes.len(),
                                Some(&mut written),
                            )
                        }
                        .is_ok()
                        {
                            count += 1;
                        }
                    }
                    println!("Succès : écrit sur {} adresses.", count);
                } else {
                    println!("Format de valeur incorrect.");
                }
            }
            continue;
        }

        // If not a command, try to scan the value
        let target_bytes = match current_type.parse_input_to_bytes(command) {
            Ok(b) => b,
            Err(_) => {
                println!("Commande inconnue ou format numérique invalide.");
                continue;
            }
        };

        if is_first_scan {
            println!("Scan complet de la mémoire en cours...");
            let mut address = 0usize;
            let type_size = current_type.size();

            loop {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                if unsafe {
                    VirtualQueryEx(
                        handle,
                        Some(address as *const c_void),
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                } == 0
                {
                    break;
                }

                let is_good = mbi.State == MEM_COMMIT
                    && (mbi.Protect & PAGE_NOACCESS == PAGE_PROTECTION_FLAGS(0))
                    && (mbi.Protect & PAGE_GUARD == PAGE_PROTECTION_FLAGS(0));

                if is_good {
                    let mut buffer = vec![0u8; mbi.RegionSize];
                    let mut read = 0;
                    if unsafe {
                        ReadProcessMemory(
                            handle,
                            mbi.BaseAddress,
                            buffer.as_mut_ptr() as _,
                            buffer.len(),
                            Some(&mut read),
                        )
                    }
                    .is_ok()
                        && read > 0
                    {
                        for i in (0..read.saturating_sub(type_size)).step_by(4) {
                            if &buffer[i..i + type_size] == target_bytes.as_slice() {
                                found_addresses.push((address + i) as usize);
                            }
                        }
                    }
                }

                let next = address.saturating_add(mbi.RegionSize);
                if next <= address {
                    break;
                }
                address = next;
            }
            is_first_scan = false;
            println!("Scan terminé. {} adresses trouvées.", found_addresses.len());
        } else {
            let initial_count = found_addresses.len();
            let type_size = current_type.size();

            found_addresses.retain(|&addr| {
                let mut buffer = vec![0u8; type_size];
                let mut read = 0;
                let res = unsafe {
                    ReadProcessMemory(
                        handle,
                        addr as *const _,
                        buffer.as_mut_ptr() as _,
                        type_size,
                        Some(&mut read),
                    )
                };

                if res.is_ok() && read == type_size {
                    return buffer == target_bytes;
                }
                false
            });

            println!(
                "Filtrage terminé : {} -> {} adresses restantes.",
                initial_count,
                found_addresses.len()
            );
        }
    }

    unsafe {
        let _ = CloseHandle(handle);
    };
}
