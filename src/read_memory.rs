// src/memory_scanner.rs

use std::collections::HashMap;
use windows_sys::Win32::{
    Foundation::{FALSE, HANDLE},
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_READONLY, PAGE_READWRITE, VirtualQueryEx,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

#[derive(Debug)]
pub enum ScannerError {
    ProcessFinished,
    InvalidAddress,
    MemoryAccessError,
    MemoryFree,
    ProcessNotFound,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
    pub state: u32,
    pub type_: u32,
}

impl MemoryRegion {
    pub fn is_readable(&self) -> bool {
        if self.state != MEM_COMMIT {
            return false;
        }

        self.protection
            & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
            != 0
    }

    pub fn is_writable(&self) -> bool {
        self.state == MEM_COMMIT && self.protection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE) != 0
    }
}

// LA STRUCTURE PRINCIPALE MANQUANTE
pub struct MemoryExploiter {
    pub process_handle: HANDLE,
    pub pid: u32,
    pub candidate_addresses: HashMap<String, Vec<usize>>,
    pub confirmed_addresses: HashMap<String, usize>,
}

impl MemoryExploiter {
    pub fn new(pid: u32) -> Result<Self, ScannerError> {
        let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };

        if process_handle == std::ptr::null_mut() {
            return Err(ScannerError::ProcessNotFound);
        }

        Ok(MemoryExploiter {
            process_handle,
            pid,
            candidate_addresses: HashMap::new(),
            confirmed_addresses: HashMap::new(),
        })
    }

    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion>, ScannerError> {
        let mut regions = Vec::new();
        let mut current_address: *const std::ffi::c_void = std::ptr::null();

        loop {
            let mut memory_info = MEMORY_BASIC_INFORMATION::default();
            let result = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    current_address,
                    &mut memory_info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                break;
            }

            regions.push(MemoryRegion {
                base_address: memory_info.BaseAddress as usize,
                size: memory_info.RegionSize,
                protection: memory_info.Protect,
                state: memory_info.State,
                type_: memory_info.Type,
            });

            // Passer à la région suivante
            let next_address = (memory_info.BaseAddress as usize) + memory_info.RegionSize;
            current_address = next_address as *const _;

            if current_address.is_null() || regions.len() > 10000 {
                break;
            }
        }

        Ok(regions)
    }

    // Lire de la mémoire à une adresse spécifique
    pub fn read_memory<T: Copy>(&self, address: usize) -> Result<T, ScannerError> {
        let size = std::mem::size_of::<T>();
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;

        let success = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                &mut bytes_read,
            )
        };

        if success == FALSE || bytes_read != size {
            return Err(ScannerError::MemoryAccessError);
        }

        Ok(unsafe { std::ptr::read(buffer.as_ptr() as *const T) })
    }

    // Lire de la mémoire brute (pour le scanning)
    pub fn read_raw_memory(&self, address: usize, buffer: &mut [u8]) -> Result<(), ScannerError> {
        let mut bytes_read = 0;

        let success = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                &mut bytes_read,
            )
        };

        if success == FALSE || bytes_read != buffer.len() {
            return Err(ScannerError::MemoryAccessError);
        }

        Ok(())
    }

    // SCANNER COMPLET - LA FONCTION QUE VOUS VOULIEZ
    pub fn full_memory_scan<T>(
        &mut self,
        target_value: T,
        scan_name: &str,
    ) -> Result<Vec<usize>, ScannerError>
    where
        T: Copy + PartialEq + std::fmt::Debug,
    {
        println!(
            "🔍 Début du scan mémoire complet pour {:?}...",
            target_value
        );

        let regions = self.get_memory_regions()?;
        let readable_regions: Vec<&MemoryRegion> =
            regions.iter().filter(|r| r.is_readable()).collect();

        println!(
            "📊 Scanning {} régions sur {}",
            readable_regions.len(),
            regions.len()
        );

        let mut all_found_addresses = Vec::new();

        for (i, region) in readable_regions.iter().enumerate() {
            print!(
                "📍 Région {}/{}: 0x{:x}-0x{:x}... ",
                i + 1,
                readable_regions.len(),
                region.base_address,
                region.base_address + region.size
            );

            let region_addresses = self.scan_region_for_value(region, target_value)?;
            println!("{} adresses", region_addresses.len());

            all_found_addresses.extend(region_addresses);

            // Éviter de trop surcharger
            if all_found_addresses.len() > 50_000 {
                println!("⚠️  Trop d'adresses, arrêt anticipé");
                break;
            }
        }

        // Sauvegarder les candidats
        self.candidate_addresses
            .insert(scan_name.to_string(), all_found_addresses.clone());

        println!(
            "🎉 Scan '{}' terminé: {} adresses trouvées",
            scan_name,
            all_found_addresses.len()
        );
        Ok(all_found_addresses)
    }

    // Scanner une région spécifique
    fn scan_region_for_value<T>(
        &self,
        region: &MemoryRegion,
        target_value: T,
    ) -> Result<Vec<usize>, ScannerError>
    where
        T: Copy + PartialEq + std::fmt::Debug,
    {
        let mut found_addresses = Vec::new();
        let value_size = std::mem::size_of::<T>();
        let step_size = 4.max(value_size); // Scanner par pas de 4 bytes minimum

        let chunk_size = 64 * 1024; // 64KB par chunk
        let region_end = region.base_address + region.size;
        let mut current_address = region.base_address;

        while current_address < region_end {
            let remaining = region_end - current_address;
            let current_chunk_size = remaining.min(chunk_size);

            let mut buffer = vec![0u8; current_chunk_size];
            if self.read_raw_memory(current_address, &mut buffer).is_ok() {
                // Scanner le buffer en mémoire locale
                for offset in (0..current_chunk_size.saturating_sub(value_size)).step_by(step_size)
                {
                    let address = current_address + offset;

                    if offset + value_size <= buffer.len() {
                        let value = unsafe {
                            std::ptr::read(buffer[offset..offset + value_size].as_ptr() as *const T)
                        };

                        if value == target_value {
                            found_addresses.push(address);
                        }
                    }
                }
            }

            current_address += current_chunk_size;
        }

        Ok(found_addresses)
    }

    // Affiner un scan existant
    pub fn refine_scan<T>(
        &mut self,
        scan_name: &str,
        new_value: T,
    ) -> Result<Vec<usize>, ScannerError>
    where
        T: Copy + PartialEq + std::fmt::Debug,
    {
        if let Some(candidates) = self.candidate_addresses.get(scan_name).cloned() {
            let mut refined = Vec::new();

            for &address in &candidates {
                if let Ok(value) = self.read_memory::<T>(address) {
                    if value == new_value {
                        refined.push(address);
                    }
                }
            }

            self.candidate_addresses
                .insert(scan_name.to_string(), refined.clone());
            println!(
                "🔎 Scan '{}' affiné: {} → {} adresses",
                scan_name,
                candidates.len(),
                refined.len()
            );

            Ok(refined)
        } else {
            println!("❌ Scan '{}' non trouvé", scan_name);
            Ok(Vec::new())
        }
    }
}

pub fn get_process(pid: u32) -> Result<MemoryExploiter, ScannerError> {
    MemoryExploiter::new(pid)
}
