use std::{
    ffi::OsString,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStringExt,
};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::{
        Diagnostics::{
            Debug::ReadProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
            },
        },
        Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx},
        Threading::{
            GetCurrentProcess, GetProcessId, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        },
    },
};

use super::{MemoryRegion, ModuleInfo, RemoteMemory};

pub struct TargetProcess {
    pid: u32,
    handle: HANDLE,
}

impl TargetProcess {
    pub fn open_read_only(pid: u32) -> Result<Self> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error()).context("OpenProcess failed");
        }
        Ok(Self { pid, handle })
    }

    pub fn from_existing_handle(pid: u32, raw_handle: u64) -> Result<Self> {
        let source = raw_handle as usize as HANDLE;
        if source.is_null() || source == INVALID_HANDLE_VALUE {
            bail!("supplied HANDLE is NULL or INVALID_HANDLE_VALUE")
        }

        // Duplicate the caller-supplied handle so TargetProcess owns only its
        // private copy and never closes the operator's original handle.
        let current = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                current,
                source,
                current,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error()).context(
                "DuplicateHandle failed; the HANDLE must be valid in this process (usually inherited from its launcher)",
            );
        }

        let actual_pid = unsafe { GetProcessId(duplicate) };
        if actual_pid == 0 {
            unsafe { CloseHandle(duplicate) };
            return Err(std::io::Error::last_os_error())
                .context("GetProcessId failed for supplied HANDLE");
        }
        if actual_pid != pid {
            unsafe { CloseHandle(duplicate) };
            bail!("supplied HANDLE belongs to PID {actual_pid}, expected PID {pid}")
        }

        Ok(Self {
            pid,
            handle: duplicate,
        })
    }

    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error()).context("module snapshot failed");
        }
        let snapshot = OwnedHandle(snapshot);
        let mut entry: MODULEENTRY32W = unsafe { zeroed() };
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
        let mut modules = Vec::new();

        let mut found = unsafe { Module32FirstW(snapshot.0, &mut entry) } != 0;
        while found {
            modules.push(ModuleInfo {
                name: wide_c_string(&entry.szModule),
                base: entry.modBaseAddr as usize as u64,
                size: entry.modBaseSize as usize,
            });
            found = unsafe { Module32NextW(snapshot.0, &mut entry) } != 0;
        }
        Ok(modules)
    }

    pub fn readable_regions(&self) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        let mut address = 0usize;
        loop {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let read = unsafe {
                VirtualQueryEx(
                    self.handle,
                    address as *const _,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if read == 0 {
                break;
            }
            let base = info.BaseAddress as usize;
            let size = info.RegionSize;
            if info.State == MEM_COMMIT
                && info.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
                && size != 0
            {
                regions.push(MemoryRegion {
                    base: base as u64,
                    size,
                });
            }
            let Some(next) = base.checked_add(size) else {
                break;
            };
            if next <= address {
                break;
            }
            address = next;
        }
        Ok(regions)
    }
}

impl RemoteMemory for TargetProcess {
    fn read_exact(&self, address: u64, destination: &mut [u8]) -> Result<()> {
        let mut bytes_read = 0;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                address as usize as *const _,
                destination.as_mut_ptr().cast(),
                destination.len(),
                &mut bytes_read,
            )
        };
        if ok == 0 || bytes_read != destination.len() {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("ReadProcessMemory failed at 0x{address:016x}"));
        }
        Ok(())
    }
}

impl Drop for TargetProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub fn ensure_elevated() -> Result<()> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("OpenProcessToken failed");
    }
    let token = OwnedHandle(token);
    let mut elevation: TOKEN_ELEVATION = unsafe { zeroed() };
    let mut returned = 0;
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("GetTokenInformation failed");
    }
    if elevation.TokenIsElevated == 0 {
        bail!("administrator privileges are required; start CMD or PowerShell as Administrator");
    }
    Ok(())
}

fn wide_c_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    OsString::from_wide(&value[..length])
        .to_string_lossy()
        .into_owned()
}
