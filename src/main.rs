use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::Command;
use std::str;

static ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

enum ELFClass {
    ELFCLASS32 = 1,
    ELFCLASS64,
}

enum Endian {
    Little = 1,
    Big,
}

#[derive(FromPrimitive)]
enum Machine {
    X86 = 3,
    ARM = 40,
    X86_64 = 62,
    AARCH64 = 183,
}

struct Executable {
    loader: String,
    class: ELFClass,
    machine: Machine,
}

fn unpack<const N: usize>(bytes: &[u8; N], endian: &Endian) -> u64 {
    let mut result: u64 = 0;

    match endian {
        Endian::Little => {
            for i in (0..N).rev() {
                result += (bytes[i] as u64) * (2u64.pow(i as u32 * 8))
            }
        }
        Endian::Big => {
            for i in 0..N {
                result += (bytes[i] as u64) * (2u64.pow((N as u32 - i as u32 - 1) * 8))
            }
        }
    }

    result
}

fn run_executable(executable: Executable, args: &[String]) -> Result<(), io::Error> {
    let qemu_suffix: &str;

    match executable.machine {
        Machine::AARCH64 => qemu_suffix = "aarch64",
        Machine::ARM => qemu_suffix = "arm",
        Machine::X86 => qemu_suffix = "i386",
        Machine::X86_64 => qemu_suffix = "x86_64",
    }

    let sysroot = env::var("EMU_SYSROOT").unwrap_or_default();
    if !sysroot.is_empty() {
        //println!("Sysroot: {}, Loader: {}", sysroot, executable.loader);

        if executable.loader.is_empty() {
            println!(
                "EMU_SYSROOT is set to {} but this executable defines no loader.",
                sysroot
            );
            println!("This can't work, please unset EMU_SYSROOT variable and re-run the command.");
            return Ok(());
        }

        // Sanity check
        let loader = format!("{}/{}", sysroot, executable.loader);
        if !Path::new(&loader).exists() {
            println!(
                "{}",
                format!(
                    "{} does not exist, {} is not setup correctly.",
                    executable.loader, sysroot
                )
            );
            return Ok(());
        }

        Command::new(format!("/usr/bin/qemu-{}", qemu_suffix))
            .arg(format!("{}/{}", sysroot, &executable.loader))
            .arg("--library-path")
            .arg(format!(
                "{root}/usr/lib{suffix}:{root}/lib{suffix}",
                root = sysroot,
                suffix = match executable.class {
                    ELFClass::ELFCLASS64 => "64",
                    _ => "",
                }
            ))
            .args(&args[1..])
            .status()
            .unwrap_or_else(|_| {
                panic!(
                    "Unable to run /usr/bin/qemu-{} using {} as sysroot.",
                    qemu_suffix, sysroot
                )
            });
    } else {
        // If there is no sysroot then the loader should exist in the filesystem.
        // Check that and error otherwise.

        if !executable.loader.is_empty() && !Path::new(&executable.loader).exists() {
            println!("{}", format!("{} does not exist, consider setting EMU_SYSROOT variable to a working sysroot path.", executable.loader));
            return Ok(());
        }

        Command::new(format!("/usr/bin/qemu-{}", qemu_suffix))
            .args(&args[1..])
            .status()
            .unwrap_or_else(|_| panic!("Unable to run /usr/bin/qemu-{}", qemu_suffix));
    }

    Ok(())
}

fn setup_executable(executable: &str) -> Result<Executable, io::Error> {
    let mut f = File::open(&executable)?;

    // https://man7.org/linux/man-pages/man5/elf.5.html
    //  #define EI_NIDENT 16

    // typedef struct {
    //      unsigned char e_ident[EI_NIDENT];
    //      uint16_t      e_type;
    //      uint16_t      e_machine;
    //      uint32_t      e_version;
    //      ElfN_Addr     e_entry; (uint32_t or uint64_t)
    //      ElfN_Off      e_phoff; (uint32_t or uint64_t)
    //      uint32_t      e_flags;
    //      uint16_t      e_ehsize;
    //      uint16_t      e_phentsize;
    //      uint16_t      e_phnum;
    //      uint16_t      e_shentsize;
    //      uint16_t      e_shnum;
    //      uint16_t      e_shstrndx;
    // } ElfN_Ehdr;

    let mut e_ident = [0; 16];

    // Read the elf magic
    f.read_exact(&mut e_ident)?;
    if e_ident[..4] != ELF_MAGIC {
        return Err(Error::new(
            ErrorKind::Other,
            format!("{} is not an ELF file.", executable),
        ));
    }

    // EI_CLASS
    let exec_class = match e_ident[4] {
        1 => ELFClass::ELFCLASS32,
        2 => ELFClass::ELFCLASS64,
        _ => return Err(Error::new(ErrorKind::Other, "Invalid ELF class.")),
    };

    // EI_DATA
    let exec_endian = match e_ident[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        _ => return Err(Error::new(ErrorKind::Other, "Unknown endianness.")),
    };

    // Read e_machine
    f.seek(SeekFrom::Start(18))?;
    let mut e_machine = [0; 2];
    f.read_exact(&mut e_machine)?;

    let machine_type_value: u16 = unpack::<2>(&e_machine, &exec_endian).try_into().unwrap();
    let exec_machine = match FromPrimitive::from_u16(machine_type_value) {
        Some(Machine::ARM) => Machine::ARM,
        Some(Machine::AARCH64) => Machine::AARCH64,
        Some(Machine::X86) => Machine::X86,
        Some(Machine::X86_64) => Machine::X86_64,
        None => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "{} is not an ARM, ARM64, x86 or x86_64 executable, machine type: {}",
                    executable, machine_type_value,
                ),
            ));
        }
    };

    let pheader_offset: u64;
    let pheader_size: u16;

    match exec_class {
        ELFClass::ELFCLASS32 => {
            let mut e_phoff = [0; 4];
            f.seek(SeekFrom::Start(28))?;
            f.read_exact(&mut e_phoff)?;
            pheader_offset = unpack::<4>(&e_phoff, &exec_endian);

            let mut e_phentsize = [0; 2];
            f.seek(SeekFrom::Current(10))?;
            f.read_exact(&mut e_phentsize)?;
            pheader_size = unpack::<2>(&e_phentsize, &exec_endian).try_into().unwrap();
        }
        ELFClass::ELFCLASS64 => {
            let mut e_phoff = [0; 8];
            f.seek(SeekFrom::Start(32))?;
            f.read_exact(&mut e_phoff)?;
            pheader_offset = unpack::<8>(&e_phoff, &exec_endian);

            let mut e_phentsize = [0; 2];
            f.seek(SeekFrom::Current(14))?;
            f.read_exact(&mut e_phentsize)?;
            pheader_size = unpack::<2>(&e_phentsize, &exec_endian).try_into().unwrap();
        }
    }

    let ph_num: u16;
    let mut e_phnum = [0; 2];
    f.read_exact(&mut e_phnum)?;
    ph_num = unpack::<2>(&e_phnum, &exec_endian).try_into().unwrap();

    // Traverse all program headers and find the type with PT_INTERP
    const PT_INTERP: u32 = 3;

    /*
    typedef struct {
        uint32_t   p_type;
        Elf32_Off  p_offset;
        Elf32_Addr p_vaddr;
        Elf32_Addr p_paddr;
        uint32_t   p_filesz;
        uint32_t   p_memsz;
        uint32_t   p_flags;
        uint32_t   p_align;
    } Elf32_Phdr;

    typedef struct {
        uint32_t   p_type;
        uint32_t   p_flags;
        Elf64_Off  p_offset;
        Elf64_Addr p_vaddr;
        Elf64_Addr p_paddr;
        uint64_t   p_filesz;
        uint64_t   p_memsz;
        uint64_t   p_align;
    } Elf64_Phdr;
    */

    f.seek(SeekFrom::Start(pheader_offset))?;
    let mut i = 0;
    let mut header_type: u32;
    let mut p_type = [0; 4];
    let mut exec_loader: String = String::new();

    while i < ph_num {
        f.read_exact(&mut p_type)?;

        header_type = unpack::<4>(&p_type, &exec_endian).try_into().unwrap();

        if header_type == PT_INTERP {
            match exec_class {
                ELFClass::ELFCLASS32 => {
                    let mut p_vaddr = [0; 4];
                    f.seek(SeekFrom::Current(4))?;
                    f.read_exact(&mut p_vaddr)?;
                    let virtual_addr: u32 = unpack::<4>(&p_vaddr, &exec_endian).try_into().unwrap();

                    let mut p_filesz = [0; 4];
                    let mut interpreter_size: u32;
                    f.seek(SeekFrom::Current(8))?;
                    f.read_exact(&mut p_filesz)?;
                    interpreter_size = unpack::<4>(&p_filesz, &exec_endian).try_into().unwrap();

                    // interpreter is null terminated
                    interpreter_size -= 1;

                    f.seek(SeekFrom::Start(virtual_addr as u64))?;
                    let mut interpreter: Vec<u8> = Vec::with_capacity(interpreter_size as usize);
                    f.take(interpreter_size as u64)
                        .read_to_end(&mut interpreter)?;

                    exec_loader = str::from_utf8(&interpreter).unwrap().to_string();
                    //println!("Loader: {}", exec_loader);
                }
                ELFClass::ELFCLASS64 => {
                    let mut p_vaddr = [0; 8];
                    f.seek(SeekFrom::Current(12))?;
                    f.read_exact(&mut p_vaddr)?;
                    let virtual_addr: u64 = unpack::<8>(&p_vaddr, &exec_endian);

                    let mut p_filesz = [0; 8];
                    let mut interpreter_size: u64;
                    f.seek(SeekFrom::Current(8))?;
                    f.read_exact(&mut p_filesz)?;
                    interpreter_size = unpack::<8>(&p_filesz, &exec_endian);

                    // interpreter is null terminated
                    interpreter_size -= 1;

                    f.seek(SeekFrom::Start(virtual_addr))?;
                    let mut interpreter: Vec<u8> = Vec::with_capacity(interpreter_size as usize);
                    f.take(interpreter_size).read_to_end(&mut interpreter)?;

                    exec_loader = str::from_utf8(&interpreter).unwrap().to_string();
                    //println!("Loader: {}", exec_loader);
                }
            }
            break;
        }

        f.seek(SeekFrom::Current((pheader_size as i64) - 4))?;
        i += 1;
    }

    let exec = Executable {
        loader: exec_loader,
        class: exec_class,
        machine: exec_machine,
    };

    Ok(exec)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} program <args>", args[0]);
        return;
    }

    let executable = setup_executable(&args[1]).unwrap();
    run_executable(executable, &args).unwrap();
}
