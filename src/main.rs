use num_enum::TryFromPrimitive;
use std::convert::TryFrom;

use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::Path;
use std::process::Command;
use std::str;

static ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
enum ELFClass {
    ELFCLASS32 = 1,
    ELFCLASS64,
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
enum Endian {
    Little = 1,
    Big,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
enum Machine {
    X86 = 3,
    PPC64 = 21,
    S390 = 22,
    ARM = 40,
    X86_64 = 62,
    AARCH64 = 183,
    RISCV = 243,
}

struct Executable {
    class: ELFClass,
    endian: Endian,
    loader: String,
    machine: Machine,
}

macro_rules! unpack {
    ($bytes:expr, $inttype:ty, $endian:expr) => {
        match $endian {
            Endian::Little => <$inttype>::from_le_bytes($bytes),
            Endian::Big => <$inttype>::from_be_bytes($bytes),
        }
    };
}

fn run_executable(executable: Executable, args: &[String]) {
    let qemu_suffix: &str = match executable.machine {
        Machine::AARCH64 => "aarch64",
        Machine::ARM => "arm",
        Machine::PPC64 => match executable.endian {
            Endian::Big => "ppc64",
            Endian::Little => "ppc64le",
        },
        Machine::RISCV => match executable.class {
            ELFClass::ELFCLASS32 => "riscv32",
            ELFClass::ELFCLASS64 => "riscv64",
        },
        Machine::S390 => match executable.class {
            ELFClass::ELFCLASS32 => "s390",
            ELFClass::ELFCLASS64 => "s390x",
        },
        Machine::X86 => "i386",
        Machine::X86_64 => "x86_64",
    };

    // On Ubuntu executables are named as qemu-<arch>-static
    let mut static_suffix: &str = "";
    let qemu_static_path = format!("/usr/bin/qemu-{}-static", qemu_suffix);
    if Path::new(&qemu_static_path).exists() {
        static_suffix = "-static";
    }

    let sysroot = env::var("EMU_SYSROOT").unwrap_or_default();
    if !sysroot.is_empty() {
        //println!("Sysroot: {}, Loader: {}", sysroot, executable.loader);

        if executable.loader.is_empty() {
            panic!(
                "EMU_SYSROOT is set to {} but this executable defines no loader.\n \
                This can't work, please unset EMU_SYSROOT variable and re-run the command.",
                sysroot
            );
        }

        // Sanity check
        let loader = format!("{}/{}", sysroot, executable.loader);
        if !Path::new(&loader).exists() {
            panic!(
                "{} does not exist, {} is not setup correctly.",
                loader, sysroot
            );
        }
        println!("Loader: {:?}", loader);

        Command::new(format!("/usr/bin/qemu-{}{}", qemu_suffix, static_suffix))
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
                    "Unable to run /usr/bin/qemu-{}{} using {} as sysroot.",
                    qemu_suffix, static_suffix, sysroot
                )
            });
    } else {
        // If there is no sysroot then the loader should exist in the filesystem.
        // Check that and error otherwise.

        if !executable.loader.is_empty() && !Path::new(&executable.loader).exists() {
            panic!("{}", format!("{} does not exist, consider setting EMU_SYSROOT variable to a working sysroot path.", executable.loader));
        }

        Command::new(format!("/usr/bin/qemu-{}{}", qemu_suffix, static_suffix))
            .args(&args[1..])
            .status()
            .unwrap_or_else(|_| {
                panic!(
                    "Unable to run /usr/bin/qemu-{}{}",
                    qemu_suffix, static_suffix
                )
            });
    }
}

fn setup_executable(executable: &str) -> Result<Executable, io::Error> {
    let mut f = File::open(&executable)?;

    // https://man7.org/linux/man-pages/man5/elf.5.html
    //  #define EI_NIDENT 16

    /*
       typedef struct {
       unsigned char e_ident[EI_NIDENT];
            uint16_t      e_type;
            uint16_t      e_machine;
            uint32_t      e_version;
            ElfN_Addr     e_entry;
            ElfN_Off      e_phoff;
            ElfN_Off      e_shoff;
            uint32_t      e_flags;
            uint16_t      e_ehsize;
            uint16_t      e_phentsize;
            uint16_t      e_phnum;
            uint16_t      e_shentsize;
            uint16_t      e_shnum;
            uint16_t      e_shstrndx;
        } ElfN_Ehdr;
    */

    let mut e_ident = [0; 16];

    // Read the elf magic
    f.read_exact(&mut e_ident)?;
    if e_ident[..4] != ELF_MAGIC {
        panic!("{} is not an ELF file.", executable);
    }

    // EI_CLASS
    let exec_class = ELFClass::try_from(e_ident[4]).unwrap_or_else(|_| {
        panic!("Invalid ELF class.");
    });

    // EI_DATA
    let exec_endian = Endian::try_from(e_ident[5]).unwrap_or_else(|_| {
        panic!("Unknown endianness.");
    });

    // Skip e_type
    f.seek(SeekFrom::Current(2))?;
    let mut e_machine = [0; 2];
    f.read_exact(&mut e_machine)?;

    let machine_type_value: u16 = unpack!(e_machine, u16, &exec_endian);
    let exec_machine = Machine::try_from(machine_type_value).unwrap_or_else(|_| {
        panic!(
            "{} is not a supported executable, machine type: {}",
            executable, machine_type_value
        )
    });

    let sheader_offset: u64;
    let sheader_size: u16;

    match exec_class {
        ELFClass::ELFCLASS32 => {
            let mut e_shoff = [0; 4];
            // Skip e_version + e_entry + e_phoff
            f.seek(SeekFrom::Current(4 + 4 + 4))?;
            f.read_exact(&mut e_shoff)?;
            sheader_offset = unpack!(e_shoff, u32, &exec_endian).into();

            let mut e_shentsize = [0; 2];
            // Skip e_flags + e_ehsize + e_phentsize + e_phnum
            f.seek(SeekFrom::Current(4 + 2 + 2 + 2))?;
            f.read_exact(&mut e_shentsize)?;
            sheader_size = unpack!(e_shentsize, u16, &exec_endian);
        }
        ELFClass::ELFCLASS64 => {
            let mut e_shoff = [0; 8];
            // Skip e_version + e_entry + e_phoff
            f.seek(SeekFrom::Current(4 + 8 + 8))?;
            f.read_exact(&mut e_shoff)?;
            sheader_offset = unpack!(e_shoff, u64, &exec_endian);

            let mut e_shentsize = [0; 2];
            // Skip e_flags + e_ehsize + e_phentsize + e_phnum
            f.seek(SeekFrom::Current(4 + 2 + 2 + 2))?;
            f.read_exact(&mut e_shentsize)?;
            sheader_size = unpack!(e_shentsize, u16, &exec_endian);
        }
    }

    let sh_num: u16;
    let mut e_shnum = [0; 2];
    f.read_exact(&mut e_shnum)?;
    sh_num = unpack!(e_shnum, u16, &exec_endian);

    /*
     typedef struct {
        uint32_t   sh_name;
        uint32_t   sh_type;
        uint32_t   sh_flags;
        Elf32_Addr sh_addr;
        Elf32_Off  sh_offset;
        uint32_t   sh_size;
        uint32_t   sh_link;
        uint32_t   sh_info;
        uint32_t   sh_addralign;
        uint32_t   sh_entsize;
      } Elf32_Shdr;

      typedef struct {
        uint32_t   sh_name;
        uint32_t   sh_type;
        uint64_t   sh_flags;
        Elf64_Addr sh_addr;
        Elf64_Off  sh_offset;
        uint64_t   sh_size;
        uint32_t   sh_link;
        uint32_t   sh_info;
        uint64_t   sh_addralign;
        uint64_t   sh_entsize;
        } Elf64_Shdr;
    */

    f.seek(SeekFrom::Start(sheader_offset))?;
    let mut i = 0;
    let mut header_type: u32;
    let mut sh_type = [0; 4];
    let mut exec_loader: String = String::new();

    // Look for sh_type == SHT_PROGBITS
    const SHT_PROGBITS: u32 = 1;

    while i < sh_num {
        // Skip sh_name
        f.seek(SeekFrom::Current(4))?;
        f.read_exact(&mut sh_type)?;

        header_type = unpack!(sh_type, u32, &exec_endian);

        if header_type == SHT_PROGBITS {
            match exec_class {
                ELFClass::ELFCLASS32 => {
                    let mut sh_offset = [0; 4];
                    // Skip sh_flags + sh_addr
                    f.seek(SeekFrom::Current(4 + 4))?;
                    f.read_exact(&mut sh_offset)?;
                    let offset: u32 = unpack!(sh_offset, u32, &exec_endian);

                    let mut sh_size = [0; 4];
                    let mut interpreter_size: u32;
                    f.read_exact(&mut sh_size)?;
                    interpreter_size = unpack!(sh_size, u32, &exec_endian);

                    // interpreter is null terminated
                    interpreter_size -= 1;

                    f.seek(SeekFrom::Start(offset as u64))?;
                    let mut interpreter: Vec<u8> = Vec::with_capacity(interpreter_size as usize);
                    f.take(interpreter_size as u64)
                        .read_to_end(&mut interpreter)?;

                    exec_loader = str::from_utf8(&interpreter).unwrap().to_string();
                    //println!("Loader: {}", exec_loader);
                }
                ELFClass::ELFCLASS64 => {
                    let mut sh_offset = [0; 8];
                    // Skip sh_flags + sh_addr
                    f.seek(SeekFrom::Current(8 + 8))?;
                    f.read_exact(&mut sh_offset)?;
                    let offset: u64 = unpack!(sh_offset, u64, &exec_endian);

                    let mut sh_size = [0; 8];
                    let mut interpreter_size: u64;
                    f.read_exact(&mut sh_size)?;
                    interpreter_size = unpack!(sh_size, u64, &exec_endian);

                    // interpreter is null terminated
                    interpreter_size -= 1;

                    f.seek(SeekFrom::Start(offset))?;
                    let mut interpreter: Vec<u8> = Vec::with_capacity(interpreter_size as usize);
                    f.take(interpreter_size).read_to_end(&mut interpreter)?;

                    exec_loader = str::from_utf8(&interpreter).unwrap().to_string();
                    //println!("Loader: {}", exec_loader);
                }
            }
            break;
        }

        // Already read sh_name and sh_type
        f.seek(SeekFrom::Current((sheader_size as i64) - 4 - 4))?;
        i += 1;
    }

    let exec = Executable {
        class: exec_class,
        endian: exec_endian,
        loader: exec_loader,
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
    run_executable(executable, &args);
}
