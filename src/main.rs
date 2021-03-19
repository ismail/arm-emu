use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::process::Command;

static ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const ARM_MACHINE_TYPE: u16 = 40;

enum ELFClass {
    ELFCLASS32 = 1,
    ELFCLASS64,
}

fn handle_arm(args: &Vec<String>, elf_class: ELFClass) {
    let ld_suffix: &str;
    let lib_suffix: &str;
    let qemu_suffix: &str;
    let sysroot: &str = &env::var("SYSROOT").unwrap_or("".to_string());

    match elf_class {
        ELFClass::ELFCLASS32 => {
            ld_suffix = "armhf.so.3";
            lib_suffix = "";
            qemu_suffix = "arm"
        }
        ELFClass::ELFCLASS64 => {
            ld_suffix = "aarch64.so.1";
            qemu_suffix = "aarch64";
            lib_suffix = "64";
        }
    }

    if sysroot != "" {
        Command::new(format!("/usr/bin/qemu-{}", qemu_suffix))
            .arg(format!(
                "{}/lib{}/ld-linux-{}",
                sysroot, lib_suffix, ld_suffix
            ))
            .arg("--library-path")
            .arg(format!(
                "{root}/usr/lib{suffix}:{root}/lib{suffix}",
                root = sysroot,
                suffix = lib_suffix
            ))
            .args(&args[1..])
            .status()
            .expect(format!("Unable to run /usr/bin/qemu-{}", qemu_suffix).as_str());
    } else {
        Command::new(format!("/usr/bin/qemu-{}", qemu_suffix))
            .args(&args[1..])
            .status()
            .expect(format!("Unable to run /usr/bin/qemu-{}", qemu_suffix).as_str());
    }
}

fn get_elf_class(executable: &str) -> Result<ELFClass, io::Error> {
    let f = File::open(&executable)?;

    // https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
    // unsigned char   e_ident[16]
    // uint16_t        e_type;
    // uint16_t        e_machine;
    let mut buffer = [0; 16 + 2 + 2];
    let mut handle = f.take(16 + 2 + 2);

    handle.read(&mut buffer)?;

    if buffer[..4] != ELF_MAGIC {
        return Err(Error::new(
            ErrorKind::Other,
            format!("{} is not an ELF file.", executable),
        ));
    }

    let machine_type: u16 = buffer[18] as u16 + buffer[19] as u16 * 256;
    if machine_type != ARM_MACHINE_TYPE {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "{} is not an ARM executable, machine type: {}",
                executable, machine_type,
            ),
        ));
    }

    let elfclass = buffer[4];

    match elfclass {
        1 => return Ok(ELFClass::ELFCLASS32),
        2 => return Ok(ELFClass::ELFCLASS64),
        _ => return Err(Error::new(ErrorKind::Other, "Invalid ELF class.")),
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let elfclass = get_elf_class(&args[1]).unwrap();

    handle_arm(&args, elfclass);

    Ok(())
}
