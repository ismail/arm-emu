use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::process::Command;

static ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const ARM_MACHINE_TYPE: u16 = 40;

fn handle_aarch64(args: &Vec<String>) {
    match env::var("SYSROOT") {
        Ok(val) => {
            Command::new("/usr/bin/qemu-aarch64")
                .arg(format!("{}/lib64/ld-linux-aarch64.so.1", val))
                .arg("--library-path")
                .arg(format!("{root}/usr/lib64:{root}/lib64", root = val))
                .args(&args[1..])
                .status()
                .expect("Unable to run /usr/bin/qemu-aarch64");
        }
        Err(_val) => {
            Command::new("/usr/bin/qemu-aarch64")
                .args(&args[1..])
                .status()
                .expect("Unable to run /usr/bin/qemu-aarch64");
        }
    }
}

fn handle_armv7(args: &Vec<String>) {
    match env::var("SYSROOT") {
        Ok(val) => {
            Command::new("/usr/bin/qemu-arm")
                .arg(format!("{}/lib/ld-linux-armhf.so.3", val))
                .arg("--library-path")
                .arg(format!("{root}/usr/lib:{root}/lib", root = val))
                .args(&args[1..])
                .status()
                .expect("Unable to run /usr/bin/qemu-arm");
        }
        Err(_val) => {
            Command::new("/usr/bin/qemu-arm")
                .args(&args[1..])
                .status()
                .expect("Unable to run /usr/bin/qemu-arm");
        }
    }
}

fn get_elf_class(executable: &str) -> Result<u8, io::Error> {
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

    Ok(elfclass)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let elfclass = get_elf_class(&args[1]);

    match elfclass {
        Ok(v) => match v {
            1 => handle_armv7(&args),
            2 => handle_aarch64(&args),
            _ => {
                return Err(Error::new(ErrorKind::Other, format!("Invalid ELF class {}.", v)));
            }
        },
        Err(e) => return Err(e),
    }

    Ok(())
}
