use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process::Command;

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

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let f = File::open(&args[1])?;

    // unsigned char   e_ident[16];
    // uint16_t        e_type;
    // uint16_t        e_machine;
    let mut buffer = [0; 16 + 2 + 2];
    let mut handle = f.take(16 + 2 + 2);
    let elf_magic: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

    handle.read(&mut buffer)?;

    assert_eq!(elf_magic, buffer[..4], "{} is not an ELF file.", &args[1]);

    let machine_type: u8 = buffer[18] as u8;
    if machine_type != 40 {
        panic!(
            "{} is not an ARM executable, machine type: {}",
            &args[1], machine_type
        );
    }

    let elfclass: u8 = buffer[4] as u8;

    match elfclass {
        1 => handle_armv7(&args),
        2 => handle_aarch64(&args),
        _ => {
            panic!("Invalid ELF class.");
        }
    }

    Ok(())
}
