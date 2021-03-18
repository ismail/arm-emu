use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().collect();

    match env::var("SYSROOT") {
        Ok(val) => {
            Command::new("/usr/bin/qemu-arm")
                .arg(format!("{}/lib/ld-linux-armhf.so.3", val))
                .arg("--library-path")
                .arg(format!("{root}/usr/lib:{root}/lib", root = val))
                .args(&args[1..])
                .spawn()
                .expect("Unable to run /usr/bin/qemu-arm");
        }
        Err(_val) => {
            Command::new("/usr/bin/qemu-arm")
                .args(&args[1..])
                .spawn()
                .expect("Unable to run /usr/bin/qemu-arm");
        }
    }
}
