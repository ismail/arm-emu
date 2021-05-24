# emu
qemu-{arm,aarch64,i386,ppc64{le},riscv{32,64},s390x,x86_64} with custom sysroot support

### Building

emu should be statically built due to various reasons, best way is to build against musl target:

```
RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-unknown-linux-musl --release
sudo cp target/x86_64-unknown-linux-musl/release/emu /usr/bin/emu
```

### Setting it up
Now you can set it to handle ARMv7 and ARM64 executable via systemd binfmt support


```
# cp binfmt.d/*.conf /etc/binfmt.d
# systemctl restart systemd-binfmt
```
### Using a chroot

```
> file /usr/lib/sysroots/aarch64/usr/bin/bash
/usr/lib/sysroots/aarch64/usr/bin/bash: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=9e8979d09cbf65626b17cd0337987675a29e99f9,
for GNU/Linux 3.7.0, stripped

> sudo chroot /usr/lib/sysroots/aarch64/
bash-5.1#
```

### Running executables outside the chroot (the main use case)

Since executables have dependencies we need to set `EMU_SYSROOT` variable to a valid sysroot path first.

```
> export EMU_SYSROOT=/usr/lib/sysroots/aarch64
```

After that run it just as any executable:
```
> /usr/lib/sysroots/aarch64/usr/bin/bash
ismail@:/home/ismail>
```

### Creating sysroots

See https://github.com/ismail/hacks/blob/master/sysrooter.sh for a script for creating
openSUSE Leap/Tumbleweed based sysroots.
