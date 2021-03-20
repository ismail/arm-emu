# emu
qemu-{arm,aarch64,i386,x86_64} with custom sysroot support

### Building

emu should be statically built due to various reasons, best way is to build against musl target:

```
RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-unknown-linux-musl --release
sudo cp target/x86_64-unknown-linux-musl/release/emu /usr/bin/emu
```

### Setting it up
Now you can set it to handle ARMv7 and ARM64 executable via systemd binfmt support

```
> cat /etc/binfmt.d/arm.conf
:arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/emu:

> cat /etc/binfmt.d/arm64.conf
:aarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/emu:CF

# Make sure to restart systemd-binfmt
> systemctl restart systemd-binfmt
```
### Using an ARM{64} chroot

```
> file /usr/lib/sysroots/aarch64/usr/bin/bash
/usr/lib/sysroots/aarch64/usr/bin/bash: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=9e8979d09cbf65626b17cd0337987675a29e99f9,
for GNU/Linux 3.7.0, stripped

> sudo chroot /usr/lib/sysroots/aarch64/
bash-5.1#
```

### Running executables outside the chroot

Since executables have dependencies we need to set `EMU_SYSROOT` variable to a valid sysroot path first.

```
> export EMU_SYSROOT=/usr/lib/sysroots/aarch64
```

After that run it just as any executable:
```
> /usr/lib/sysroots/aarch64/usr/bin/bash
ismail@:/home/ismail>
```

### Creating ARM{64} sysroots

See https://github.com/ismail/hacks/blob/master/sysrooter.sh for a script for creating
openSUSE Tumbleweed based sysroot for ARM{64}.
