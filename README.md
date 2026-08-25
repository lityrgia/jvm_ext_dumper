# JVM External Class Dumper

External class dumper written in Rust for JVM HotSpot 8.

Run it as Administrator and enter the PID of a Java process:

```text
JVM External Dumper · HotSpot 8

Target PID: <your pid>
```

## How it works 🎈

The dumper reads HotSpot metadata from the target process. It first uses
exported `gHotSpotVMStructs` and `gHotSpotVMTypes`; if exports are stripped, it
searches for the internal tables. If those tables are also unavailable, it uses
a validated structural heuristic starting from the `java/lang/Object` `Symbol`
and follows `ConstantPool`/`InstanceKlass` relationships. Reconstructed classes
are written directly to `classes.jar`.

## Build ♟️

```bash
git clone https://github.com/lityrgia/jvm_ext_dumper.git
cd jvm_ext_dumper
cargo build --release
```
