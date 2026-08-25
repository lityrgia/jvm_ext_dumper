mod archive;
mod bytecode;

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

pub use archive::make_jar;
use bytecode::restore_bytecodes;

use super::{dictionary::DiscoveredClass, vmstructs::VmStructTable, vmtypes::VmTypes};

#[derive(Debug, Default)]
pub struct DumpReport {
    pub written: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

#[derive(Clone, Debug)]
enum Cp {
    Utf8(Vec<u8>),
    Integer(u32),
    Float(u32),
    Long(u64),
    Double(u64),
    Class(u16),
    String(u16),
    Ref(u8, u16, u16),
    NameType(u16, u16),
    MethodHandle(u8, u16),
    MethodType(u16),
    InvokeDynamic(u16, u16),
    Empty,
}

struct FieldOut {
    flags: u16,
    name: u16,
    descriptor: u16,
    generic: Option<u16>,
}

struct ExceptionOut {
    start_pc: u16,
    end_pc: u16,
    handler_pc: u16,
    catch_type: u16,
}

struct CodeOut {
    max_stack: u16,
    max_locals: u16,
    bytes: Vec<u8>,
    exceptions: Vec<ExceptionOut>,
    stack_map: Option<Vec<u8>>,
}

struct MethodOut {
    flags: u16,
    name: u16,
    descriptor: u16,
    generic: Option<u16>,
    code: Option<CodeOut>,
}

#[derive(Default)]
struct Layout {
    ik_constants: u64,
    ik_fields: u64,
    ik_field_count: u64,
    ik_methods: u64,
    ik_interfaces: u64,
    ik_major: u64,
    ik_minor: u64,
    ik_generic: u64,
    klass_flags: u64,
    klass_super: u64,
    klass_name: u64,
    cp_tags: u64,
    cp_length: u64,
    cp_size: u64,
    cp_cache: u64,
    cp_reference_map: u64,
    cp_operands: u64,
    symbol_len: u64,
    symbol_body: u64,
    array_len: u64,
    array_ptr_data: u64,
    method_const: u64,
    method_flags: u64,
    cm_name: u64,
    cm_sig: u64,
    cm_flags: u64,
    cm_code_size: u64,
    cm_size: u64,
    cm_max_stack: u64,
    cm_max_locals: u64,
    cm_stackmap: u64,
    cm_header_size: u64,
    cache_length: u64,
    cache_entry_indices: u64,
    cache_header_size: u64,
    cache_entry_size: u64,
}

pub fn dump_all<M: RemoteMemory>(
    memory: &M,
    classes: &[DiscoveredClass],
    vm: &VmStructTable,
    types: &VmTypes,
    output: &Path,
) -> DumpReport {
    let layout = match Layout::new(vm, types) {
        Ok(v) => v,
        Err(_) => {
            return DumpReport {
                written: 0,
                failed: classes.len(),
                failures: vec![
                    "HotSpot layout is missing required VMStructs/VMTypes entries".into(),
                ],
            };
        }
    };
    let mut report = DumpReport::default();
    for class in classes {
        match reconstruct(memory, class, &layout)
            .and_then(|bytes| write_class(output, &class.internal_name, &bytes))
        {
            Ok(()) => report.written += 1,
            Err(error) => {
                report.failed += 1;
                if report.failures.len() < 8 {
                    report
                        .failures
                        .push(format!("{}: {error:#}", class.internal_name));
                }
            }
        }
    }
    report
}

impl Layout {
    fn new(vm: &VmStructTable, types: &VmTypes) -> Result<Self> {
        let o = |t: &str, f: &str| {
            vm.find(t, f)
                .map(|e| e.offset)
                .with_context(|| format!("missing {t}::{f}"))
        };
        Ok(Self {
            ik_constants: o("InstanceKlass", "_constants")?,
            ik_fields: o("InstanceKlass", "_fields")?,
            ik_field_count: o("InstanceKlass", "_java_fields_count")?,
            ik_methods: o("InstanceKlass", "_methods")?,
            ik_interfaces: o("InstanceKlass", "_local_interfaces")?,
            ik_major: o("InstanceKlass", "_major_version")?,
            ik_minor: o("InstanceKlass", "_minor_version")?,
            ik_generic: o("InstanceKlass", "_generic_signature_index")?,
            klass_flags: o("Klass", "_access_flags")?,
            klass_super: o("Klass", "_super")?,
            klass_name: o("Klass", "_name")?,
            cp_tags: o("ConstantPool", "_tags")?,
            cp_length: o("ConstantPool", "_length")?,
            cp_size: types.size("ConstantPool")?,
            cp_cache: o("ConstantPool", "_cache")?,
            cp_reference_map: o("ConstantPool", "_reference_map")?,
            cp_operands: o("ConstantPool", "_operands")?,
            symbol_len: o("Symbol", "_length")?,
            symbol_body: o("Symbol", "_body")?,
            array_len: o("Array<Klass*>", "_length")?,
            array_ptr_data: o("Array<Klass*>", "_data[0]")?,
            method_const: o("Method", "_constMethod")?,
            method_flags: o("Method", "_access_flags")?,
            cm_name: o("ConstMethod", "_name_index")?,
            cm_sig: o("ConstMethod", "_signature_index")?,
            cm_flags: o("ConstMethod", "_flags")?,
            cm_code_size: o("ConstMethod", "_code_size")?,
            cm_size: o("ConstMethod", "_constMethod_size")?,
            cm_max_stack: o("ConstMethod", "_max_stack")?,
            cm_max_locals: o("ConstMethod", "_max_locals")?,
            cm_stackmap: o("ConstMethod", "_stackmap_data")?,
            cm_header_size: types.size("ConstMethod")?,
            cache_length: o("ConstantPoolCache", "_length")?,
            cache_entry_indices: o("ConstantPoolCacheEntry", "_indices")?,
            cache_header_size: types.size("ConstantPoolCache")?,
            cache_entry_size: types.size("ConstantPoolCacheEntry")?,
        })
    }
}

fn reconstruct<M: RemoteMemory>(m: &M, class: &DiscoveredClass, l: &Layout) -> Result<Vec<u8>> {
    let cp_addr = m.read_u64(class.klass + l.ik_constants)?;
    if cp_addr == 0 {
        bail!("null cp")
    }
    let mut cp = read_cp(m, cp_addr, l)?;
    let this = ensure_class(&mut cp, class.internal_name.as_bytes())?;
    let super_ptr = m.read_u64(class.klass + l.klass_super)?;
    let super_index = if super_ptr == 0 {
        0
    } else {
        let n = klass_name(m, super_ptr, l)?;
        ensure_class(&mut cp, &n)?
    };
    let interfaces = read_interfaces(m, m.read_u64(class.klass + l.ik_interfaces)?, l, &mut cp)?;
    let fields = read_fields(m, class.klass, l)?;
    let is_interface = (m.read_u32(class.klass + l.klass_flags)? as u16 & 0x0200) != 0;
    let methods = read_methods(m, class.klass, cp_addr, l, &cp, is_interface)?;
    let class_generic = nonzero(m.read_u16(class.klass + l.ik_generic)?);
    let bootstrap_methods = read_bootstrap_methods(m, cp_addr, l)?;
    let needs_code = methods.iter().any(|v| v.code.is_some());
    let needs_stackmap = methods
        .iter()
        .any(|v| v.code.as_ref().and_then(|c| c.stack_map.as_ref()).is_some());
    let needs_signature = class_generic.is_some()
        || fields.iter().any(|v| v.generic.is_some())
        || methods.iter().any(|v| v.generic.is_some());
    let code_name = needs_code
        .then(|| add_utf8(&mut cp, b"Code".to_vec()))
        .transpose()?;
    let stackmap_name = needs_stackmap
        .then(|| add_utf8(&mut cp, b"StackMapTable".to_vec()))
        .transpose()?;
    let signature_name = needs_signature
        .then(|| add_utf8(&mut cp, b"Signature".to_vec()))
        .transpose()?;
    let bootstrap_name = (!bootstrap_methods.is_empty())
        .then(|| add_utf8(&mut cp, b"BootstrapMethods".to_vec()))
        .transpose()?;
    let mut out = Vec::new();
    u4(&mut out, 0xcafebabe);
    u2(&mut out, m.read_u16(class.klass + l.ik_minor)?);
    u2(&mut out, m.read_u16(class.klass + l.ik_major)?);
    u2(&mut out, cp.len() as u16);
    for entry in cp.iter().skip(1) {
        write_cp(&mut out, entry)?;
    }
    u2(
        &mut out,
        (m.read_u32(class.klass + l.klass_flags)? as u16) & 0x7631,
    );
    u2(&mut out, this);
    u2(&mut out, super_index);
    u2(&mut out, interfaces.len() as u16);
    for v in interfaces {
        u2(&mut out, v)
    }
    u2(&mut out, fields.len() as u16);
    for field in fields {
        u2(&mut out, field.flags & 0x50df);
        u2(&mut out, field.name);
        u2(&mut out, field.descriptor);
        u2(&mut out, u16::from(field.generic.is_some()));
        if let Some(sig) = field.generic {
            write_signature(&mut out, signature_name.context("Signature CP entry")?, sig);
        }
    }
    u2(&mut out, methods.len() as u16);
    for method in methods {
        u2(&mut out, method.flags);
        u2(&mut out, method.name);
        u2(&mut out, method.descriptor);
        let attrs = u16::from(method.code.is_some()) + u16::from(method.generic.is_some());
        u2(&mut out, attrs);
        if let Some(code) = method.code {
            write_code(
                &mut out,
                code_name.context("Code CP entry")?,
                stackmap_name,
                code,
            )?;
        }
        if let Some(sig) = method.generic {
            write_signature(&mut out, signature_name.context("Signature CP entry")?, sig);
        }
    }
    u2(
        &mut out,
        u16::from(class_generic.is_some()) + u16::from(!bootstrap_methods.is_empty()),
    );
    if let Some(sig) = class_generic {
        write_signature(&mut out, signature_name.context("Signature CP entry")?, sig);
    }
    if !bootstrap_methods.is_empty() {
        write_bootstrap_methods(
            &mut out,
            bootstrap_name.context("BootstrapMethods CP entry")?,
            &bootstrap_methods,
        )?;
    }
    Ok(out)
}

fn read_cp<M: RemoteMemory>(m: &M, addr: u64, l: &Layout) -> Result<Vec<Cp>> {
    let len = m.read_u32(addr + l.cp_length)? as usize;
    if !(1..65500).contains(&len) {
        bail!("cp length")
    }
    let tags = m.read_u64(addr + l.cp_tags)?;
    if tags == 0 {
        bail!("null tags")
    };
    let mut tv = vec![0; len];
    m.read_exact(tags + 4, &mut tv)?;
    let mut cp = vec![Cp::Empty; len];
    let base = addr + l.cp_size;
    for i in 1..len {
        let tag = tv[i];
        let slot = base + i as u64 * 8;
        let raw = m.read_u64(slot)?;
        cp[i] = match tag {
            1 => Cp::Utf8(symbol(m, raw, l)?),
            3 => Cp::Integer(raw as u32),
            4 => Cp::Float(raw as u32),
            5 => Cp::Long(raw),
            6 => Cp::Double(raw),
            7 | 100 | 103 => {
                let name = if tag == 7 && raw > u32::MAX as u64 {
                    klass_name(m, raw, l)?
                } else if tag == 7 {
                    let idx = (raw & 0xffff) as u16;
                    cp_utf8(&cp, idx)?.to_vec()
                } else {
                    symbol(m, raw & !1_u64, l)?
                };
                let ni = add_utf8(&mut cp, name)?;
                Cp::Class(ni)
            }
            101 => Cp::Class(raw as u16),
            8 => {
                let ni = add_utf8(&mut cp, symbol(m, raw, l)?)?;
                Cp::String(ni)
            }
            102 => Cp::String(raw as u16),
            9..=11 => Cp::Ref(tag, raw as u16, (raw >> 16) as u16),
            12 => Cp::NameType(raw as u16, (raw >> 16) as u16),
            15 | 104 => Cp::MethodHandle(raw as u8, (raw >> 16) as u16),
            16 | 105 => Cp::MethodType(raw as u16),
            18 => Cp::InvokeDynamic(raw as u16, (raw >> 16) as u16),
            0 => Cp::Empty,
            _ => bail!("unsupported constant-pool tag {tag} at {i}"),
        };
    }
    if cp.len() > 65535 {
        bail!("cp overflow")
    }
    Ok(cp)
}

fn read_fields<M: RemoteMemory>(m: &M, k: u64, l: &Layout) -> Result<Vec<FieldOut>> {
    let count = m.read_u16(k + l.ik_field_count)? as usize;
    let a = m.read_u64(k + l.ik_fields)?;
    if count == 0 {
        return Ok(Vec::new());
    }
    if a == 0 {
        bail!("null fields")
    }
    let array_length = m.read_u32(a + l.array_len)? as usize;
    // The u2 array also contains JVM-injected fields. Generic signature
    // indices are packed after every six-slot FieldInfo, not merely after
    // `_java_fields_count` entries.
    let mut generic_base = array_length;
    let mut all_fields = 0usize;
    while all_fields.checked_mul(6).context("field table overflow")? < generic_base {
        let flags = m.read_u16(a + 4 + (all_fields * 12) as u64)?;
        if flags & 0x0800 != 0 {
            generic_base = generic_base
                .checked_sub(1)
                .context("field generic table underflow")?;
        }
        all_fields += 1;
    }
    if all_fields * 6 != generic_base || count > all_fields {
        bail!("malformed field table")
    }
    let mut generic_slot = generic_base;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let p = a + 4 + (i * 12) as u64;
        let raw_flags = m.read_u16(p)?;
        let generic = if raw_flags & 0x0800 != 0 {
            if generic_slot >= array_length {
                bail!("missing field generic signature")
            }
            let value = m.read_u16(a + 4 + (generic_slot * 2) as u64)?;
            generic_slot += 1;
            nonzero(value)
        } else {
            None
        };
        out.push(FieldOut {
            // Remove HotSpot-only watched/internal/stable/generic bits.
            flags: raw_flags & 0x50df,
            name: m.read_u16(p + 2)?,
            descriptor: m.read_u16(p + 4)?,
            generic,
        });
    }
    Ok(out)
}

fn read_methods<M: RemoteMemory>(
    m: &M,
    k: u64,
    cp_addr: u64,
    l: &Layout,
    cp: &[Cp],
    interface: bool,
) -> Result<Vec<MethodOut>> {
    let a = m.read_u64(k + l.ik_methods)?;
    if a == 0 {
        return Ok(Vec::new());
    };
    let count = m.read_u32(a + l.array_len)? as usize;
    if count > 65535 {
        bail!("methods")
    }
    let mut out = Vec::new();
    for i in 0..count {
        let method = m.read_u64(a + l.array_ptr_data + i as u64 * 8)?;
        if method == 0 {
            continue;
        }
        let cm = m.read_u64(method + l.method_const)?;
        if cm == 0 {
            continue;
        }
        let name = m.read_u16(cm + l.cm_name)?;
        let sig = m.read_u16(cm + l.cm_sig)?;
        cp_utf8(cp, name)?;
        let flags = m.read_u32(method + l.method_flags)? as u16 & 0x1dff;
        let cm_flags = m.read_u16(cm + l.cm_flags)?;
        let generic = if cm_flags & 0x0010 != 0 {
            nonzero(read_method_generic(m, cm, cm_flags, l)?)
        } else {
            None
        };
        let code = if flags & 0x0500 == 0 {
            Some(read_code(m, cm, cp_addr, cm_flags, l)?)
        } else {
            None
        };
        // Java 8 interfaces may contain static/default methods. Preserve all
        // declared methods; abstract/native methods correctly have no Code.
        let _ = interface;
        out.push(MethodOut {
            flags,
            name,
            descriptor: sig,
            generic,
            code,
        });
    }
    Ok(out)
}

fn read_code<M: RemoteMemory>(
    m: &M,
    cm: u64,
    cp: u64,
    cm_flags: u16,
    l: &Layout,
) -> Result<CodeOut> {
    let size = m.read_u16(cm + l.cm_code_size)? as usize;
    if size == 0 {
        bail!("concrete method has empty bytecode")
    }
    let mut bytes = vec![0; size];
    m.read_exact(cm + l.cm_header_size, &mut bytes)?;
    restore_bytecodes(m, cp, l, &mut bytes)?;
    let exceptions = read_exception_table(m, cm, cm_flags, l)?;
    let stack_map = read_u1_array(m, m.read_u64(cm + l.cm_stackmap)?, l)?;
    Ok(CodeOut {
        max_stack: m.read_u16(cm + l.cm_max_stack)?,
        max_locals: m.read_u16(cm + l.cm_max_locals)?,
        bytes,
        exceptions,
        stack_map,
    })
}

fn read_u1_array<M: RemoteMemory>(m: &M, addr: u64, l: &Layout) -> Result<Option<Vec<u8>>> {
    if addr == 0 {
        return Ok(None);
    }
    let len = m.read_u32(addr + l.array_len)? as usize;
    if len > 1 << 24 {
        bail!("oversized u1 array")
    }
    let mut out = vec![0; len];
    m.read_exact(addr + 4, &mut out)?;
    Ok(Some(out))
}

fn method_tail_cursor<M: RemoteMemory>(m: &M, cm: u64, flags: u16, l: &Layout) -> Result<u64> {
    let words = m.read_u32(cm + l.cm_size)? as u64;
    if words == 0 || words > 1 << 24 {
        bail!("invalid ConstMethod size")
    }
    let annotation_pointers =
        (flags >> 7 & 1) + (flags >> 8 & 1) + (flags >> 9 & 1) + (flags >> 10 & 1);
    Ok(cm + words * 8 - annotation_pointers as u64 * 8 - 2)
}

fn read_method_generic<M: RemoteMemory>(m: &M, cm: u64, flags: u16, l: &Layout) -> Result<u16> {
    m.read_u16(method_tail_cursor(m, cm, flags, l)?)
}

fn skip_tail_table<M: RemoteMemory>(m: &M, cursor: &mut u64, width_u2: u64) -> Result<()> {
    let len = m.read_u16(*cursor)? as u64;
    let bytes = len
        .checked_mul(width_u2)
        .and_then(|v| v.checked_mul(2))
        .context("ConstMethod tail overflow")?;
    *cursor = cursor
        .checked_sub(bytes + 2)
        .context("ConstMethod tail underflow")?;
    Ok(())
}

fn read_exception_table<M: RemoteMemory>(
    m: &M,
    cm: u64,
    flags: u16,
    l: &Layout,
) -> Result<Vec<ExceptionOut>> {
    if flags & 0x0008 == 0 {
        return Ok(Vec::new());
    }
    let mut cursor = method_tail_cursor(m, cm, flags, l)?;
    if flags & 0x0010 != 0 {
        cursor -= 2;
    }
    if flags & 0x0020 != 0 {
        skip_tail_table(m, &mut cursor, 2)?;
    }
    if flags & 0x0002 != 0 {
        skip_tail_table(m, &mut cursor, 1)?;
    }
    let count = m.read_u16(cursor)? as usize;
    if count > 65535 {
        bail!("oversized exception table")
    }
    let start = cursor
        .checked_sub(count as u64 * 8)
        .context("exception table underflow")?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let p = start + i as u64 * 8;
        out.push(ExceptionOut {
            start_pc: m.read_u16(p)?,
            end_pc: m.read_u16(p + 2)?,
            handler_pc: m.read_u16(p + 4)?,
            catch_type: m.read_u16(p + 6)?,
        });
    }
    Ok(out)
}

fn read_bootstrap_methods<M: RemoteMemory>(m: &M, cp: u64, l: &Layout) -> Result<Vec<Vec<u16>>> {
    let addr = m.read_u64(cp + l.cp_operands)?;
    if addr == 0 {
        return Ok(Vec::new());
    }
    let len = m.read_u32(addr + l.array_len)? as usize;
    if !(2..=65535).contains(&len) {
        bail!("invalid bootstrap operands")
    }
    let read = |index: usize| -> Result<u16> {
        if index >= len {
            bail!("bootstrap operand out of range")
        }
        m.read_u16(addr + 4 + index as u64 * 2)
    };
    let first_offset = read(0)? as usize | ((read(1)? as usize) << 16);
    if first_offset > len || first_offset & 1 != 0 {
        bail!("invalid bootstrap operand index")
    }
    let count = first_offset / 2;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let offset = read(i * 2)? as usize | ((read(i * 2 + 1)? as usize) << 16);
        let bsm = read(offset)?;
        let argc = read(offset + 1)? as usize;
        let mut entry = Vec::with_capacity(argc + 1);
        entry.push(bsm);
        for j in 0..argc {
            entry.push(read(offset + 2 + j)?);
        }
        out.push(entry);
    }
    Ok(out)
}

fn read_interfaces<M: RemoteMemory>(
    m: &M,
    a: u64,
    l: &Layout,
    cp: &mut Vec<Cp>,
) -> Result<Vec<u16>> {
    if a == 0 {
        return Ok(Vec::new());
    }
    let n = m.read_u32(a + l.array_len)? as usize;
    if n > 65535 {
        bail!("interfaces")
    }
    let mut v = Vec::new();
    for i in 0..n {
        let k = m.read_u64(a + l.array_ptr_data + i as u64 * 8)?;
        v.push(ensure_class(cp, &klass_name(m, k, l)?)?)
    }
    Ok(v)
}
fn klass_name<M: RemoteMemory>(m: &M, k: u64, l: &Layout) -> Result<Vec<u8>> {
    symbol(m, m.read_u64(k + l.klass_name)?, l)
}
fn symbol<M: RemoteMemory>(m: &M, s: u64, l: &Layout) -> Result<Vec<u8>> {
    if s == 0 {
        bail!("null symbol")
    }
    let n = m.read_u16(s + l.symbol_len)? as usize;
    let mut v = vec![0; n];
    m.read_exact(s + l.symbol_body, &mut v)?;
    Ok(v)
}
fn cp_utf8(cp: &[Cp], i: u16) -> Result<&[u8]> {
    match cp.get(i as usize) {
        Some(Cp::Utf8(v)) => Ok(v),
        _ => bail!("bad utf8 index {i}"),
    }
}
fn add_utf8(cp: &mut Vec<Cp>, v: Vec<u8>) -> Result<u16> {
    if let Some((i, _)) = cp
        .iter()
        .enumerate()
        .find(|(_, e)| matches!(e,Cp::Utf8(x)if*x==v))
    {
        return Ok(i as u16);
    }
    if cp.len() >= 65535 {
        bail!("cp full")
    }
    cp.push(Cp::Utf8(v));
    Ok((cp.len() - 1) as u16)
}
fn ensure_class(cp: &mut Vec<Cp>, name: &[u8]) -> Result<u16> {
    for (i, e) in cp.iter().enumerate() {
        if let Cp::Class(n) = e
            && cp_utf8(cp, *n).ok() == Some(name)
        {
            return Ok(i as u16);
        }
    }
    let n = add_utf8(cp, name.to_vec())?;
    if cp.len() >= 65535 {
        bail!("cp full")
    }
    cp.push(Cp::Class(n));
    Ok((cp.len() - 1) as u16)
}
fn write_cp(o: &mut Vec<u8>, e: &Cp) -> Result<()> {
    match e {
        Cp::Empty => {}
        Cp::Utf8(v) => {
            o.push(1);
            u2(o, v.len() as u16);
            o.extend(v)
        }
        Cp::Integer(v) => {
            o.push(3);
            u4(o, *v)
        }
        Cp::Float(v) => {
            o.push(4);
            u4(o, *v)
        }
        Cp::Long(v) => {
            o.push(5);
            u8(o, *v)
        }
        Cp::Double(v) => {
            o.push(6);
            u8(o, *v)
        }
        Cp::Class(v) => {
            o.push(7);
            u2(o, *v)
        }
        Cp::String(v) => {
            o.push(8);
            u2(o, *v)
        }
        Cp::Ref(t, a, b) => {
            o.push(*t);
            u2(o, *a);
            u2(o, *b)
        }
        Cp::NameType(a, b) => {
            o.push(12);
            u2(o, *a);
            u2(o, *b)
        }
        Cp::MethodHandle(k, i) => {
            o.push(15);
            o.push(*k);
            u2(o, *i)
        }
        Cp::MethodType(i) => {
            o.push(16);
            u2(o, *i)
        }
        Cp::InvokeDynamic(bootstrap, name_type) => {
            o.push(18);
            u2(o, *bootstrap);
            u2(o, *name_type)
        }
    }
    Ok(())
}

fn write_signature(out: &mut Vec<u8>, name: u16, signature: u16) {
    u2(out, name);
    u4(out, 2);
    u2(out, signature);
}

fn write_code(
    out: &mut Vec<u8>,
    name: u16,
    stackmap_name: Option<u16>,
    code: CodeOut,
) -> Result<()> {
    let mut body = Vec::new();
    u2(&mut body, code.max_stack);
    u2(&mut body, code.max_locals);
    u4(&mut body, code.bytes.len() as u32);
    body.extend(code.bytes);
    u2(&mut body, code.exceptions.len() as u16);
    for e in code.exceptions {
        u2(&mut body, e.start_pc);
        u2(&mut body, e.end_pc);
        u2(&mut body, e.handler_pc);
        u2(&mut body, e.catch_type);
    }
    u2(&mut body, u16::from(code.stack_map.is_some()));
    if let Some(stackmap) = code.stack_map {
        u2(&mut body, stackmap_name.context("StackMapTable CP entry")?);
        u4(&mut body, stackmap.len() as u32);
        body.extend(stackmap);
    }
    u2(out, name);
    u4(out, body.len() as u32);
    out.extend(body);
    Ok(())
}

fn write_bootstrap_methods(out: &mut Vec<u8>, name: u16, methods: &[Vec<u16>]) -> Result<()> {
    if methods.len() > 65535 {
        bail!("too many bootstrap methods")
    }
    let mut body = Vec::new();
    u2(&mut body, methods.len() as u16);
    for method in methods {
        let (&reference, args) = method.split_first().context("empty bootstrap method")?;
        u2(&mut body, reference);
        u2(&mut body, args.len() as u16);
        for &arg in args {
            u2(&mut body, arg);
        }
    }
    u2(out, name);
    u4(out, body.len() as u32);
    out.extend(body);
    Ok(())
}

fn nonzero(value: u16) -> Option<u16> {
    (value != 0).then_some(value)
}
fn write_class(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    if name.starts_with('/')
        || name.contains('\\')
        || name.split('/').any(|part| part == "." || part == "..")
    {
        bail!("unsafe class name");
    }
    let path = root.join(format!("{name}.class"));
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?
    }
    fs::write(path, bytes)?;
    Ok(())
}
fn u2(o: &mut Vec<u8>, v: u16) {
    o.extend(v.to_be_bytes())
}
fn u4(o: &mut Vec<u8>, v: u32) {
    o.extend(v.to_be_bytes())
}
fn u8(o: &mut Vec<u8>, v: u64) {
    o.extend(v.to_be_bytes())
}
