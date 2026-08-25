use anyhow::{Context, Result, bail};

use crate::platform::RemoteMemory;

use super::Layout;

fn cache_cp_index<M: RemoteMemory>(
    memory: &M,
    constant_pool: u64,
    cache_index: u32,
    layout: &Layout,
) -> Result<u16> {
    let cache = memory.read_u64(constant_pool + layout.cp_cache)?;
    if cache == 0 {
        bail!("rewritten bytecode without ConstantPoolCache")
    }
    let length = memory.read_u32(cache + layout.cache_length)?;
    if cache_index >= length {
        bail!("constant-pool cache index {cache_index} >= {length}")
    }
    let entry = cache + layout.cache_header_size + cache_index as u64 * layout.cache_entry_size;
    Ok(memory.read_u64(entry + layout.cache_entry_indices)? as u16)
}

fn reference_cp_index<M: RemoteMemory>(
    memory: &M,
    constant_pool: u64,
    index: u16,
    layout: &Layout,
) -> Result<u16> {
    let map = memory.read_u64(constant_pool + layout.cp_reference_map)?;
    if map == 0 {
        bail!("fast ldc without reference map")
    }
    let length = memory.read_u32(map + layout.array_len)? as usize;
    if index as usize >= length {
        bail!("reference-map index out of range")
    }
    memory.read_u16(map + 4 + index as u64 * 2)
}

pub(super) fn restore_bytecodes<M: RemoteMemory>(
    memory: &M,
    constant_pool: u64,
    layout: &Layout,
    code: &mut [u8],
) -> Result<()> {
    let cache = memory.read_u64(constant_pool + layout.cp_cache)?;
    let rewritten = cache != 0;
    let mut bci = 0usize;
    while bci < code.len() {
        let opcode = code[bci];
        let length = bytecode_length(code, bci)?;
        if bci + length > code.len() {
            bail!("truncated bytecode at bci {bci}")
        }
        if (203..=233).contains(&opcode) && !rewritten {
            bail!("HotSpot fast bytecode {opcode} without ConstantPoolCache at bci {bci}")
        }
        match opcode {
            178..=185 if rewritten => {
                restore_cache_u2(memory, constant_pool, layout, code, bci + 1)?
            }
            186 if rewritten => {
                let raw = u32::from_le_bytes(code[bci + 1..bci + 5].try_into().unwrap());
                let cache_length = memory.read_u32(cache + layout.cache_length)?;
                let index = if raw < cache_length { raw } else { !raw };
                let cp_index = cache_cp_index(memory, constant_pool, index, layout)?;
                code[bci + 1..bci + 3].copy_from_slice(&cp_index.to_be_bytes());
                code[bci + 3] = 0;
                code[bci + 4] = 0;
            }
            186 => {
                if code[bci + 3] != 0 || code[bci + 4] != 0 {
                    bail!("unrewritten invokedynamic has non-zero reserved bytes at bci {bci}")
                }
            }
            203..=210 => {
                code[bci] = 180;
                restore_cache_u2(memory, constant_pool, layout, code, bci + 1)?;
            }
            211..=219 => {
                code[bci] = 181;
                restore_cache_u2(memory, constant_pool, layout, code, bci + 1)?;
            }
            220 => code[bci] = 42,
            221..=223 => {
                code[bci] = 42;
                code[bci + 1] = 180;
                restore_cache_u2(memory, constant_pool, layout, code, bci + 2)?;
            }
            224 => code[bci] = 21,
            225 => {
                code[bci] = 21;
                code[bci + 2] = 21;
            }
            226 => {
                code[bci] = 21;
                code[bci + 2] = 52;
            }
            227 => {
                code[bci] = 182;
                restore_cache_u2(memory, constant_pool, layout, code, bci + 1)?;
            }
            228 | 229 => code[bci] = 171,
            230 => {
                code[bci] = 18;
                code[bci + 1] =
                    reference_cp_index(memory, constant_pool, code[bci + 1] as u16, layout)? as u8;
            }
            231 => {
                code[bci] = 19;
                let index = u16::from_le_bytes([code[bci + 1], code[bci + 2]]);
                let original = reference_cp_index(memory, constant_pool, index, layout)?;
                code[bci + 1..bci + 3].copy_from_slice(&original.to_be_bytes());
            }
            232 => code[bci] = 177,
            233 => {
                code[bci] = 182;
                restore_cache_u2(memory, constant_pool, layout, code, bci + 1)?;
            }
            202 => bail!("active breakpoint at bci {bci}"),
            234..=255 => bail!("unknown HotSpot bytecode {opcode} at bci {bci}"),
            _ => {}
        }
        bci += length;
    }
    Ok(())
}

fn restore_cache_u2<M: RemoteMemory>(
    memory: &M,
    constant_pool: u64,
    layout: &Layout,
    code: &mut [u8],
    at: usize,
) -> Result<()> {
    let index = u16::from_le_bytes([code[at], code[at + 1]]) as u32;
    let original = cache_cp_index(memory, constant_pool, index, layout)?;
    code[at..at + 2].copy_from_slice(&original.to_be_bytes());
    Ok(())
}

fn bytecode_length(code: &[u8], at: usize) -> Result<usize> {
    let opcode = code[at];
    let fixed = match opcode {
        16 | 18 | 21..=25 | 54..=58 | 169 | 188 | 224 | 230 => 2,
        17
        | 19
        | 20
        | 132
        | 153..=168
        | 178..=184
        | 187
        | 189
        | 192
        | 193
        | 198
        | 199
        | 203..=219
        | 227
        | 231
        | 233 => 3,
        197 | 221..=223 => 4,
        185 | 186 | 200 | 201 => 5,
        196 => {
            let next = *code.get(at + 1).context("truncated wide")?;
            if next == 132 { 6 } else { 4 }
        }
        170 => switch_length(code, at, true)?,
        171 | 228 | 229 => switch_length(code, at, false)?,
        225 => 4,
        226 => 3,
        _ if opcode <= 233 => 1,
        _ => bail!("invalid bytecode {opcode}"),
    };
    Ok(fixed)
}

fn switch_length(code: &[u8], at: usize, table: bool) -> Result<usize> {
    let aligned = (at + 4) & !3;
    let read_i32 = |position: usize| -> Result<i32> {
        let bytes: [u8; 4] = code
            .get(position..position + 4)
            .context("truncated switch")?
            .try_into()
            .unwrap();
        Ok(i32::from_be_bytes(bytes))
    };
    let words = if table {
        let low = read_i32(aligned + 4)? as i64;
        let high = read_i32(aligned + 8)? as i64;
        if high < low || high - low > 65535 {
            bail!("invalid tableswitch")
        }
        3 + (high - low + 1) as usize
    } else {
        let pairs = read_i32(aligned + 4)?;
        if !(0..=65535).contains(&pairs) {
            bail!("invalid lookupswitch")
        }
        2 + pairs as usize * 2
    };
    aligned
        .checked_sub(at)
        .and_then(|value| value.checked_add(words * 4))
        .context("switch length overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Memory(Vec<u8>);

    impl RemoteMemory for Memory {
        fn read_exact(&self, address: u64, destination: &mut [u8]) -> Result<()> {
            let start = address as usize;
            let end = start + destination.len();
            destination.copy_from_slice(self.0.get(start..end).context("test memory OOB")?);
            Ok(())
        }
    }

    #[test]
    fn unrewritten_member_reference_keeps_classfile_cp_index() {
        let memory = Memory(vec![0; 64]);
        let layout = Layout {
            cp_cache: 8,
            ..Layout::default()
        };
        let mut code = vec![180, 0x12, 0x34, 177];

        restore_bytecodes(&memory, 16, &layout, &mut code).unwrap();

        assert_eq!(code, [180, 0x12, 0x34, 177]);
    }

    #[test]
    fn unrewritten_invokedynamic_keeps_cp_index_and_reserved_bytes() {
        let memory = Memory(vec![0; 64]);
        let layout = Layout {
            cp_cache: 8,
            ..Layout::default()
        };
        let mut code = vec![186, 0x00, 0x2a, 0, 0, 177];

        restore_bytecodes(&memory, 16, &layout, &mut code).unwrap();

        assert_eq!(code, [186, 0x00, 0x2a, 0, 0, 177]);
    }
}
