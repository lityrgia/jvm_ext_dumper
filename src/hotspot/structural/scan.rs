use std::collections::HashSet;

use anyhow::{Result, bail};

use crate::platform::{MemoryRegion, RemoteMemory, TargetProcess};

use super::layout::valid_symbol_at;

const SCAN_CHUNK: usize = 4 * 1024 * 1024;
const PAGE_SIZE: usize = 0x1000;

pub(super) fn scan_symbols(
    process: &TargetProcess,
    regions: &[MemoryRegion],
    body: &[u8],
    limit: usize,
) -> Result<Vec<u64>> {
    if body.is_empty() {
        bail!("empty scan pattern")
    }
    let mut collector = SymbolCollector::new(body, limit);
    for region in regions {
        collector.reset_tail();
        let mut offset = 0usize;
        while offset < region.size && !collector.is_full() {
            let size = SCAN_CHUNK.min(region.size - offset);
            let address = region.base + offset as u64;
            let mut block = vec![0; size];
            if process.read_exact(address, &mut block).is_ok() {
                collector.collect(process, &block, address);
            } else {
                scan_pages(process, &mut collector, address, size);
            }
            offset += size;
        }
        if collector.is_full() {
            break;
        }
    }
    Ok(collector.into_symbols())
}

fn scan_pages(
    process: &TargetProcess,
    collector: &mut SymbolCollector<'_>,
    address: u64,
    size: usize,
) {
    for page_offset in (0..size).step_by(PAGE_SIZE) {
        let page_size = PAGE_SIZE.min(size - page_offset);
        let mut page = vec![0; page_size];
        let page_address = address + page_offset as u64;
        if process.read_exact(page_address, &mut page).is_ok() {
            collector.collect(process, &page, page_address);
        } else {
            collector.reset_tail();
        }
        if collector.is_full() {
            break;
        }
    }
}

struct SymbolCollector<'a> {
    body: &'a [u8],
    limit: usize,
    tail: Vec<u8>,
    seen: HashSet<u64>,
    symbols: Vec<u64>,
}

impl<'a> SymbolCollector<'a> {
    fn new(body: &'a [u8], limit: usize) -> Self {
        Self {
            body,
            limit,
            tail: Vec::new(),
            seen: HashSet::new(),
            symbols: Vec::new(),
        }
    }

    fn collect(&mut self, process: &TargetProcess, block: &[u8], address: u64) {
        let tail_len = self.tail.len();
        self.tail.extend_from_slice(block);
        for found in find_subslices(&self.tail, self.body) {
            if found + self.body.len() <= tail_len {
                continue;
            }
            let body_address = address - tail_len as u64 + found as u64;
            let Some(symbol) = body_address.checked_sub(8) else {
                continue;
            };
            if symbol & 7 == 0
                && self.seen.insert(symbol)
                && valid_symbol_at(process, symbol, Some(self.body))
            {
                self.symbols.push(symbol);
            }
            if self.is_full() {
                break;
            }
        }
        let keep = self.body.len().saturating_sub(1).min(self.tail.len());
        self.tail.drain(..self.tail.len() - keep);
    }

    fn reset_tail(&mut self) {
        self.tail.clear();
    }

    fn is_full(&self) -> bool {
        self.symbols.len() == self.limit
    }

    fn into_symbols(self) -> Vec<u64> {
        self.symbols
    }
}

pub(super) fn scan_u64(
    process: &TargetProcess,
    regions: &[MemoryRegion],
    wanted: u64,
    limit: usize,
) -> Result<Vec<u64>> {
    let mut hits = Vec::new();
    for region in regions {
        let mut offset = 0usize;
        while offset < region.size && hits.len() < limit {
            let size = SCAN_CHUNK.min(region.size - offset);
            let address = region.base + offset as u64;
            let mut bytes = vec![0; size];
            if process.read_exact(address, &mut bytes).is_ok() {
                collect_aligned_u64(&bytes, address, wanted, &mut hits, limit);
            } else {
                scan_u64_pages(process, address, size, wanted, &mut hits, limit);
            }
            offset += size;
        }
        if hits.len() == limit {
            break;
        }
    }
    Ok(hits)
}

fn scan_u64_pages(
    process: &TargetProcess,
    address: u64,
    size: usize,
    wanted: u64,
    hits: &mut Vec<u64>,
    limit: usize,
) {
    for page_offset in (0..size).step_by(PAGE_SIZE) {
        let page_size = PAGE_SIZE.min(size - page_offset);
        let mut page = vec![0; page_size];
        let page_address = address + page_offset as u64;
        if process.read_exact(page_address, &mut page).is_ok() {
            collect_aligned_u64(&page, page_address, wanted, hits, limit);
        }
        if hits.len() == limit {
            break;
        }
    }
}

fn collect_aligned_u64(bytes: &[u8], address: u64, wanted: u64, hits: &mut Vec<u64>, limit: usize) {
    let first = ((8 - (address & 7)) & 7) as usize;
    for index in (first..bytes.len().saturating_sub(7)).step_by(8) {
        if u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap()) == wanted {
            hits.push(address + index as u64);
            if hits.len() == limit {
                break;
            }
        }
    }
}

fn find_subslices<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(move |(index, bytes)| (bytes == needle).then_some(index))
}

#[cfg(test)]
mod tests {
    use super::find_subslices;

    #[test]
    fn substring_scanner_reports_overlapping_hits() {
        assert_eq!(
            find_subslices(b"aaaa", b"aa").collect::<Vec<_>>(),
            [0, 1, 2]
        );
    }
}
