use std::u64::MAX;

use exe::{VecPE, PE};

use crate::utils::pe_size::get_pe_file_size;

pub fn round_to_pe_sz(pe: &VecPE, value: usize) -> usize {
    usize::min(value, get_pe_file_size(pe))
}

pub fn round_to_pe_sz_with_offset<P: PE>(pe: &P, offset: usize, value: usize) -> usize {
    let pe_sz = get_pe_file_size(pe);
    match offset + value > pe_sz {
        true => pe_sz - offset,
        false => value,
    }
}

pub fn safe_read<P: PE>(pe: &P, offset: usize, size: usize) -> &[u8] {
    let pe_sz = get_pe_file_size(pe);
    if offset > pe_sz {
        return pe.read(0, 0).unwrap();
    }

    let safe_size = round_to_pe_sz_with_offset(pe, offset, size);
    println!("gonna read sz {:x} at {:x} ({:x}). pe sz {:x}", safe_size, offset, offset+safe_size, pe_sz);
    pe.read(offset, safe_size).unwrap()
}
