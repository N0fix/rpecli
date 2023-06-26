use exe::{CCharString, SectionCharacteristics, VecPE, PE};

pub fn get_pe_size(pe: &VecPE) -> usize {
    match pe.get_section_table() {
        Ok(sections) => sections
            .iter()
            .map(|s| s.pointer_to_raw_data.0 + s.size_of_raw_data)
            .max()
            .unwrap() as usize,
        Err(_) => panic!("Could not parse section table ! Is your file a PE file?"),
    }
}

pub fn get_pe_file_size<P: PE>(pe: &P) -> usize {
    pe.as_slice().len()
    // pe.get_buffer().as_ref().len()
}
