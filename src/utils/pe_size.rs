use exe::{CCharString, SectionCharacteristics, VecPE, PE};

pub fn get_pe_size(pe: &VecPE) -> u32 {
    match pe.get_section_table() {
        Ok(sections) => sections
            .iter()
            .map(|s| s.pointer_to_raw_data.0 + s.size_of_raw_data)
            .max()
            .unwrap(),
        Err(_) => panic!("Could not parse section table ! Is your file a PE file?"),
    }
}
