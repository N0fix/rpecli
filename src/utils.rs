use colored::Colorize;
use entropy::shannon_entropy;
use exe::{CCharString, SectionCharacteristics, VecPE, PE};
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;

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

pub fn display_sections(pe: &VecPE) {
    let mut table = Table::new();
    
    table.style = term_table::TableStyle::thin();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Name".bold(), 1, term_table::table_cell::Alignment::Center),
        TableCell::new_with_alignment(
            "VirtAddr".bold(),
            1,
            term_table::table_cell::Alignment::Center,
        ),
        TableCell::new_with_alignment(
            "VirtSize".bold(),
            1,
            term_table::table_cell::Alignment::Center,
        ),
        TableCell::new_with_alignment(
            "RawAddr".bold(),
            1,
            term_table::table_cell::Alignment::Center,
        ),
        TableCell::new_with_alignment(
            "RawSize".bold(),
            1,
            term_table::table_cell::Alignment::Center,
        ),
        TableCell::new_with_alignment(
            "Entropy".bold(),
            1,
            term_table::table_cell::Alignment::Center,
        ),
        TableCell::new_with_alignment("md5".bold(), 1, term_table::table_cell::Alignment::Center),
        TableCell::new_with_alignment(
            "Characteristics".bold(),
            1,
            term_table::table_cell::Alignment::Center,
        ),
        ]));
        match pe.get_section_table() {
            Ok(sections) => {
            println!(
                "{:^9} {:>10} {:>10} {:>9} {:>9} {:>8} {:^32}     {:>15}",
                "Name".bold(),
                "VirtAddr".bold(),
                "VirtSize".bold(),
                "RawAddr".bold(),
                "RawSize".bold(),
                "Entropy".bold(),
                "md5".bold(),
                "Characteristics".bold(),
            );
            for &section in sections {
                let characteristics = format!("{:?} {:?}", section.characteristics, section.characteristics
                & (SectionCharacteristics::MEM_EXECUTE
                    | SectionCharacteristics::MEM_READ
                    | SectionCharacteristics::MEM_WRITE));
                let section_hash = format!("{:?}", md5::compute(section.read(pe).unwrap()));
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment(section.name.as_str().unwrap(), 1, term_table::table_cell::Alignment::Center),
                    TableCell::new_with_alignment(section.virtual_address.0, 1, term_table::table_cell::Alignment::Center),
                    TableCell::new_with_alignment(section.virtual_size, 1, term_table::table_cell::Alignment::Center),
                    TableCell::new_with_alignment(section.pointer_to_raw_data.0, 1, term_table::table_cell::Alignment::Center),
                    TableCell::new_with_alignment(section.size_of_raw_data, 1, term_table::table_cell::Alignment::Center),
                    TableCell::new_with_alignment(shannon_entropy(section.read(pe).unwrap()), 1, term_table::table_cell::Alignment::Center),
                    TableCell::new_with_alignment(section_hash, 1, term_table::table_cell::Alignment::Center),
                    TableCell::new_with_alignment(characteristics, 1, term_table::table_cell::Alignment::Center),
                ]));
                println!(
                    "{:9} {:>#10x} {:>#10x} {:>#9x} {:>#9x}   {:>6.2}  {:x}    {:>15x} ({:?}) ",
                    section.name.as_str().unwrap(),
                    // section.characteristics.bits(),
                    section.virtual_address.0,
                    section.virtual_size,
                    section.pointer_to_raw_data.0,
                    section.size_of_raw_data,
                    shannon_entropy(section.read(pe).unwrap()),
                    md5::compute(section.read(pe).unwrap()),
                    section.characteristics.bits(),
                    section.characteristics
                    & (SectionCharacteristics::MEM_EXECUTE
                        | SectionCharacteristics::MEM_READ
                        | SectionCharacteristics::MEM_WRITE)
                    );
            }
            table.max_column_width = term_size::dimensions().or_else(|| Some((4000, 4000))).unwrap().0;
            println!("{}", table.render());
            
        }
        Err(_) => panic!("Could not parse section table ! Is your file a PE file?"),
    }
}
