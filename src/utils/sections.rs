use std::error::Error;

use colored::Colorize;
use entropy::shannon_entropy;
use exe::PEType;
use exe::{CCharString, SectionCharacteristics, VecPE, PE};
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;

pub fn display_sections(pe: &VecPE) {
    let mut table = Table::new();

    table.style = term_table::TableStyle::empty();
    table.separate_rows = false;
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Name".bold(), 1, term_table::table_cell::Alignment::Center),
        TableCell::new_with_alignment(
            "VirtAddr".bold(),
            1,
            term_table::table_cell::Alignment::Left,
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
            // println!(
            //     "{:^9} {:>10} {:>10} {:>9} {:>9} {:>8} {:^32}     {:>15}",
            //     "Name".bold(),
            //     "VirtAddr".bold(),
            //     "VirtSize".bold(),
            //     "RawAddr".bold(),
            //     "RawSize".bold(),
            //     "Entropy".bold(),
            //     "md5".bold(),
            //     "Characteristics".bold(),
            // );
            for &section in sections {
                let characteristics = format!(
                    "{:?} {:?}",
                    section.characteristics,
                    section.characteristics
                        & (SectionCharacteristics::MEM_EXECUTE
                            | SectionCharacteristics::MEM_READ
                            | SectionCharacteristics::MEM_WRITE)
                );
                let section_hash = format!("{:?}", md5::compute(section.read(pe).unwrap()));
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment(
                        section.name.as_str().unwrap(),
                        1,
                        term_table::table_cell::Alignment::Left,
                    ),
                    TableCell::new_with_alignment(
                        format!("{:#x}", section.virtual_address.0),
                        1,
                        term_table::table_cell::Alignment::Right,
                    ),
                    TableCell::new_with_alignment(
                        format!("{:#x}", section.virtual_size),
                        1,
                        term_table::table_cell::Alignment::Right,
                    ),
                    TableCell::new_with_alignment(
                        format!("{:#x}", section.pointer_to_raw_data.0),
                        1,
                        term_table::table_cell::Alignment::Right,
                    ),
                    TableCell::new_with_alignment(
                        format!("{:#x}", section.size_of_raw_data),
                        1,
                        term_table::table_cell::Alignment::Right,
                    ),
                    TableCell::new_with_alignment(
                        format!("{:6.2}", shannon_entropy(section.read(pe).unwrap())),
                        1,
                        term_table::table_cell::Alignment::Right,
                    ),
                    TableCell::new_with_alignment(
                        section_hash,
                        1,
                        term_table::table_cell::Alignment::Right,
                    ),
                    TableCell::new_with_alignment(
                        format!(
                            "{:x} ({:?})",
                            section.characteristics.bits(),
                            section.characteristics
                                & (SectionCharacteristics::MEM_EXECUTE
                                    | SectionCharacteristics::MEM_READ
                                    | SectionCharacteristics::MEM_WRITE)
                        ),
                        1,
                        term_table::table_cell::Alignment::Left,
                    ),
                ]));
                // println!(
                //     "{:9} {:>#10x} {:>#10x} {:>#9x} {:>#9x}   {:>6.2}  {:x}    {:>15x} ({:?}) ",
                //     section.name.as_str().unwrap(),
                //     // section.characteristics.bits(),
                //     section.virtual_address.0,
                //     section.virtual_size,
                //     section.pointer_to_raw_data.0,
                //     section.size_of_raw_data,
                //     shannon_entropy(section.read(pe).unwrap()),
                //     md5::compute(section.read(pe).unwrap()),
                //     section.characteristics.bits(),
                //     section.characteristics
                //         & (SectionCharacteristics::MEM_EXECUTE
                //             | SectionCharacteristics::MEM_READ
                //             | SectionCharacteristics::MEM_WRITE)
                // );
            }
            table.max_column_width = term_size::dimensions()
                .or_else(|| Some((4000, 4000)))
                .unwrap()
                .0;
            println!("{}", table.render());
        }
        Err(_) => panic!("Could not parse section table ! Is your file a PE file?"),
    }
}

pub fn get_section_name_from_offset<P: PE>(offset: u64, pe: &P) -> Result<String, exe::Error> {
    let sections = match pe.get_section_table() {
        Ok(sections) => sections,
        Err(_) => panic!("Could not parse section table ! Is your file a PE file?"),
    };

    for section in sections {
        if offset >= (section.virtual_address.0 as u64)
            && ((offset)
                < (section.virtual_size as u64 + section.virtual_address.0 as u64))
        {
            return Ok(section.name.as_str().unwrap().to_owned());
        }
    }

    Err(exe::Error::SectionNotFound)
}

pub fn get_section_EP<P: PE>(pe: &P) -> &str {
    let entrypoint = pe.get_entrypoint().unwrap().0 as u64;
    let sections = match pe.get_section_table() {
        Ok(sections) => sections,
        Err(_) => panic!("Could not parse section table ! Is your file a PE file?"),
    };

    for section in sections {
        if entrypoint >= (section.virtual_address.0 as u64)
            && ((entrypoint as u64)
                < (section.virtual_size as u64 + section.virtual_address.0 as u64))
        {
            return section.name.as_str().unwrap();
        }
    }

    "Not in a section" // Should return an error we can match and print w/ red color
}
