use std::error::Error;

use colored::Colorize;
use entropy::shannon_entropy;
use exe::{Buffer, PEType};
use exe::{CCharString, SectionCharacteristics, VecPE, PE};
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;
#[macro_use]
use crate::{color_format_if, alert_format, warn_format, alert_format_if, warn_format_if};
use crate::util::{round_to_pe_sz, round_to_pe_sz_with_offset, safe_read};

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
                let data_offset = section.data_offset(pe.get_type());
                let data_size = section.data_size(pe.get_type());
                let section_data = safe_read(pe, data_offset, data_size); // pe.read(offset.into(), size).unwrap();
                let section_hash = format!("{:?}", md5::compute(section_data));
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
                        format!(
                            "{}",
                            alert_format_if!(
                                format!("{:#x}", section.size_of_raw_data),
                                section.size_of_raw_data != section_data.len() as u32
                            )
                        ),
                        1,
                        term_table::table_cell::Alignment::Right,
                    ),
                    TableCell::new_with_alignment(
                        format!("{:6.2}", shannon_entropy(section_data)),
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
            && ((offset) < (section.virtual_size as u64 + section.virtual_address.0 as u64))
        {
            return Ok(section.name.as_str().unwrap().to_owned());
        }
    }

    Err(exe::Error::SectionNotFound)
}
