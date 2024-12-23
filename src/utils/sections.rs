use bitflags::{bitflags, Flags};
use colored::Colorize;
use entropy::shannon_entropy;
use exe::{Buffer, PEType};
use exe::{CCharString, VecPE, PE};
use pkbuffer::{Castable, VecBuffer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Debug, Display};
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;
#[macro_use]
use crate::{color_format_if, alert_format, warn_format, alert_format_if, warn_format_if};
use crate::util::{round_to_pe_sz, round_to_pe_sz_with_offset, safe_read, CChar_to_escaped_string};

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd)]
pub struct Section<'data> {
    name: String,
    virt_addr: u32,
    virt_size: u32,
    raw_addr: u32,
    raw_size: u32,
    #[serde(skip_serializing)]
    data: &'data [u8],
    entropy: Option<f32>,
    characteristics: u32,
}

impl Section<'_> {
    pub fn parse(pe: &VecPE) -> SectionTable {
        let mut result = SectionTable { sections: vec![] };
        match pe.get_section_table() {
            Ok(sec_tbl) => {
                for sec in sec_tbl {
                    let data_offset: usize = sec.data_offset(pe.get_type());
                    let data_size = sec.data_size(pe.get_type());
                    let section_data = safe_read(pe, data_offset, data_size);

                    result.sections.push(Section {
                        name: match sec.name.as_str() {
                            Ok(s) => s.to_string(),
                            Err(_) => CChar_to_escaped_string(&sec.name),
                        },
                        virt_addr: sec.virtual_address.0,
                        virt_size: sec.virtual_size,
                        raw_addr: sec.pointer_to_raw_data.0,
                        raw_size: sec.size_of_raw_data,
                        data: section_data,
                        entropy: Some(shannon_entropy(section_data)),
                        characteristics: sec.characteristics.bits(),
                    });
                }
            }
            Err(_) => return result,
        };

        result
    }
}

#[derive(Default, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SectionTable<'data> {
    #[serde(borrow)]
    pub sections: Vec<Section<'data>>,
}

bitflags! {
    /// A series of bitflags representing section characteristics.
    #[derive(Debug)]
    #[repr(C)]
    pub struct SectionCharacteristics: u32 {
        const TYPE_REG               = 0x00000000;
        const TYPE_DSECT             = 0x00000001;
        const TYPE_NOLOAD            = 0x00000002;
        const TYPE_GROUP             = 0x00000004;
        const TYPE_NO_PAD            = 0x00000008;
        const TYPE_COPY              = 0x00000010;
        const CNT_CODE               = 0x00000020;
        const CNT_INITIALIZED_DATA   = 0x00000040;
        const CNT_UNINITIALIZED_DATA = 0x00000080;
        const LNK_OTHER              = 0x00000100;
        const LNK_INFO               = 0x00000200;
        const TYPE_OVER              = 0x00000400;
        const LNK_REMOVE             = 0x00000800;
        const LNK_COMDAT             = 0x00001000;
        const RESERVED               = 0x00002000;
        const MEM_PROTECTED          = 0x00004000;
        const NO_DEFER_SPEC_EXC      = 0x00004000;
        const GPREL                  = 0x00008000;
        const MEM_FARDATA            = 0x00008000;
        const MEM_SYSHEAP            = 0x00010000;
        const MEM_PURGEABLE          = 0x00020000;
        const MEM_16BIT              = 0x00020000;
        const MEM_LOCKED             = 0x00040000;
        const MEM_PRELOAD            = 0x00080000;
        const ALIGN_1BYTES           = 0x00100000;
        const ALIGN_2BYTES           = 0x00200000;
        const ALIGN_4BYTES           = 0x00300000;
        const ALIGN_8BYTES           = 0x00400000;
        const ALIGN_16BYTES          = 0x00500000;
        const ALIGN_32BYTES          = 0x00600000;
        const ALIGN_64BYTES          = 0x00700000;
        const ALIGN_128BYTES         = 0x00800000;
        const ALIGN_256BYTES         = 0x00900000;
        const ALIGN_512BYTES         = 0x00A00000;
        const ALIGN_1024BYTES        = 0x00B00000;
        const ALIGN_2048BYTES        = 0x00C00000;
        const ALIGN_4096BYTES        = 0x00D00000;
        const ALIGN_8192BYTES        = 0x00E00000;
        const ALIGN_MASK             = 0x00F00000;
        const LNK_NRELOC_OVFL        = 0x01000000;
        const MEM_DISCARDABLE        = 0x02000000;
        const MEM_NOT_CACHED         = 0x04000000;
        const MEM_NOT_PAGED          = 0x08000000;
        const MEM_SHARED             = 0x10000000;
        const MEM_EXECUTE            = 0x20000000;
        const MEM_READ               = 0x40000000;
        const MEM_WRITE              = 0x80000000;
    }
}
unsafe impl Castable for SectionCharacteristics {}

impl Display for SectionTable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.sections.len() == 0 {
            return write!(f, "{}", warn_format!("No sections"));
        }

        let mut table = Table::new();

        table.style = term_table::TableStyle::empty();
        table.separate_rows = false;
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(
                "Name".bold(),
                1,
                term_table::table_cell::Alignment::Center,
            ),
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
            TableCell::new_with_alignment(
                "md5".bold(),
                1,
                term_table::table_cell::Alignment::Center,
            ),
            TableCell::new_with_alignment(
                "Characteristics".bold(),
                1,
                term_table::table_cell::Alignment::Center,
            ),
        ]));

        for section in &self.sections {
            // Ok(sections) => {
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
            let section_hash = format!("{:?}", md5::compute(section.data));
            let entropy = shannon_entropy(section.data);
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(
                    section.name.clone(),
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    format!("{:#x}", section.virt_addr),
                    1,
                    term_table::table_cell::Alignment::Right,
                ),
                TableCell::new_with_alignment(
                    format!("{:#x}", section.virt_size),
                    1,
                    term_table::table_cell::Alignment::Right,
                ),
                TableCell::new_with_alignment(
                    format!("{:#x}", section.raw_addr),
                    1,
                    term_table::table_cell::Alignment::Right,
                ),
                TableCell::new_with_alignment(
                    format!(
                        "{}",
                        alert_format_if!(
                            format!("{:#x}", section.raw_size),
                            section.raw_size != section.data.len() as u32
                        )
                    ),
                    1,
                    term_table::table_cell::Alignment::Right,
                ),
                TableCell::new_with_alignment(
                    alert_format_if!(format!("{:6.2}", entropy).bold(), entropy > 6.7),
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
                        "{:X} ({:?})",
                        section.characteristics,
                        (
                            SectionCharacteristics::from_bits(section.characteristics).unwrap()
                            // & (SectionCharacteristics::MEM_EXECUTE
                            // | SectionCharacteristics::MEM_READ
                            // | SectionCharacteristics::MEM_WRITE)
                        )
                        .0
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
            // }
            // Err(_) => panic!("Could not parse section table ! Is your file a PE file?"),
        }
        table.max_column_width = term_size::dimensions()
            .or_else(|| Some((4000, 4000)))
            .unwrap()
            .0;
        writeln!(f, "{}", table.render())?;

        Ok(())
    }
}

pub fn display_sections(pe: &VecPE) {
    println!("{}", Section::parse(pe));
}

pub fn get_section_name_from_offset(offset: u64, pe: &VecPE) -> Option<String> {
    let sections = Section::parse(pe);

    for section in sections.sections {
        if offset >= (section.virt_addr as u64)
            && ((offset) < (section.virt_size as u64 + section.virt_addr as u64))
        {
            return Some(section.name.to_owned());
        }
    }

    None
}
