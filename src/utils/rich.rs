use crate::compare_default_impl;
use std::collections::HashMap;
use std::fmt::Display;
// #[macro_use]
// macro_rules! compare_default_impl;
// use rpecli::compare_default_impl;
use crate::utils::rich_headers::rich_utils::{ObjectKind, RichIter, RichRecord, RichStructure};
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use bytemuck::cast_slice;
use colored::Colorize;
use dataview::PodMethods;
use exe::VecPE;
use phf::phf_map;
use serde::{Deserialize, Serialize};
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;

#[derive(PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct RichTable {
    pub rich_entries: Vec<RichRecord>,
    pub key: u32,
}

impl RichTable {
    pub fn parse(pe: &VecPE) -> RichTable {
        let mut rich_table: RichTable = RichTable {
            rich_entries: vec![],
            key: 0,
        };
        let ptr_buf = pe.get_buffer().as_ref();
        if ptr_buf.len() < 0x400 {
            return rich_table;
        }
        let rich_header = match RichStructure::try_from(cast_slice(&ptr_buf[0..0x400])) {
            Ok(rich) => rich,
            Err(_) => {
                return rich_table;
            }
        };

        rich_table.key = rich_header.xor_key();

        for record in rich_header.records() {
            rich_table.rich_entries.push(record);
        }

        rich_table
    }
}

impl IntoIterator for RichTable {
    type Item = RichRecord;
    type IntoIter = std::vec::IntoIter<RichRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.rich_entries.into_iter()
    }
}

compare_default_impl!(RichTable, RichRecord);

impl Display for RichTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rich_entries.len() == 0 {
            return write!(f, "{}", warn_format!("No rich headers"));
        }

        let mut table = Table::new();
        table.max_column_width = term_size::dimensions()
            .or_else(|| Some((4000, 4000)))
            .unwrap()
            .0;
        table.style = term_table::TableStyle::empty();
        table.separate_rows = false;

        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(
                "Build".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Product ID".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Count".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Product Name".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Guessed Visual Studio version".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Raw data".bold(),
                1,
                term_table::table_cell::Alignment::Center,
            ),
        ]));

        for rich in self.rich_entries.iter() {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(
                    &rich.build,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.product,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.count,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.get_product_name(),
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.lookup_vs_version(),
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    hex::encode(unsafe {
                        std::mem::transmute::<[u32; 2], [u8; 8]>(rich.encode(self.key))
                    }),
                    1,
                    term_table::table_cell::Alignment::Right,
                ),
            ]));
        }
        write!(f, "{}", table.render())
    }
}

pub fn display_rich(pe: &VecPE) {
    let richs = RichTable::parse(pe);
    println!("{}", richs);
}
