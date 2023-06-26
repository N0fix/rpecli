use std::collections::HashMap;

use exe::{
    VSFixedFileInfo, VSStringFileInfo, VSStringTable, VSVersionInfo, VecPE, WCharString, PE,
};
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;

fn string_vec(string_file_info: &VSStringFileInfo) -> Result<Vec<(String, String)>, exe::Error> {
    let mut result = Vec::<(String, String)>::new();

    for entry in &string_file_info.children[0].children {
        let entry_key = entry.header.key.as_u16_str()?;
        let entry_value = entry.value.as_u16_str()?;

        result.push((
            entry_key.as_ustr().to_string_lossy(),
            entry_value.as_ustr().to_string_lossy(),
        ));
    }

    Ok(result)
}

pub fn display_version_info(pe: &VecPE) {
    let vs_version_check = VSVersionInfo::parse(pe);
    let vs_version = vs_version_check.unwrap();
    if let Some(string_file_info) = vs_version.string_file_info {
        let infos = string_vec(&string_file_info).unwrap();

        let string_map = string_file_info.children[0].string_map().unwrap();
        let mut table = Table::new();
        table.max_column_width = term_size::dimensions()
            .or_else(|| Some((4000, 4000)))
            .unwrap()
            .0;
        for (key, value) in infos.into_iter() {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(key, 1, term_table::table_cell::Alignment::Left),
                TableCell::new_with_alignment(value, 1, term_table::table_cell::Alignment::Right),
            ]));
        }
        println!("{}", table.render());
    } else {
        panic!("couldn't get string file info");
    }
}

pub fn display_sig(pe: &VecPE) {
    let security_dir = match pe.get_data_directory(exe::ImageDirectoryEntry::Security) {
        Ok(security_dir) => security_dir,
        Err(_) => {
            println!("No security directory");
            return;
        }
    };
    if security_dir.virtual_address.0 == 0 {
        println!("Not signed");
    } else {
        // TODO : use https://docs.rs/authenticode-parser-sys/latest/authenticode_parser_sys/index.html
        // authenticode parser from AVAST
        println!("Signed. TODO : Parse signatures and print them");
    }
}
