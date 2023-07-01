use std::io::Write;

use colored::Colorize;
use exe::pe::PE;
use exe::types::{CCharString, ImportData, ImportDirectory};
use exe::ResolvedDirectoryData::{Data, Directory};
use exe::{Buffer, ImageDirectoryEntry, ResolvedDirectoryID, ResourceDirectoryMut, PETranslation, RVA, Address};
use exe::{
    ImageResourceDataEntry, ImageResourceDirStringU, ImageResourceDirectoryEntry,
    ResolvedDirectoryData, ResourceDirectory, ResourceDirectoryData, ResourceDirectoryID,
    ResourceID, VecPE, WCharString,
};
use term_table::Table;
use term_table::row::Row;
use term_table::table_cell::TableCell;

use crate::util::safe_read;

pub fn ResolvedDirectoryID_to_string(id: ResolvedDirectoryID) -> String {
    match id {
        ResolvedDirectoryID::ID(id) => return resource_id_to_type(ResourceID::from_u32(id)),
        ResolvedDirectoryID::Name(id) => return id,
    }
}

pub fn resource_id_to_type(id: ResourceID) -> String {
    return match id {
        ResourceID::Cursor => "Cursor".to_owned(),
        ResourceID::Bitmap => "Bitmap".to_owned(),
        ResourceID::Icon => "Icon".to_owned(),
        ResourceID::Menu => "Menu".to_owned(),
        ResourceID::Dialog => "Dialog".to_owned(),
        ResourceID::String => "String".to_owned(),
        ResourceID::FontDir => "FontDir".to_owned(),
        ResourceID::Font => "Font".to_owned(),
        ResourceID::Accelerator => "Accelerator".to_owned(),
        ResourceID::RCData => "RCData".to_owned(),
        ResourceID::MessageTable => "MessageTable".to_owned(),
        ResourceID::GroupCursor => "GroupCursor".to_owned(),
        ResourceID::Reserved => "Reserved".to_owned(),
        ResourceID::GroupIcon => "GroupIcon".to_owned(),
        ResourceID::Reserved2 => "Reserved2".to_owned(),
        ResourceID::Version => "Version".to_owned(),
        ResourceID::DlgInclude => "DlgInclude".to_owned(),
        ResourceID::Reserved3 => "Reserved3".to_owned(),
        ResourceID::PlugPlay => "PlugPlay".to_owned(),
        ResourceID::VXD => "VXD".to_owned(),
        ResourceID::AniCursor => "AniCursor".to_owned(),
        ResourceID::AniIcon => "AniIcon".to_owned(),
        ResourceID::HTML => "HTML".to_owned(),
        ResourceID::Manifest => "Manifest".to_owned(),
        ResourceID::Unknown => "Unknown".to_owned(),
    };
}

pub fn display_rsrc(pe: &VecPE) {
    let rsrc = match ResourceDirectory::parse(pe) {
        Ok(r) => r,
        Err(_) => {
            println!("No resource");
            return;
        }
    };
    let mut table = Table::new();

    table.style = term_table::TableStyle::empty();
    // table.separate_rows = false;
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Name".bold(), 1, term_table::table_cell::Alignment::Center),
        TableCell::new_with_alignment("Offset".bold(), 1, term_table::table_cell::Alignment::Center),
        TableCell::new_with_alignment("RSRC ID".bold(), 1, term_table::table_cell::Alignment::Center),
        TableCell::new_with_alignment("Lang ID".bold(), 1, term_table::table_cell::Alignment::Center),
        TableCell::new_with_alignment("MD5".bold(), 1, term_table::table_cell::Alignment::Center),
    ]));

    // println!("{} resource(s)\n", rsrc.root_node.directory.entries());
    for entry in rsrc.resources {
        let data_entry = match entry.get_data_entry(pe) {
            Ok(e) => e,
            Err(_) => &ImageResourceDataEntry{
                offset_to_data: RVA(0),
                size: 0,
                code_page: 0,
                reserved: 0,
            }
        };
        // match data_entry.offset_to_data.as_offset(pe) {
        //     Ok(x) => println!("{:?} sz | {:?}", x, data_entry.offset_to_data.as_offset(pe).unwrap()),
        //     Err(x) => {
        //         if let exe::Error::InvalidOffset(off) = x {
        //             println!("OOB offset {:?}", off);
        //         } else {

        //             println!("Invalid sz");
        //         }
        //     }
        // };
        let resource_directory_name = ResolvedDirectoryID_to_string(entry.type_id);
        let res_data = safe_read(pe, data_entry.offset_to_data.0 /*pe.translate(PETranslation::Memory(data_entry.offset_to_data)).unwrap()*/ as usize, data_entry.size as usize);
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(format!("{}", resource_directory_name), 1, term_table::table_cell::Alignment::Center),
            TableCell::new_with_alignment(format!("{:x}", entry.data.0), 1, term_table::table_cell::Alignment::Center),
            TableCell::new_with_alignment(format!("{:?}", entry.rsrc_id), 1, term_table::table_cell::Alignment::Center),
            TableCell::new_with_alignment(format!("{:?}", entry.lang_id), 1, term_table::table_cell::Alignment::Center),
            TableCell::new_with_alignment(format!("{:?}", md5::compute(res_data)), 1, term_table::table_cell::Alignment::Center),
        ]));
        println!(
            "{} (offset: {:x}) rsrc {:?}: lang {:?} {:?}",
            resource_directory_name, entry.data.0, entry.rsrc_id, entry.lang_id, md5::compute(res_data)
        );


        // TODO : display with verbose on certain types.
        // TODO : mode to dump rsrc directly to a file.
        // if resource_directory_name == "Manifest" {
        //     let data = data_entry.read(pe).unwrap();
        //     println!("\n[DUMPED]\n{}", std::str::from_utf8(data).unwrap());
        // }
    }
    println!("{}", table.render());
}
