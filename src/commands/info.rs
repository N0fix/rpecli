use std::ffi::OsString;
use std::path::{Path, PathBuf};

use colored::Colorize;
use exe::{Address, FileCharacteristics, ImageFileHeader, VecPE, PE};

use crate::disassembler::disass::disassemble_bytes;
use crate::import_export::{display_exports, display_imports};
use crate::util::get_subsystem;
use crate::utils::debug::display_debug_info;
use crate::utils::rich::display_rich;
use crate::utils::rsrc::display_rsrc;
use crate::utils::sections::{display_sections, get_section_name_from_offset};
use crate::utils::sig::display_sig;
use crate::utils::timestamps::format_timestamp;
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};

use crate::utils::hash;
use crate::utils::tls::display_tls;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use human_bytes::human_bytes;

fn get_type(pe: &VecPE) -> &str {
    let file_characteristics = match pe.get_arch().unwrap() {
        exe::Arch::X86 => pe.get_nt_headers_32().unwrap().file_header.characteristics,
        exe::Arch::X64 => pe.get_nt_headers_64().unwrap().file_header.characteristics,
    };
    match file_characteristics.contains(FileCharacteristics::DLL) {
        true => "DLL",
        false => "PE",
    }
}

pub fn info_cmd(pe_filepaths: &Vec<String>, display_hashes: bool) {
    for file in pe_filepaths {
        display_info(file, display_hashes);
    }
}

fn display_info(pe_filepath: &String, display_hashes: bool) {
    let Ok(image) = VecPE::from_disk_file(&pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {:?}", pe_filepath))
        );
        return;
    };
    println!("Metadata:\n{}", "=".repeat(if true { 80 } else { 0 }));
    if (display_hashes) {
        hash::display_hashes(&image);
    }

    println!("");
    let pe_sz = image.get_buffer().as_ref().len();
    let Ok(arch) = image.get_arch() else {
        println!("Invalid NT Header");
        return;
    };
    println!("Size:\t\t{} ({} bytes)", human_bytes(pe_sz as u32), pe_sz);
    println!("Type:\t\t{:?} {}", arch, get_type(&image));

    let Ok(arch) = image.get_arch() else {
        println!("{}", alert_format!("Could not read PE arch"));
        return;
    };

    let timestamp = match arch {
        exe::Arch::X86 => {
            image
                .get_nt_headers_32()
                .unwrap()
                .file_header
                .time_date_stamp
        }
        exe::Arch::X64 => {
            image
                .get_nt_headers_64()
                .unwrap()
                .file_header
                .time_date_stamp
        }
    };

    println!("Compile Time:\t{}", format_timestamp(timestamp as i64));
    let Ok(entrypoint) = image.get_entrypoint() else {
        println!("{}", "Invalid NT headers".red().bold());
        return;
    };

    let ep_section = match get_section_name_from_offset(entrypoint.0 as u64, &image) {
        Some(s) => s,
        None => String::from("Not in a section"),
    };
    println!(
        "Subsystem:      {}",
        get_subsystem(&image).unwrap().as_string()
    );
    println!("Entrypoint:     {:#x} => {}\n", entrypoint.0, ep_section);
    println!(
        "Code at entrypoint:\n{}",
        "=".repeat(if true { 80 } else { 0 })
    );
    let bitness = match arch {
        exe::Arch::X86 => 32u32,
        exe::Arch::X64 => 64u32,
    };
    disassemble_bytes(
        image.get_buffer().as_ref(),
        bitness,
        entrypoint.as_offset(&image).unwrap().0 as usize,
        10,
    );
    println!("");
    println!("Signature:\n{}", "=".repeat(if true { 80 } else { 0 }));

    display_sig(&image);

    println!("");
    println!("Rich headers:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_rich(&image);
    println!("");
    // if true else 0, keeping this for later
    println!("Sections:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_sections(&image);

    println!("");
    println!("Imports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_imports(&image);
    println!("");
    println!("Exports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_exports(&image);
    // println!("Type:\t\t{:#x} bytes", image.get_type());
    println!("");
    println!("Debug info:\n{}", "=".repeat(if true { 80 } else { 0 }));

    display_debug_info(&image);

    println!("");
    println!("Resources:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_rsrc(&image, display_hashes);

    println!("");
    println!("TLS callbacks:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_tls(&image);
}
