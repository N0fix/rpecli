use colored::Colorize;
use exe::{FileCharacteristics, VecPE, PE};

use crate::util::get_subsystem;
use crate::{color_format_if, alert_format, warn_format, alert_format_if, warn_format_if};
use crate::import_export::{display_exports, display_imports};
use crate::rich::display_rich;
use crate::sig::display_sig;
use crate::utils::debug::display_debug_info;
use crate::utils::rsrc::display_rsrc;
use crate::utils::sections::{display_sections, get_section_name_from_offset};

use crate::utils::hash::display_hashes;
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


pub fn display_info(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!("{}", alert_format!(format!("Could not read {}", pe_filepath)));
        return;
    };
    println!("Metadata:\n{}", "=".repeat(if true { 80 } else { 0 }));
    // display_hashes(&image);

    println!("");
    let pe_sz = image.get_buffer().as_ref().len();
    println!("Size:\t\t{} ({} bytes)", human_bytes(pe_sz as u32), pe_sz);
    println!(
        "Type:\t\t{:?} {}",
        image.get_arch().unwrap(),
        get_type(&image)
    );

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

    let naive = NaiveDateTime::from_timestamp_opt(timestamp.into(), 0).unwrap();
    let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    println!(
        "Compile Time:\t{} (Timestamp: {})",
        datetime.format("%Y-%m-%d %H:%M:%S"),
        timestamp as i64
    );
    let Ok(entrypoint) = image.get_entrypoint() else {
        println!("{}", "Invalid NT headers".red().bold());
        return;
    };
    let ep_section =
        match get_section_name_from_offset(entrypoint.0 as u64, &image) {
            Ok(s) => s,
            Err(_) => String::from("Not in a section"),
        };
    println!("Subsystem:      {}", get_subsystem(&image).unwrap().as_string() );
    println!(
        "Entrypoint:     {:#x} => {}\n",
        entrypoint.0,
        ep_section
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
    display_rsrc(&image);

    println!("");
    println!("TLS callbacks:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_tls(&image);
}
