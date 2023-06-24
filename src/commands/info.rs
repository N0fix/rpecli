use exe::{FileCharacteristics, VecPE, PE};

use crate::import_export::{display_imports, display_exports};
use crate::rich::display_rich;
use crate::sig::display_sig;
use crate::utils::sections::{display_sections, get_section_EP};

use crate::utils::hash::display_hashes;
use chrono::{TimeZone, Utc};

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

// TODO show debug, TLS & ressources
pub fn display_info(pe_filepath: &str) {
    let image = VecPE::from_disk_file(pe_filepath).unwrap();
    println!("Metadata:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_hashes(&image);

    println!("");

    println!("Size:\t\t{:#x} bytes", image.get_buffer().as_ref().len());
    println!(
        "Type:\t\t{:?} {}",
        image.get_arch().unwrap(),
        get_type(&image)
    );

    let timestamp = match image.get_arch().unwrap() {
        exe::Arch::X86 => {
            image.get_nt_headers_32().unwrap().file_header.time_date_stamp
        },
        exe::Arch::X64 => {
            image.get_nt_headers_64().unwrap().file_header.time_date_stamp
        },
    };

    println!("Compile Time:\t{} (Timestamp: {})", Utc.timestamp_millis_opt(timestamp as i64).unwrap(), timestamp);

    println!(
        "Entrypoint:     {:#x} => {}\n",
        image.get_entrypoint().unwrap().0,
        get_section_EP(&image)
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
}
