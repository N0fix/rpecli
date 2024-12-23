use crate::disassembler::disass::disassemble_bytes;
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::{VecPE, PE};

pub fn disass_section(pe_filepath: &String, section_name: &str) {
    let Ok(pe) = VecPE::from_disk_file(pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {}", pe_filepath))
        );
        return;
    };
    if let Ok(section) = pe.get_section_by_name(section_name) {
        let bitness = match pe
            .get_arch()
            .expect("Couldn't read target PE target architecture")
        {
            exe::Arch::X86 => 32u32,
            exe::Arch::X64 => 64u32,
        };
        disassemble_bytes(section.read(&pe).unwrap(), bitness, 0, u32::MAX)
    }
}
