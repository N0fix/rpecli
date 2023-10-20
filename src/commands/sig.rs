use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::VecPE;

use crate::utils::sig::display_sig;

fn display_signature(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {}", pe_filepath))
        );
        return;
    };
    display_sig(&image);
}

pub fn sig_cmd(pe_filepaths: &Vec<String>) {
    for file in pe_filepaths {
        display_signature(file);
    }
}
