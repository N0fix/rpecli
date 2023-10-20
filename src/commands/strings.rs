use std::collections::HashMap;

use crate::{
    alert_format, alert_format_if, color_format_if,
    compare::Comparable,
    utils::strings::{self, get_strings, MatchString},
    warn_format, warn_format_if,
};
use colored::Colorize;
use exe::VecPE;
use indicatif::ProgressBar;

type StringCounter<'pe> = HashMap<&'pe String, u32>;

fn display_strings(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {}", pe_filepath))
        );
        return;
    };
    strings::display_strings(&image, 4);
}

pub fn strings_cmd(pe_filepaths: &Vec<String>) {
    let mut strings: Vec<MatchString> = vec![];
    let bar = ProgressBar::new(pe_filepaths.len() as u64);
    for (i, file) in pe_filepaths.iter().enumerate() {
        // display_strings(file);
        let Ok(image) = VecPE::from_disk_file(file) else {
            println!("{}", alert_format!(format!("Could not read {}", file)));
            continue;
        };

        strings.push(get_strings(image.get_buffer().as_ref(), 4));
        if pe_filepaths.len() > 1 {
            bar.inc(1);
        }
    }
    bar.finish();
    let sorted_map = MatchString::compare(strings);

    for (str, cnt) in sorted_map.iter() {
        let percentage = (*cnt as f32 / pe_filepaths.len() as f32) * 100.0;
        if percentage > 30.0 {
            println!(
                "{:6.2}% : {}",
                (*cnt as f32 / pe_filepaths.len() as f32) * 100.0,
                str
            );
        }
    }
}
