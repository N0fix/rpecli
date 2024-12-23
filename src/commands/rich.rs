use std::path::Path;

use crate::compare::Comparable;
use crate::utils::rich::display_rich;
use crate::{
    alert_format, alert_format_if, color_format_if, utils::rich::RichTable, warn_format,
    warn_format_if,
};
use colored::Colorize;
use exe::VecPE;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::io::Write as _;
use std::io::{stdout, Write};
#[derive(Serialize, Deserialize)]

struct RichInformation {
    filename: String,
    table: RichTable,
}
pub fn rich_cmd(pe_filepaths: &Vec<String>, json_output: bool) {
    // let mut r = vec![];

    let mut x: Vec<RichInformation> = vec![];

    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            println!("{}", alert_format!(format!("Could not read {}", file)));
            continue;
        };
        // println!("Rich:\n{}", "=".repeat(if true { 80 } else { 0 }));
        let richs = RichTable::parse(&image);
        // display_rich(&image);
        if json_output {
            write!(stdout(), "{}\n", serde_json::to_string(&richs).unwrap());
            // write!(stdout(), "{}\n{}\n", file, &richs);
        } else {
            write!(stdout(), "{}\n", richs);
            // x.push(RichInformation {
            //     filename: file.to_owned(),
            //     table: richs.clone(),
            // });
        }
        // let path = Path::new(file).file_name().unwrap();
        // r.push(richs.clone());
    }
    // let sorted_map = RichTable::compare(r);
    // for (str, cnt) in sorted_map.iter() {
    // println!(
    // "{:6.2}% : {}",
    // (*cnt as f32 / pe_filepaths.len() as f32) * 100.0,
    // str
    // );
    // }
    // if json_output {
    //     write!(stdout(), "{}\n", serde_json::to_string(&x).unwrap());
    // }
}
