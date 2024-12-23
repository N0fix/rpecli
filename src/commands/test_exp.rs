use crate::{
    alert_format, alert_format_if, color_format_if,
    utils::{
        self, debug::DebugEntries, export::{pexp, Exports}, import::{pimp, Imports}, rich::RichTable, rich_headers::rich_utils::RichRecord, sections::{Section, SectionTable}
    },
    warn_format, warn_format_if,
};
use colored::Colorize;
use exe::VecPE;
use serde::{Deserialize, Serialize};
use std::io::stdout;
use std::io::Write;

#[derive(Serialize, Deserialize)]
struct FilesExport {
    pub filename: String,
    pub exports: Option<Exports>,
}

#[derive(Serialize, Deserialize)]
struct FilesImport {
    pub filename: String,
    pub imports: Option<Imports>,
}

#[derive(Serialize, Deserialize)]
struct FilesRich {
    pub filename: String,
    pub rich: RichTable,
}

#[derive(Serialize, Deserialize)]
struct FilesSection<'a> {
    pub filename: String,
    #[serde(borrow)]
    pub section: SectionTable<'a>,
}

#[derive(Serialize, Deserialize)]
struct FilesDebug {
    pub filename: String,
    pub dbg: DebugEntries,
}

#[derive(Serialize, Deserialize)]
struct FileDescription<'a> {
    pub filename: String,
    #[serde(borrow)]
    pub sections: Vec<Section<'a>>,
    pub rich: Option<Vec<RichRecord>>,
    //sig
    pub imports: Option<Imports>,
    pub exports: Option<Exports>,
    pub dbg: Option<DebugEntries>,
    // rsrc
    // tls
}

pub fn test_cmd(pe_filepaths: &Vec<String>) {
    // let mut x: Vec<FilesExport> = vec![];

    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            // println!("{}", alert_format!(format!("Could not read {}", file)));
            // panic!("");
            continue;
        };
        // println!("{}", file);
        let rich_entries = RichTable::parse(&image).rich_entries;
        let file_desc = FileDescription {
            filename: file.to_string(),
            sections: Section::parse(&image).sections,
            rich: match rich_entries.len() {
                0 => None,
                sz => Some(rich_entries),
            },
            dbg: DebugEntries::parse(&image).ok(),
            imports: pimp(&image),
            exports: pexp(&image),
        };
        write!(stdout(), "{}\n", serde_json::to_string(&file_desc).unwrap());
    }
    // println!("{}", serde_json::to_string(&x).unwrap());

    // let mut x: Vec<FilesImport> = vec![];

    // for file in pe_filepaths {
    //     let Ok(image) = VecPE::from_disk_file(file) else {
    //         // println!("{}", alert_format!(format!("Could not read {}", file)));
    //         // panic!("");
    //         continue;
    //     };
    //     // println!("{}", file);

    //     x.push(FilesImport {
    //         filename: file.to_owned(),
    //         imports: ,
    //     });
    // }
    // println!("{}", serde_json::to_string(&x).unwrap());

    // let mut x: Vec<FilesRich> = vec![];
    // for file in pe_filepaths {
    //     let Ok(image) = VecPE::from_disk_file(file) else {
    //         // println!("{}", alert_format!(format!("Could not read {}", file)));
    //         // panic!("");
    //         continue;
    //     };
    //     // println!("{}", file);

    //     x.push(FilesRich {
    //         filename: file.to_owned(),
    //         rich: RichTable::parse(&image),
    //     });
    // }
    // println!("{}", serde_json::to_string(&x).unwrap());

    // for file in pe_filepaths {
    //     let mut x: Vec<FilesSection> = vec![];
    //     let Ok(image) = VecPE::from_disk_file(file) else {
    //         // println!("{}", alert_format!(format!("Could not read {}", file)));
    //         // panic!("");
    //         continue;
    //     };
    //     // println!("{}", file);
    //     x.push(FilesSection {
    //         filename: file.to_owned(),
    //         section: Section::parse(&image),
    //     });
    //     println!("{}", serde_json::to_string(&x).unwrap());
    // }

    // let mut x: Vec<FilesDebug> = vec![];
    // for file in pe_filepaths {
    //     let Ok(image) = VecPE::from_disk_file(file) else {
    //         // println!("{}", alert_format!(format!("Could not read {}", file)));
    //         // panic!("");
    //         continue;
    //     };
    //     match DebugEntries::parse(&image) {
    //         Ok(dbg) => x.push(FilesDebug {
    //             filename: file.to_owned(),
    //             dbg: dbg,
    //         }),
    //         Err(_) => {}
    //     };
    //     // println!("{}", file);

    //     println!("{}", serde_json::to_string(&x).unwrap());
    // }
}
