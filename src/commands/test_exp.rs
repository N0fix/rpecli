use crate::{
    alert_format, alert_format_if, color_format_if,
    utils::{
        debug::DebugEntries,
        export::{pexp, Exports},
        import::{pimp, Imports},
        rich::RichTable,
        sections::{Section, SectionTable},
    },
    warn_format, warn_format_if,
};
use colored::Colorize;
use exe::VecPE;
use serde::{Deserialize, Serialize};

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

// Export
// Import
// Rich
// Sections
// Debug
pub fn test_cmd(pe_filepaths: &Vec<String>) {
    let mut x: Vec<FilesExport> = vec![];

    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            // println!("{}", alert_format!(format!("Could not read {}", file)));
            // panic!("");
            continue;
        };
        // println!("{}", file);

        x.push(FilesExport {
            filename: file.to_owned(),
            exports: pexp(&image),
        });
    }
    println!("{}", serde_json::to_string(&x).unwrap());

    let mut x: Vec<FilesImport> = vec![];

    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            // println!("{}", alert_format!(format!("Could not read {}", file)));
            // panic!("");
            continue;
        };
        // println!("{}", file);

        x.push(FilesImport {
            filename: file.to_owned(),
            imports: pimp(&image),
        });
    }
    println!("{}", serde_json::to_string(&x).unwrap());

    let mut x: Vec<FilesRich> = vec![];
    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            // println!("{}", alert_format!(format!("Could not read {}", file)));
            // panic!("");
            continue;
        };
        // println!("{}", file);

        x.push(FilesRich {
            filename: file.to_owned(),
            rich: RichTable::parse_pe(&image),
        });
    }
    println!("{}", serde_json::to_string(&x).unwrap());

    for file in pe_filepaths {
        let mut x: Vec<FilesSection> = vec![];
        let Ok(image) = VecPE::from_disk_file(file) else {
            // println!("{}", alert_format!(format!("Could not read {}", file)));
            // panic!("");
            continue;
        };
        // println!("{}", file);
        x.push(FilesSection {
            filename: file.to_owned(),
            section: Section::parse_pe(&image),
        });
        println!("{}", serde_json::to_string(&x).unwrap());
    }

    let mut x: Vec<FilesDebug> = vec![];
    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            // println!("{}", alert_format!(format!("Could not read {}", file)));
            // panic!("");
            continue;
        };
        match DebugEntries::parse(&image) {
            Ok(dbg) => x.push(FilesDebug {
                filename: file.to_owned(),
                dbg: dbg,
            }),
            Err(_) => {}
        };
        // println!("{}", file);

        println!("{}", serde_json::to_string(&x).unwrap());
    }
}
