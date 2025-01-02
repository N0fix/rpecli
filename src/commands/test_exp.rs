use crate::{
    alert_format, alert_format_if, color_format_if,
    utils::{
        self, debug::DebugEntries, export::{pexp, Exports}, import::{pimp, Imports}, rich::RichTable, rich_headers::rich_utils::RichRecord, rsrc::Resources, sections::{Section, SectionTable}, sig::PeAuthenticodes, tls::TLSCallbacks
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
    pub sig: Option<PeAuthenticodes>,
    pub imports: Option<Imports>,
    pub exports: Option<Exports>,
    pub dbg: Option<DebugEntries>,
    pub rsrc: Option<Resources>,
    pub tls: Option<TLSCallbacks>,
}

pub fn test_cmd(pe_filepaths: &Vec<String>) {
    // let mut x: Vec<FilesExport> = vec![];

    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            continue;
        };
        let rich_entries = RichTable::parse(&image).rich_entries;
        let file_desc = FileDescription {
            filename: file.to_string(),
            sections: Section::parse(&image).sections,
            rich: match rich_entries.len() {
                0 => None,
                sz => Some(rich_entries),
            },
            dbg: DebugEntries::parse(&image).ok(),
            sig: PeAuthenticodes::parse(&image).ok(),
            imports: pimp(&image),
            exports: pexp(&image),
            rsrc: match Resources::parse(&image).ok() {
                Some(r) => r,
                None => None,
            },
            tls: match TLSCallbacks::parse(&image).ok() {
                Some(t) => t,
                None => None,
            }
        };
        write!(stdout(), "{}\n", serde_json::to_string(&file_desc).unwrap());
    }
}
