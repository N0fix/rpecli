use clap::{Parser, Subcommand};
use colored::Colorize;
use exe::pe::{VecPE, PE};
use exe::types::CCharString;
use exe::{Buffer, SectionCharacteristics};
mod commands;
mod disassembler;
mod format;
mod import_export;
mod util;
mod utils;
use crate::commands::import_export::{display_exports, display_import_export, display_imports};
use crate::commands::info::display_info;
use crate::commands::resource::display_ressource;
use crate::commands::sig::display_signature;

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Print all available information
    Info(PEArgs),
    /// Print both import and exports
    ImportExport(PEArgs),
    /// Print imports
    Import(PEArgs),
    /// Print exports
    Export(PEArgs),
    /// Print resources
    Rsrc(PEArgs),
    /// Print authenticode signature
    Sig(PEArgs),
}

#[derive(Parser, Debug)]
#[clap(author = "Author Name", version, about)]
/// A Very simple Package Hunter
struct Arguments {
    /// Do not compute hash of PE file. (This should greatly improve performance)
    #[clap(short, long)]
    no_hash: bool,
    #[clap(subcommand)]
    cmd: SubCommand,
}

#[derive(Parser, Debug)]
struct PEArgs {
    pe: String,
}

fn main() {
    // let args = Cli::parse();
    let args = Arguments::parse();
    println!("{args:#?}");
    match args.cmd {
        SubCommand::Info(subcommand_args) => {
            display_info(&subcommand_args.pe, !args.no_hash);
        }
        SubCommand::ImportExport(subcommand_args) => {
            display_import_export(&subcommand_args.pe);
        }
        SubCommand::Rsrc(subcommand_args) => {
            display_ressource(&subcommand_args.pe, !args.no_hash);
        }
        SubCommand::Sig(subcommand_args) => {
            display_signature(&subcommand_args.pe);
        }
        SubCommand::Import(subcommand_args) => display_imports(&subcommand_args.pe),
        SubCommand::Export(subcommand_args) => display_exports(&subcommand_args.pe),
    }
}
