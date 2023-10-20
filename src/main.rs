use clap::{Parser, Subcommand};
mod commands;
mod disassembler;
mod format;
mod import_export;
mod util;
mod utils;
use crate::commands::disassemble::disass_section;
use crate::commands::import_export::{display_exports, display_import_export, display_imports};
use crate::commands::info::display_info;
use crate::commands::resource::{display_ressource, dump_resources};
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
    /// Print or dump resources
    Rsrc(RsrcArg),
    /// Print authenticode signature
    Sig(PEArgs),
    /// Disassemble section
    Disass(DisassArg)
}

#[derive(Parser, Debug)]
#[clap(version)]
struct Arguments {
    /// Do not compute any hashes when reading PE file. (Enabling this option should greatly improve performance)
    #[clap(short, long)]
    no_hash: bool,
    #[clap(subcommand)]
    cmd: SubCommand,
}

#[derive(Parser, Debug)]
struct PEArgs {
    pe: String,
}

#[derive(Parser, Debug)]
struct DisassArg {
    pe: String,
    section_name: String
}

#[derive(Parser, Debug)]
struct RsrcArg {
    pe: String,
    /// Dump resources to /tmp/resources/
    #[clap(short, long)]
    dump: bool
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
            if subcommand_args.dump {
                dump_resources(&subcommand_args.pe);
            } else {
                display_ressource(&subcommand_args.pe, !args.no_hash);
            }
        }
        SubCommand::Sig(subcommand_args) => {
            display_signature(&subcommand_args.pe);
        }
        SubCommand::Import(subcommand_args) => display_imports(&subcommand_args.pe),
        SubCommand::Export(subcommand_args) => display_exports(&subcommand_args.pe),
        SubCommand::Disass(subcommand_args) => disass_section(&subcommand_args.pe, &subcommand_args.section_name)
    }
}
