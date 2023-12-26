use clap::{Parser, Subcommand};
use commands::test_exp::test_cmd;
mod commands;
mod compare;
mod disassembler;
mod format;
mod import_export;
mod util;
mod utils;
use crate::commands::disassemble::disass_section;
use crate::commands::import_export::{export_cmd, import_cmd, import_export_cmd};
use crate::commands::info::info_cmd;
use crate::commands::resource::rsrc_cmd;
use crate::commands::rich::rich_cmd;
use crate::commands::sig::sig_cmd;
use crate::commands::strings::strings_cmd;
use compare::Comparable;

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
    /// Rich headers
    Rich(RichArg),
    /// Print or dump resources
    Rsrc(RsrcArg),
    /// Print authenticode signature
    Sig(PEArgs),
    /// Disassemble section
    Disass(DisassArg),
    /// Print strings
    Strings(PEArgs),
    /// Test command for development
    Test(PEArgs),
}

/// This tool is still under development.
/// Some of the commands have a `--json` argument that outputs the result as a JSON string.
/// Try "rpecli COMMAND --help" to show help for a specific command.
/// Certain commands support multiple PE files as arguments and will compare them if you give multiple PE files.
#[derive(Parser, Debug)]
#[clap(version)]
struct Arguments {
    /// Do not compute any hashes when reading PE file. (Enabling this option should greatly improve performance)
    #[clap(short, long)]
    no_hash: bool,

    #[clap(subcommand)]
    cmd: SubCommand,
}

#[derive(Parser, Debug, Clone)]
struct PEArgs {
    /// Output as json
    #[clap(short, long)]
    json: bool,
    #[clap(required = true, value_delimiter = ' ', num_args = 1..)]
    pe: Vec<String>,
}

#[derive(Parser, Debug, Clone)]
struct RichArg {
    /// Output as json
    #[clap(short, long)]
    json: bool,
    #[clap(required = true, value_delimiter = ' ', num_args = 1..)]
    pe: Vec<String>,
}

#[derive(Parser, Debug)]
struct DisassArg {
    pe: String,
    section_name: String,
}

#[derive(Parser, Debug)]
struct RsrcArg {
    #[clap(required = true, value_delimiter = ' ', num_args = 1..)]
    pe: Vec<String>,
    /// Dump resources to <temp dir>/resources/
    #[clap(short, long)]
    dump: bool,
    /// Output as json
    #[clap(short, long)]
    json: bool,
}

fn main() {
    // let args = Cli::parse();
    let args = Arguments::parse();
    // println!("{args:#?}");
    match args.cmd {
        SubCommand::Info(subcommand_args) => {
            info_cmd(&subcommand_args.pe, !args.no_hash);
        }
        SubCommand::ImportExport(subcommand_args) => {
            import_export_cmd(&subcommand_args.pe);
        }
        SubCommand::Rsrc(subcommand_args) => {
            rsrc_cmd(
                &subcommand_args.pe,
                !args.no_hash,
                subcommand_args.dump,
                subcommand_args.json,
            );
        }
        SubCommand::Sig(subcommand_args) => {
            sig_cmd(&subcommand_args.pe, subcommand_args.json);
        }
        SubCommand::Import(subcommand_args) => {
            import_cmd(&subcommand_args.pe, subcommand_args.json)
        }
        SubCommand::Export(subcommand_args) => {
            export_cmd(&subcommand_args.pe, subcommand_args.json)
        }
        SubCommand::Disass(subcommand_args) => {
            disass_section(&subcommand_args.pe, &subcommand_args.section_name)
        }
        SubCommand::Strings(subcommand_args) => {
            strings_cmd(&subcommand_args.pe);
        }
        SubCommand::Rich(subcommand_args) => {
            rich_cmd(&subcommand_args.pe, subcommand_args.json);
        }
        SubCommand::Test(subcommand_args) => {
            test_cmd(&subcommand_args.pe);
        }
    }
}
