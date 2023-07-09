use colored::Colorize;
use exe::pe::{VecPE, PE};
use exe::types::CCharString;
use exe::{Buffer, SectionCharacteristics};
extern crate argparse;
use argparse::{ArgumentParser, Store};
mod commands;
mod format;
mod import_export;
mod rich;
mod util;
mod utils;
use crate::commands::import_export::display_import_export;
use crate::commands::info::display_info;
use crate::commands::resource::display_ressource;
use crate::commands::sig::display_signature;
use crate::import_export::{display_exports, display_imports};
use crate::rich::display_rich;
use crate::utils::pe_size::get_pe_size;
use crate::utils::sections::display_sections;
use crate::utils::sig::display_sig;
// https://github.com/clap-rs/clap/blob/master/examples/derive_ref/hand_subcommand.rs
use clap::error::{Error, ErrorKind};
use clap::{ArgMatches, Args as _, Command, FromArgMatches, Parser, Subcommand};

#[derive(Parser, Debug)]
struct PEArgs {
    pe: String,
}

#[derive(Debug)]
enum CliSub {
    Info(PEArgs),
    ImportExport(PEArgs),
    Rsrc(PEArgs),
    Sig(PEArgs),
}

impl FromArgMatches for CliSub {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        match matches.subcommand() {
            Some(("info", args)) => Ok(Self::Info(PEArgs::from_arg_matches(args)?)),
            Some(("import_export", args)) => {
                Ok(Self::ImportExport(PEArgs::from_arg_matches(args)?))
            }
            Some(("rsrc", args)) => Ok(Self::Rsrc(PEArgs::from_arg_matches(args)?)),
            Some(("sig", args)) => Ok(Self::Sig(PEArgs::from_arg_matches(args)?)),
            Some((_, _)) => Err(Error::raw(
                ErrorKind::InvalidSubcommand,
                "Valid subcommands are `info` `import_export` `rsrc` `sig` ",
            )),
            None => Err(Error::raw(
                ErrorKind::MissingSubcommand,
                "Valid subcommands are `info` `import_export` `rsrc` `sig` ",
            )),
        }
    }
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), Error> {
        match matches.subcommand() {
            Some(("info", args)) => *self = Self::Info(PEArgs::from_arg_matches(args)?),
            Some(("import_export", args)) => {
                *self = Self::ImportExport(PEArgs::from_arg_matches(args)?)
            }
            Some(("rsrc", args)) => *self = Self::Rsrc(PEArgs::from_arg_matches(args)?),
            Some(("sig", args)) => *self = Self::Rsrc(PEArgs::from_arg_matches(args)?),
            Some((_, _)) => {
                return Err(Error::raw(
                    ErrorKind::InvalidSubcommand,
                    "Valid subcommands are `info` `import_export` `rsrc` `sig`",
                ))
            }
            None => (),
        };
        Ok(())
    }
}

impl Subcommand for CliSub {
    fn augment_subcommands(cmd: Command) -> Command {
        cmd.subcommand(PEArgs::augment_args(Command::new("info")))
            .subcommand(PEArgs::augment_args(Command::new("import_export")))
            .subcommand(PEArgs::augment_args(Command::new("rsrc")))
            .subcommand(PEArgs::augment_args(Command::new("sig")))
            .subcommand_required(true)
    }
    fn augment_subcommands_for_update(cmd: Command) -> Command {
        cmd.subcommand(PEArgs::augment_args(Command::new("info")))
            .subcommand(PEArgs::augment_args(Command::new("import_export")))
            .subcommand(PEArgs::augment_args(Command::new("rsrc")))
            .subcommand(PEArgs::augment_args(Command::new("sig")))
            .subcommand_required(true)
    }
    fn has_subcommand(name: &str) -> bool {
        matches!(name, "info" | "import_export | rsrc | sig")
    }
}

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long)]
    no_hashes: bool,
    #[command(subcommand)]
    subcommand: CliSub,
}

fn main() {
    let args = Cli::parse();
    let hashes = if args.no_hashes { false } else { true };
    println!("{args:#?}");
    match args.subcommand {
        CliSub::Info(args) => {
            display_info(&args.pe);
        }
        CliSub::ImportExport(args) => {
            display_import_export(&args.pe);
        }
        CliSub::Rsrc(args) => {
            display_ressource(&args.pe, hashes);
        }
        CliSub::Sig(args) => {
            display_signature(&args.pe);
        }
    };
}
