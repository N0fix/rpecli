use exe::pe::{VecPE, PE};
use exe::types::CCharString;
use exe::{Buffer, SectionCharacteristics};
extern crate argparse;
use argparse::{ArgumentParser, Store};
mod commands;
mod import_export;
mod rich;
mod sig;
mod util;
mod utils;
mod format;
use crate::commands::info::display_info;
use crate::import_export::{display_exports, display_imports};
use crate::rich::display_rich;
use crate::sig::{display_sig, display_version_info};
use crate::utils::pe_size::get_pe_size;
use crate::utils::sections::display_sections;
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
    Remove(PEArgs),
}

impl FromArgMatches for CliSub {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        match matches.subcommand() {
            Some(("info", args)) => Ok(Self::Info(PEArgs::from_arg_matches(args)?)),
            Some(("remove", args)) => Ok(Self::Remove(PEArgs::from_arg_matches(args)?)),
            Some((_, _)) => Err(Error::raw(
                ErrorKind::InvalidSubcommand,
                "Valid subcommands are `info` and `remove`",
            )),
            None => Err(Error::raw(
                ErrorKind::MissingSubcommand,
                "Valid subcommands are `info` and `remove`",
            )),
        }
    }
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), Error> {
        match matches.subcommand() {
            Some(("info", args)) => *self = Self::Info(PEArgs::from_arg_matches(args)?),
            Some(("remove", args)) => *self = Self::Remove(PEArgs::from_arg_matches(args)?),
            Some((_, _)) => {
                return Err(Error::raw(
                    ErrorKind::InvalidSubcommand,
                    "Valid subcommands are `info` and `remove`",
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
            .subcommand(PEArgs::augment_args(Command::new("remove")))
            .subcommand_required(true)
    }
    fn augment_subcommands_for_update(cmd: Command) -> Command {
        cmd.subcommand(PEArgs::augment_args(Command::new("info")))
            .subcommand(PEArgs::augment_args(Command::new("remove")))
            .subcommand_required(true)
    }
    fn has_subcommand(name: &str) -> bool {
        matches!(name, "info" | "remove")
    }
}

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long)]
    top_level: bool,
    #[command(subcommand)]
    subcommand: CliSub,
}

fn main() {
    let args = Cli::parse();
    println!("{args:#?}");
    match args.subcommand {
        CliSub::Info(args) => {
            display_info(&args.pe);
        }
        CliSub::Remove(_) => todo!(),
    };

    return;

    let mut pe_filepath = String::default();
    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("PE cli info");
        ap.refer(&mut pe_filepath)
            .add_argument("pe_filepath", Store, "")
            .required();
        ap.parse_args_or_exit();
    }
    let image = VecPE::from_disk_file(pe_filepath).unwrap();
    // dbg!(pe_filepath);
    println!("Sections:\n==============================================");
    display_sections(&image);
    println!("");

    println!("PE Info:\n==============================================");
    let pe_size = get_pe_size(&image);
    println!(
        "File size {:#x}, pe size {:#x}\n",
        image.as_slice().len(),
        pe_size
    );

    println!("Imports:\n==============================================");
    display_imports(&image);
    println!("");
    println!("Exports:\n==============================================");
    display_exports(&image);

    // display_version_info(&image);

    display_sig(&image);

    display_rich(&image);
}
