use exe::pe::{VecPE, PE};
use exe::types::CCharString;
use exe::{Buffer, SectionCharacteristics};
extern crate argparse;

use argparse::{ArgumentParser, Store};
mod import_export;
mod rich;
mod rich_utils;
mod rich_utils_err;
mod sig;
mod utils;
use crate::import_export::{display_exports, display_imports};
use crate::rich::display_rich;
use crate::sig::{display_sig, display_version_info};
use crate::utils::{display_sections, get_pe_size};

fn main() {
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
    let pe_size: u32 = get_pe_size(&image);
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
