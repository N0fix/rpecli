use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use authenticode::AttributeCertificateError;
use colored::Colorize;
use exe::VecPE;
use rpecli::utils::sig::PeAuthenticodes;

use crate::utils::sig::display_sig;
use std::io::{stdout, Write};

fn display_signature(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {}", pe_filepath))
        );
        return;
    };
    display_sig(&image);
}

pub fn sig_cmd(pe_filepaths: &Vec<String>, json_print: bool) {
    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            println!(
                "{}",
                alert_format!(format!("Could not read {}", file))
            );
            return;
        };
        let sigs = match PeAuthenticodes::parse(&image) {
            Ok(sigs) => sigs,
            Err(e) => match e {
                AttributeCertificateError::OutOfBounds => {
                    println!(
                        "{}",
                        alert_format!("Security directory exists, but is out of bounds")
                    );
                    return;
                }
                AttributeCertificateError::InvalidSize => {
                    println!(
                        "{}",
                        alert_format!("Security directory exists, but signature has an invalid size")
                    );
                    return;
                }
                AttributeCertificateError::InvalidCertificateSize { size }=> {
                    println!("{}", alert_format!(format!("Signature {} has an invalid size", size)));
                    return;
                }
            },
        };
        if(json_print) {
            write!(stdout(), "{}", serde_json::to_string(&sigs).unwrap());
        } else {
            println!("{}", sigs);
        }
    }
}
