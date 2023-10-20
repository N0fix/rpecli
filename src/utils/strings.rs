use crate::compare_default_impl;

use crate::{
    alert_format, alert_format_if, color_format_if, utils::strings, warn_format, warn_format_if,
};
use colored::Colorize;
use exe::VecPE;
use rust_strings::{strings, BytesConfig, Encoding};
use std::collections::HashMap;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct MatchString {
    matches: Vec<(String, u64)>,
}

pub fn get_strings(buffer: &[u8], min_size: usize) -> MatchString {
    let config = BytesConfig::new(buffer.to_vec())
        .with_min_length(min_size)
        .with_encoding(Encoding::ASCII)
        .with_encoding(Encoding::UTF16LE);

    MatchString {
        matches: strings(&config).expect("Something went wrong extracting strings."),
    }
}

pub fn display_strings(pe: &VecPE, min_size: u32) {
    let data = pe.get_buffer().as_ref();

    let extracted_strings = get_strings(data, min_size as usize);
    for str in extracted_strings.into_iter() {
        println!("{}", str);
    }
}

pub struct MatchStringIterator {
    matches: MatchString,
    index: usize,
}

impl Iterator for MatchStringIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.matches.matches.len() {
            // This impl is quite terrible since we are copying strings instead of passing references to them.
            // This severly undermines performances.
            let result = Some(self.matches.matches[self.index].0.clone());
            self.index += 1;
            result
        } else {
            None
        }
    }
}

impl IntoIterator for MatchString {
    type Item = String;

    type IntoIter = MatchStringIterator;

    fn into_iter(self) -> Self::IntoIter {
        MatchStringIterator {
            index: 0,
            matches: self,
        }
    }
}

compare_default_impl!(MatchString, String);
