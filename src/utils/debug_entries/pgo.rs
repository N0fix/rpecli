use std::{
    ffi::CStr,
    fmt::{self, Display},
    io::Read,
    slice,
};

use bytemuck::cast_slice;
use exe::VecPE;
use pkbuffer::Buffer;

use crate::utils::debug::{DebugEntry, ImageDebugType, ReadError, ReadFrom};

/// PGO information.
#[derive(Copy, Clone)]
pub struct Pgo<'a> {
    pub image: &'a [u32],
}

impl<'a> Pgo<'a> {
    /// Gets the underlying image.
    pub fn image(&self) -> &'a [u32] {
        self.image
    }
    /// Iterator over the PGO sections.
    pub fn iter(&self) -> PgoIter<'a> {
        let image = if self.image.len() >= 1 {
            &self.image[1..]
        } else {
            self.image
        };
        PgoIter { image }
    }
}

impl Display for Pgo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  PGO:")?;
        for item in self.iter() {
            writeln!(
                f,
                "    {:#08x} {:#?} (size : {:#x})",
                item.rva, item.name, item.size
            )?;
        }

        Ok(())
    }
}

impl<'a> IntoIterator for Pgo<'a> {
    type Item = PgoItem<'a>;
    type IntoIter = PgoIter<'a>;
    fn into_iter(self) -> PgoIter<'a> {
        self.iter()
    }
}

impl fmt::Debug for Pgo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'pe> ReadFrom<'pe> for Pgo<'pe> {
    //     // type Error = &'static str;

    fn read_debug_from(
        debug_directory: &DebugEntry,
        pe: &'pe VecPE,
    ) -> Result<Pgo<'pe>, ReadError> {
        match ImageDebugType::from_u32(debug_directory.type_) {
            ImageDebugType::Pogo => {
                let x: &[u8] = pe
                    .read(
                        debug_directory.pointer_to_raw_data as usize,
                        debug_directory.size_of_data as usize,
                    )
                    .unwrap();
                Ok(Pgo {
                    image: cast_slice(&x[0..]),
                })
            }
            _ => Err(ReadError::InvalidType),
        }
    }
}

/// Iterator over PGO sections.
#[derive(Clone)]
pub struct PgoIter<'a> {
    image: &'a [u32],
}
impl<'a> Iterator for PgoIter<'a> {
    type Item = PgoItem<'a>;
    fn next(&mut self) -> Option<PgoItem<'a>> {
        if self.image.len() >= 3 {
            let rva = self.image[0];
            let size = self.image[1];
            let name = CStr::from_bytes_until_nul(dataview::bytes(&self.image[2..])).unwrap();
            let len = name.to_str().unwrap().len() >> 2;
            self.image = &self.image[2 + len + 1..];
            Some(PgoItem { rva, size, name })
        } else {
            None
        }
    }
}
/// Describes a PGO section.
#[derive(Copy, Clone, Debug)]
pub struct PgoItem<'a> {
    pub rva: u32,
    pub size: u32,
    pub name: &'a CStr,
}
