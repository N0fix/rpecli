// Copyright (c) 2016-2018 Casper <CasualX@users.noreply.github.com>
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// References:
//
// * https://github.com/dishather/richprint
// * https://ntcore.com/?p=27
// * https://securelist.com/the-devils-in-the-rich-header/84348/
// * http://bytepointer.com/articles/the_microsoft_rich_header.htm
// * http://bytepointer.com/articles/rich_header_lifewire_vxmags_29A-8.009.htm
// * https://pdfs.semanticscholar.org/44ad/fa896e6598b1723507060126125a0cad39a1.pdf

use dataview::PodMethods;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    iter, mem, result,
};

use phf::phf_map;

use crate::utils::rich_headers::rich_utils_err::Error;

use super::rich_utils_err;

/// From https://github.com/RichHeaderResearch/RichPE/blob/master/spoof_check.py
/// (Thanks !)
static KNOWN_PRODUCT_IDS: phf::Map<u16, &'static str> = phf_map! {
  0u16 => "Unknown",
  1u16 => "Import0",
  2u16 => "Linker510",
  3u16 => "Cvtomf510",
  4u16 => "Linker600",
  5u16 => "Cvtomf600",
  6u16 => "Cvtres500",
  7u16 => "Utc11_Basic",
  8u16 => "Utc11_C",
  9u16 => "Utc12_Basic",
  10u16 => "Utc12_C",
  11u16 => "Utc12_CPP",
  12u16 => "AliasObj60",
  13u16 => "VisualBasic60",
  14u16 => "Masm613",
  15u16 => "Masm710",
  16u16 => "Linker511",
  17u16 => "Cvtomf511",
  18u16 => "Masm614",
  19u16 => "Linker512",
  20u16 => "Cvtomf512",
  21u16 => "Utc12_C_Std",
  22u16 => "Utc12_CPP_Std",
  23u16 => "Utc12_C_Book",
  24u16 => "Utc12_CPP_Book",
  25u16 => "Implib700",
  26u16 => "Cvtomf700",
  27u16 => "Utc13_Basic",
  28u16 => "Utc13_C",
  29u16 => "Utc13_CPP",
  30u16 => "Linker610",
  31u16 => "Cvtomf610",
  32u16 => "Linker601",
  33u16 => "Cvtomf601",
  34u16 => "Utc12_1_Basic",
  35u16 => "Utc12_1_C",
  36u16 => "Utc12_1_CPP",
  37u16 => "Linker620",
  38u16 => "Cvtomf620",
  39u16 => "AliasObj70",
  40u16 => "Linker621",
  41u16 => "Cvtomf621",
  42u16 => "Masm615",
  43u16 => "Utc13_LTCG_C",
  44u16 => "Utc13_LTCG_CPP",
  45u16 => "Masm620",
  46u16 => "ILAsm100",
  47u16 => "Utc12_2_Basic",
  48u16 => "Utc12_2_C",
  49u16 => "Utc12_2_CPP",
  50u16 => "Utc12_2_C_Std",
  51u16 => "Utc12_2_CPP_Std",
  52u16 => "Utc12_2_C_Book",
  53u16 => "Utc12_2_CPP_Book",
  54u16 => "Implib622",
  55u16 => "Cvtomf622",
  56u16 => "Cvtres501",
  57u16 => "Utc13_C_Std",
  58u16 => "Utc13_CPP_Std",
  59u16 => "Cvtpgd1300",
  60u16 => "Linker622",
  61u16 => "Linker700",
  62u16 => "Export622",
  63u16 => "Export700",
  64u16 => "Masm700",
  65u16 => "Utc13_POGO_I_C",
  66u16 => "Utc13_POGO_I_CPP",
  67u16 => "Utc13_POGO_O_C",
  68u16 => "Utc13_POGO_O_CPP",
  69u16 => "Cvtres700",
  70u16 => "Cvtres710p",
  71u16 => "Linker710p",
  72u16 => "Cvtomf710p",
  73u16 => "Export710p",
  74u16 => "Implib710p",
  75u16 => "Masm710p",
  76u16 => "Utc1310p_C",
  77u16 => "Utc1310p_CPP",
  78u16 => "Utc1310p_C_Std",
  79u16 => "Utc1310p_CPP_Std",
  80u16 => "Utc1310p_LTCG_C",
  81u16 => "Utc1310p_LTCG_CPP",
  82u16 => "Utc1310p_POGO_I_C",
  83u16 => "Utc1310p_POGO_I_CPP",
  84u16 => "Utc1310p_POGO_O_C",
  85u16 => "Utc1310p_POGO_O_CPP",
  86u16 => "Linker624",
  87u16 => "Cvtomf624",
  88u16 => "Export624",
  89u16 => "Implib624",
  90u16 => "Linker710",
  91u16 => "Cvtomf710",
  92u16 => "Export710",
  93u16 => "Implib710",
  94u16 => "Cvtres710",
  95u16 => "Utc1310_C",
  96u16 => "Utc1310_CPP",
  97u16 => "Utc1310_C_Std",
  98u16 => "Utc1310_CPP_Std",
  99u16 => "Utc1310_LTCG_C",
  100u16 => "Utc1310_LTCG_CPP",
  101u16 => "Utc1310_POGO_I_C",
  102u16 => "Utc1310_POGO_I_CPP",
  103u16 => "Utc1310_POGO_O_C",
  104u16 => "Utc1310_POGO_O_CPP",
  105u16 => "AliasObj710",
  106u16 => "AliasObj710p",
  107u16 => "Cvtpgd1310",
  108u16 => "Cvtpgd1310p",
  109u16 => "Utc1400_C",
  110u16 => "Utc1400_CPP",
  111u16 => "Utc1400_C_Std",
  112u16 => "Utc1400_CPP_Std",
  113u16 => "Utc1400_LTCG_C",
  114u16 => "Utc1400_LTCG_CPP",
  115u16 => "Utc1400_POGO_I_C",
  116u16 => "Utc1400_POGO_I_CPP",
  117u16 => "Utc1400_POGO_O_C",
  118u16 => "Utc1400_POGO_O_CPP",
  119u16 => "Cvtpgd1400",
  120u16 => "Linker800",
  121u16 => "Cvtomf800",
  122u16 => "Export800",
  123u16 => "Implib800",
  124u16 => "Cvtres800",
  125u16 => "Masm800",
  126u16 => "AliasObj800",
  127u16 => "PhoenixPrerelease",
  128u16 => "Utc1400_CVTCIL_C",
  129u16 => "Utc1400_CVTCIL_CPP",
  130u16 => "Utc1400_LTCG_MSIL",
  131u16 => "Utc1500_C",
  132u16 => "Utc1500_CPP",
  133u16 => "Utc1500_C_Std",
  134u16 => "Utc1500_CPP_Std",
  135u16 => "Utc1500_CVTCIL_C",
  136u16 => "Utc1500_CVTCIL_CPP",
  137u16 => "Utc1500_LTCG_C",
  138u16 => "Utc1500_LTCG_CPP",
  139u16 => "Utc1500_LTCG_MSIL",
  140u16 => "Utc1500_POGO_I_C",
  141u16 => "Utc1500_POGO_I_CPP",
  142u16 => "Utc1500_POGO_O_C",
  143u16 => "Utc1500_POGO_O_CPP",

  144u16 => "Cvtpgd1500",
  145u16 => "Linker900",
  146u16 => "Export900",
  147u16 => "Implib900",
  148u16 => "Cvtres900",
  149u16 => "Masm900",
  150u16 => "AliasObj900",
  151u16 => "Resource900",

  152u16 => "AliasObj1000",
  154u16 => "Cvtres1000",
  155u16 => "Export1000",
  156u16 => "Implib1000",
  157u16 => "Linker1000",
  158u16 => "Masm1000",

  170u16 => "Utc1600_C",
  171u16 => "Utc1600_CPP",
  172u16 => "Utc1600_CVTCIL_C",
  173u16 => "Utc1600_CVTCIL_CPP",
  174u16 => "Utc1600_LTCG_C ",
  175u16 => "Utc1600_LTCG_CPP",
  176u16 => "Utc1600_LTCG_MSIL",
  177u16 => "Utc1600_POGO_I_C",
  178u16 => "Utc1600_POGO_I_CPP",
  179u16 => "Utc1600_POGO_O_C",
  180u16 => "Utc1600_POGO_O_CPP",

  183u16 => "Linker1010",
  184u16 => "Export1010",
  185u16 => "Implib1010",
  186u16 => "Cvtres1010",
  187u16 => "Masm1010",
  188u16 => "AliasObj1010",

  199u16 => "AliasObj1100",
  201u16 => "Cvtres1100",
  202u16 => "Export1100",
  203u16 => "Implib1100",
  204u16 => "Linker1100",
  205u16 => "Masm1100",

  206u16 => "Utc1700_C",
  207u16 => "Utc1700_CPP",
  208u16 => "Utc1700_CVTCIL_C",
  209u16 => "Utc1700_CVTCIL_CPP",
  210u16 => "Utc1700_LTCG_C ",
  211u16 => "Utc1700_LTCG_CPP",
  212u16 => "Utc1700_LTCG_MSIL",
  213u16 => "Utc1700_POGO_I_C",
  214u16 => "Utc1700_POGO_I_CPP",
  215u16 => "Utc1700_POGO_O_C",
  216u16 => "Utc1700_POGO_O_CPP",

  219u16 => "Cvtres1200",
  220u16 => "Export1200",
  221u16 => "Implib1200",
  222u16 => "Linker1200",
  223u16 => "Masm1200",
  // Speculation
  224u16 => "AliasObj1200",

  237u16 => "Cvtres1210",
  238u16 => "Export1210",
  239u16 => "Implib1210",
  240u16 => "Linker1210",
  241u16 => "Masm1210",
  // Speculation
  242u16 => "Utc1810_C",
  243u16 => "Utc1810_CPP",
  244u16 => "Utc1810_CVTCIL_C",
  245u16 => "Utc1810_CVTCIL_CPP",
  246u16 => "Utc1810_LTCG_C ",
  247u16 => "Utc1810_LTCG_CPP",
  248u16 => "Utc1810_LTCG_MSIL",
  249u16 => "Utc1810_POGO_I_C",
  250u16 => "Utc1810_POGO_I_CPP",
  251u16 => "Utc1810_POGO_O_C",
  252u16 => "Utc1810_POGO_O_CPP",

  255u16 => "Cvtres1400",
  256u16 => "Export1400",
  257u16 => "Implib1400",
  258u16 => "Linker1400",
  259u16 => "Masm1400",

  260u16 => "Utc1900_C",
  261u16 => "Utc1900_CPP",
  // Speculation
  262u16 => "Utc1900_CVTCIL_C",
  263u16 => "Utc1900_CVTCIL_CPP",
  264u16 => "Utc1900_LTCG_C ",
  265u16 => "Utc1900_LTCG_CPP",
  266u16 => "Utc1900_LTCG_MSIL",
  267u16 => "Utc1900_POGO_I_C",
  268u16 => "Utc1900_POGO_I_CPP",
  269u16 => "Utc1900_POGO_O_C",
  270u16 => "Utc1900_POGO_O_CPP"
};

//----------------------------------------------------------------

// The Rich structure:
// 'DanS' ^ x, x, x, x,
// compid ^ x, revision ^ x, ...
// 'Rich', x
// padding, ...

const DANS_MARKER: u32 = 0x536e6144; // "DanS"
const RICH_MARKER: u32 = 0x68636952; // "Rich"

/// Rich structure.
#[derive(Copy, Clone)]
pub struct RichStructure<'a> {
    dos_stub: &'a [u32],
    image: &'a [u32],
}
impl<'a> RichStructure<'a> {
    pub(crate) fn try_from(image: &'a [u32]) -> Result<RichStructure<'a>, rich_utils_err::Error> {
        // Read as a slice of dwords up until the PE headers
        let image = image
            .get(15)
            .and_then(|e_lfanew| image.get(..(e_lfanew / 4) as usize))
            .ok_or(Error::Invalid)?;

        // Skip the padding zeroes
        let mut end = image.len();
        loop {
            if end < 16 {
                return Err(Error::Invalid);
            }
            if image[end - 1] != 0 {
                break;
            }
            end -= 1;
        }
        let end = end;

        // Find the Rich marker and the xor key
        if image[end - 2] != RICH_MARKER {
            return Err(Error::BadMagic);
        }
        let x = image[end - 1];
        let dx = DANS_MARKER ^ x;

        // Scan to find the header block
        let mut start = end - 6;
        loop {
            if start < 16 {
                return Err(Error::Invalid);
            }
            if image[start] == dx
                && image[start + 1] == x
                && image[start + 2] == x
                && image[start + 3] == x
            {
                break;
            }
            start -= 2;
        }
        let start = start;

        // Everything before is the dos stub
        let dos_stub = &image[..start];
        let image = &image[start..end];

        Ok(RichStructure { dos_stub, image })
    }
    /// Returns the Rich image without the padding.
    pub fn image(&self) -> &'a [u32] {
        self.image
    }
    /// Calculate the checksum.
    ///
    /// The checksum should be equal to the xor key.
    pub fn checksum(&self) -> u32 {
        Self::_checksum(self.dos_stub, self.records())
    }
    fn _checksum<I>(dos_stub: &[u32], records: I) -> u32
    where
        I: Iterator<Item = RichRecord>,
    {
        let mut csum = mem::size_of_val(dos_stub) as u32;

        let mut i = 0;
        for dword in dos_stub {
            // Zero the e_lfanew field
            let bytes = if i == 0x3c {
                [0; 4]
            } else {
                unsafe { *(dword as *const _ as *const [u8; 4]) }
            };
            // Accumulate
            csum = u32::wrapping_add(csum, (bytes[0] as u32).rotate_left(i + 0));
            csum = u32::wrapping_add(csum, (bytes[1] as u32).rotate_left(i + 1));
            csum = u32::wrapping_add(csum, (bytes[2] as u32).rotate_left(i + 2));
            csum = u32::wrapping_add(csum, (bytes[3] as u32).rotate_left(i + 3));
            i += 4;
        }

        for record in records {
            let value = (record.product as u32) << 16 | (record.build as u32);
            csum = u32::wrapping_add(csum, value.rotate_left(record.count));
        }

        csum
    }
    /// Gets the xor key.
    pub fn xor_key(&self) -> u32 {
        self.image[1]
    }
    /// Gets the records.
    pub fn records(&self) -> RichIter<'a> {
        let iter = &self.image[4..self.image.len() - 2];
        let key = self.xor_key();
        RichIter { iter, key }
    }
    /// Encodes a new set of records.
    ///
    /// If the destination does not have the right len, returns Err with the right len.
    /// Call encode again with destination of the returned len, destination is not modified.
    ///
    /// Returns Ok with the len of the destination when encoding was successful.
    pub fn encode(&self, records: &[RichRecord], dest: &mut [u32]) -> result::Result<usize, usize> {
        let xor_key = Self::_checksum(self.dos_stub, records.iter().cloned());
        let n = records.len();
        let total_size = ((xor_key / 32) % 3 + n as u32) * 8 + 0x20;
        let total_len = (total_size / 4) as usize;
        if dest.len() < n * 2 + 6 {
            Err(total_len)
        } else {
            // Write the header
            dest[0] = DANS_MARKER ^ xor_key;
            dest[1] = xor_key;
            dest[2] = xor_key;
            dest[3] = xor_key;
            // Write the records
            for (i, record) in records.iter().enumerate() {
                let values = record.encode(xor_key);
                dest[i * 2 + 4] = values[0];
                dest[i * 2 + 5] = values[1];
            }
            // Write the footer
            dest[n * 2 + 4] = RICH_MARKER;
            dest[n * 2 + 5] = xor_key;
            // Write the padding
            for i in n * 2 + 6..dest.len() {
                dest[i] = 0;
            }
            Ok(total_len)
        }
    }
}
impl<'a> fmt::Debug for RichStructure<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RichStructure")
            .field("xor_key", &self.xor_key())
            .field("checksum", &self.checksum())
            .field("records", &self.records())
            .finish()
    }
}

//----------------------------------------------------------------

/// Rich record.
///
/// Rich records contain a product identifier and its build number.
/// The count value indicates how many .obj files were linked generated by the product.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct RichRecord {
    pub build: u16,
    pub product: u16,
    pub count: u32,
}

impl RichRecord {
    /// Decodes the record with the given key.
    pub fn decode(key: u32, values: &[u32; 2]) -> RichRecord {
        let field = values[0] ^ key;
        let build = (field & 0xffff) as u16;
        let product = ((field >> 16) & 0xffff) as u16;
        let count = values[1] ^ key;
        RichRecord {
            build,
            product,
            count,
        }
    }
    /// Encodes the record with the given key.
    pub fn encode(&self, key: u32) -> [u32; 2] {
        let value = (self.product as u32) << 16 | (self.build as u32);
        [value ^ key, self.count ^ key]
    }

    /// From https://github.com/hasherezade/bearparser/blob/65d6417b1283eb64237141ee0c865bdf0f13ac73/parser/pe/RichHdrWrapper.cpp#L231
    /// (Thanks !)
    pub fn lookup_vs_version(&self) -> &'static str {
        match &self.product {
            1 => "Visual Studio",
            0x2 | 0x6 | 0xC | 0xE => "Visual Studio 97 05.00",
            0xA | 0xB | 0xD | 0x15 | 0x16 => "Visual Studio 6.0 06.00",
            0x0019..=0x0045 => "Visual Studio 2002 07.00",
            0x005a..=0x006c => "Visual Studio 2003 07.10",
            0x006d..=0x0082 => "Visual Studio 2005 08.00",
            0x0106..=0x010a => "Visual Studio 2017 14.01+",
            0x00fd..=0x0105 => "Visual Studio 2015 14.00",
            0x00eb..=0x00fc => "Visual Studio 2013 12.10",
            0x00d9..=0x00ea => "Visual Studio 2013 12.00",
            0x00c7..=0x00d8 => "Visual Studio 2012 11.00",
            0x00b5..=0x00c6 => "Visual Studio 2010 10.10",
            0x0098..=0x00b4 => "Visual Studio 2010 10.00",
            0x0083..=0x0097 => "Visual Studio 2008 09.00",
            _ => "UNKN PRODUCT",
        }
    }

    pub fn get_product_name(&self) -> &'static str {
        KNOWN_PRODUCT_IDS
            .contains_key(&self.product)
            .then(|| KNOWN_PRODUCT_IDS[&self.product])
            .or_else(|| Some(""))
            .unwrap()
    }
}

impl Display for RichRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(write!(f, "Raw data : {:#02}-{:#02}-{:#04} (build-product-count) => {:>6} - {:>4} - {:>4} => {:<17} {:<25}", 
            hex::encode((self.build).as_bytes()),
            hex::encode((self.product).as_bytes()),
            hex::encode(self.count.as_bytes()),
            &self.build,
            &self.product,
            &self.count,
            &self.get_product_name(),
            &self.lookup_vs_version(),
            // hex::encode(
            //     unsafe {
            //         std::mem::transmute::<[u32; 2], [u8; 8]>([(self.product as u32) << 16 | (self.build as u32), self.count])
            //     }
            // ),
            // &self.key,
            // hex::encode(
                // unsafe { std::mem::transmute::<[u32; 2], [u8; 8]>(self.encode(self.key)) } 
            // ),
        )?)
    }
}

//----------------------------------------------------------------

/// Defines the kinds of objects.
///
/// Rich records can identify the product used and with it the _'language'_ of the objects.
/// This allows a mapping of products and the kind of _'language'_ it was generated from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
pub enum ObjectKind {
    Unknown,
    Link,
    /// Exported symbol.
    Export,
    /// Imported symbol.
    Import,
    /// Resource object.
    Resource,
    /// Assembly object.
    Assembly,
    /// C++ object.
    #[cfg_attr(feature = "serde", serde(rename = "C++"))]
    CPP,
    /// C object.
    C,
}
impl From<u16> for ObjectKind {
    fn from(product: u16) -> ObjectKind {
        match product {
            0x00ff | 0x00c9 | 0x009a | 0x007c | 0x005e | 0x0045 | 0x0006 => ObjectKind::Resource,
            0x0100 | 0x00dc | 0x00ca | 0x009b | 0x0092 | 0x007a | 0x005c | 0x003f => {
                ObjectKind::Export
            }
            0x0101 | 0x00dd | 0x00cb | 0x009c | 0x0093 | 0x007b | 0x005d | 0x0019 | 0x0002 => {
                ObjectKind::Import
            }
            0x0102 | 0x00de | 0x00cc | 0x009d | 0x0091 | 0x0078 | 0x005a | 0x003d | 0x0004 => {
                ObjectKind::Link
            }
            0x0103 | 0x00df | 0x00cd | 0x009e | 0x0095 | 0x007d | 0x000f | 0x0040 => {
                ObjectKind::Assembly
            }
            0x0104 | 0x00e0 | 0x00ce | 0x00aa | 0x0083 | 0x006d | 0x005f | 0x001c | 0x000a
            | 0x0015 => ObjectKind::C,
            0x0105 | 0x00e1 | 0x00cf | 0x00ab | 0x0084 | 0x006e | 0x0060 | 0x001d | 0x000b
            | 0x0016 => ObjectKind::CPP,

            0x0001 => ObjectKind::Import,
            _ => ObjectKind::Unknown,
        }
    }
}

//----------------------------------------------------------------

/// Iterator over the Rich records.
#[derive(Clone)]
pub struct RichIter<'a> {
    iter: &'a [u32],
    key: u32,
}
impl<'a> Iterator for RichIter<'a> {
    type Item = RichRecord;
    fn next(&mut self) -> Option<RichRecord> {
        if self.iter.len() >= 2 {
            let record = RichRecord::decode(self.key, &[self.iter[0], self.iter[1]]);
            self.iter = &self.iter[2..];
            Some(record)
        } else {
            None
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.iter.len() / 2;
        (len, Some(len))
    }
    fn count(self) -> usize {
        self.size_hint().0
    }
    fn nth(&mut self, n: usize) -> Option<RichRecord> {
        if self.iter.len() >= n * 2 + 2 {
            let record = RichRecord::decode(self.key, &[self.iter[n * 2], self.iter[n * 2 + 1]]);
            self.iter = &self.iter[n * 2 + 2..];
            Some(record)
        } else {
            self.iter = &self.iter[..0];
            None
        }
    }
}
impl<'a> DoubleEndedIterator for RichIter<'a> {
    fn next_back(&mut self) -> Option<RichRecord> {
        let len = self.iter.len();
        if len >= 2 {
            let record = RichRecord::decode(self.key, &[self.iter[len - 2], self.iter[len - 1]]);
            self.iter = &self.iter[..len - 2];
            Some(record)
        } else {
            None
        }
    }
}
impl<'a> ExactSizeIterator for RichIter<'a> {}
impl<'a> iter::FusedIterator for RichIter<'a> {}
impl<'a> fmt::Debug for RichIter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

//----------------------------------------------------------------

/*
   "rich_structure": {
       "xor_key": 129284757318,
       "checksum": 129284757318,
       "records": [
           {
               "build": 6030,
               "product": 95,
               "count": 68,
           },
       ]
   },
*/
