use std::fmt::Display;

use crate::utils::rich_headers::rich_utils::{ObjectKind, RichIter, RichRecord, RichStructure};
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use bytemuck::cast_slice;
use colored::Colorize;
use exe::VecPE;
use phf::phf_map;
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;
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

/// From https://github.com/hasherezade/bearparser/blob/65d6417b1283eb64237141ee0c865bdf0f13ac73/parser/pe/RichHdrWrapper.cpp#L231
/// (Thanks !)
fn lookup_vs_version(product_id: u16) -> &'static str {
    match product_id {
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
        _ => "UNKN",
    }
}

struct Rich<'rich_data> {
    product_name: &'rich_data str,
    build: u16,
    product_id: u16,
    count: u32,
    guessed_visual_studio_version: &'rich_data str,
}

impl Rich<'_> {
    pub fn parse_pe(pe: &VecPE) -> RichTable {
        let mut rich_table: RichTable = RichTable {
            rich_headers: vec![],
        };
        let ptr_buf = pe.get_buffer().as_ref();
        if ptr_buf.len() < 0x400 {
            return rich_table;
        }
        let rich_header = match RichStructure::try_from(cast_slice(&ptr_buf[0..0x400])) {
            Ok(rich) => rich,
            Err(_) => {
                return rich_table;
            }
        };

        for record in rich_header.records() {
            let product_name = KNOWN_PRODUCT_IDS
                .contains_key(&record.product)
                .then(|| KNOWN_PRODUCT_IDS[&record.product])
                .or_else(|| Some(""))
                .unwrap();

            rich_table.rich_headers.push(Rich {
                product_name: product_name,
                build: record.build,
                product_id: record.product,
                count: record.count,
                guessed_visual_studio_version: lookup_vs_version(record.product),
            })
        }

        rich_table
    }
}

struct RichTable<'rich_data> {
    rich_headers: Vec<Rich<'rich_data>>,
}

impl Display for RichTable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rich_headers.len() == 0 {
            return write!(f, "{}", warn_format!("No rich headers"));
        }

        let mut table = Table::new();
        table.max_column_width = term_size::dimensions()
            .or_else(|| Some((4000, 4000)))
            .unwrap()
            .0;
        table.style = term_table::TableStyle::empty();
        table.separate_rows = false;

        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(
                "Product Name".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Build".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Product ID".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Count".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
            TableCell::new_with_alignment(
                "Guessed Visual Studio version".bold(),
                1,
                term_table::table_cell::Alignment::Left,
            ),
        ]));

        for rich in self.rich_headers.iter() {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(
                    &rich.product_name,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.build,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.product_id,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.count,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
                TableCell::new_with_alignment(
                    &rich.guessed_visual_studio_version,
                    1,
                    term_table::table_cell::Alignment::Left,
                ),
            ]));
        }
        write!(f, "{}", table.render())
    }
}

pub fn display_rich(pe: &VecPE) {
    let richs = Rich::parse_pe(pe);
    println!("{}", richs);
}
