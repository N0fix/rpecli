use exe::{
    CCharString, ImageDirectoryEntry, ImageExportDirectory, ImportData, ImportDirectory,
    PETranslation, ThunkData, ThunkFunctions, VecPE, PE, RVA,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct ImportFunction {
    /// Import function name. This can be an ordinal if `import_by_ordinal` is true.
    pub name: String,
    /// Is function imported by ordinal
    pub import_by_ordinal: bool,
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct ImportEntry {
    pub name: String,
    pub imports: Vec<ImportFunction>,
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Imports {
    pub modules: Vec<ImportEntry>,
}

impl Imports {
    pub fn parse<'data, P: PE>(pe: &'data P) -> Result<Imports, exe::Error> {
        let mut result = Imports::default();
        let import_directory = match ImportDirectory::parse(pe) {
            Ok(import_dir) => import_dir,
            Err(_) => {
                return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Import));
            }
        };

        for import in import_directory.descriptors {
            let mut entry = ImportEntry::default();

            entry.name = match import.get_name(pe) {
                Ok(n) => match n.as_str() {
                    Ok(s) => s.to_string().to_ascii_lowercase(),
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            };

            let import_entries = match import.get_imports(pe) {
                Ok(import_entries) => import_entries,
                Err(e) => {
                    return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Import));
                }
            };
            for import_data in import_entries {
                let function_name = match import_data {
                    ImportData::Ordinal(x) => x.to_string(),
                    ImportData::ImportByName(s) => s.to_string(),
                };
                let is_import_by_ordinal = matches!(import_data, ImportData::Ordinal(_));
                entry.imports.push(ImportFunction {
                    name: function_name,
                    import_by_ordinal: is_import_by_ordinal,
                });
            }

            result.modules.push(entry);
        }

        Ok(result)
    }
}

pub fn pimp(pe: &VecPE) -> Option<Imports> {
    match Imports::parse(pe) {
        Ok(imports) => Some(imports),
        Err(_) => None,
    }
}
