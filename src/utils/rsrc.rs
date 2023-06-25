use exe::{ResourceDirectory, VecPE, ResourceDirectoryID, ImageResourceDirStringU, ResourceID, ImageResourceDirectoryEntry, WCharString, ResolvedDirectoryData, ResourceDirectoryData, ImageResourceDataEntry};
use exe::pe::{PE};
use exe::types::{CCharString, ImportData, ImportDirectory};
use exe::ResolvedDirectoryData::{Directory, Data};
use exe::{
    Buffer, ImageDirectoryEntry,
    ResolvedDirectoryID,  ResourceDirectoryMut,
};

pub fn ResolvedDirectoryID_to_string(id: ResolvedDirectoryID) -> String {
    match id {
        ResolvedDirectoryID::ID(id) => return resource_id_to_type(ResourceID::from_u32(id)),
        ResolvedDirectoryID::Name(id) => return id,
    }
}

pub fn resource_id_to_type(id: ResourceID) -> String {
    return match id {
        ResourceID::Cursor => "Cursor".to_owned(),
        ResourceID::Bitmap => "Bitmap".to_owned(),
        ResourceID::Icon => "Icon".to_owned(),
        ResourceID::Menu => "Menu".to_owned(),
        ResourceID::Dialog => "Dialog".to_owned(),
        ResourceID::String => "String".to_owned(),
        ResourceID::FontDir => "FontDir".to_owned(),
        ResourceID::Font => "Font".to_owned(),
        ResourceID::Accelerator => "Accelerator".to_owned(),
        ResourceID::RCData => "RCData".to_owned(),
        ResourceID::MessageTable => "MessageTable".to_owned(),
        ResourceID::GroupCursor => "GroupCursor".to_owned(),
        ResourceID::Reserved => "Reserved".to_owned(),
        ResourceID::GroupIcon => "GroupIcon".to_owned(),
        ResourceID::Reserved2 => "Reserved2".to_owned(),
        ResourceID::Version => "Version".to_owned(),
        ResourceID::DlgInclude => "DlgInclude".to_owned(),
        ResourceID::Reserved3 => "Reserved3".to_owned(),
        ResourceID::PlugPlay => "PlugPlay".to_owned(),
        ResourceID::VXD => "VXD".to_owned(),
        ResourceID::AniCursor => "AniCursor".to_owned(),
        ResourceID::AniIcon => "AniIcon".to_owned(),
        ResourceID::HTML => "HTML".to_owned(),
        ResourceID::Manifest => "Manifest".to_owned(),
        ResourceID::Unknown => "Unknown".to_owned(),
    };
}

pub fn display_rsrc(pe: &VecPE) {
    let rsrc = match ResourceDirectory::parse(pe) {
        Ok(r) => r,
        Err(_) => {
            println!("No resource");
            return;
        },
    };
    // println!("{} resource(s)\n", rsrc.root_node.directory.entries());
    for entry in rsrc.resources {
        let data_entry = entry.get_data_entry(pe).unwrap();
        let resource_directory_name = ResolvedDirectoryID_to_string(entry.type_id);
        println!("{} (offset: {:x}) rsrc {:?}: lang {:?}", resource_directory_name, entry.data.0, entry.rsrc_id, entry.lang_id);

        // TODO : display with verbose on certain types.
        // TODO : mode to dump rsrc directly to a file.
        if resource_directory_name == "Manifest" {
            let data = data_entry.read(pe).unwrap();
            println!("\n[DUMPED]\n{}", std::str::from_utf8(data).unwrap());
        }
    }
}
