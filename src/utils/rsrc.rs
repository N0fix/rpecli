use exe::{ResourceDirectory, VecPE, ResourceDirectoryID, ImageResourceDirStringU, ResourceID, ImageResourceDirectoryEntry, WCharString, ResolvedDirectoryData, ResourceDirectoryData, ImageResourceDataEntry};
use exe::pe::{PE};
use exe::types::{CCharString, ImportData, ImportDirectory};
use exe::ResolvedDirectoryData::{Directory, Data};
use exe::{
    Buffer, ImageDirectoryEntry,
    ResolvedDirectoryID,  ResourceDirectoryMut,
};

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

fn load_rsrc_root_node_entry(pe: &VecPE, entry: &ImageResourceDirectoryEntry) -> String {
    let x = match entry.get_id() {
        ResourceDirectoryID::ID(id) => resource_id_to_type(ResourceID::from_u32(id)),
        ResourceDirectoryID::Name(offset) => {
            let resolved = offset.resolve(&*pe).unwrap();
            let dir_string = ImageResourceDirStringU::parse(&*pe, resolved).unwrap();

            let string_data = dir_string.name.as_u16_str().unwrap();
            string_data.to_string()
        }
    };

    
    let data = entry.get_data();
    
    let Directory(second_level) = data.resolve(&*pe).unwrap() else { panic!("Not a second_level node"); };
    println!("{:?}   (Timestamp {:x})", x, second_level.directory.time_date_stamp);

    for third_level_entry in second_level.entries {
        
        let ResourceDirectoryID::ID(entry_id_name) = third_level_entry.get_id() else { panic!("Last level should not have ResourceOffset"); };
        println!("\t=> {:10}: {:?} {}", "Name", entry_id_name, third_level_entry.name.get_dword());
        if x == "Manifest" {
            let data = entry.get_data();
            let resolved: ResolvedDirectoryData = ResourceDirectoryData::resolve(&data, pe).unwrap();
            // pe.get_ref::<ImageResourceDataEntry>(data);
        }
    }
    println!("");

    return x;
}

pub fn display_rsrc(pe: &VecPE) {
    let rsrc = match ResourceDirectory::parse(pe) {
        Ok(r) => r,
        Err(_) => {
            println!("No resource");
            return;
        },
    };
    println!("{} resource(s)\n", rsrc.root_node.directory.entries());
    for entry in rsrc.root_node.entries {
        load_rsrc_root_node_entry(pe, entry);
    }
    for entry in rsrc.resources {
        if let ResolvedDirectoryID::ID(x) = entry.type_id {
            println!("{}", resource_id_to_type(ResourceID::from_u32(x)));
        }
        println!("{:x} {:?} {:?}", entry.data.0, entry.lang_id, entry.rsrc_id);
    }
}

// def display_resources(self, pe):
// """Display resources"""
// if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
//     if (len(pe.DIRECTORY_ENTRY_RESOURCE.entries) > 0):
//         print("Resources:")
//         print("=" * 80)
//         print("%-12s %-7s %-9s %-14s %-17s %-14s %-9s" % (
//             "Id", "Name", "Size", "Lang", "Sublang", "Type", "MD5"))
//         for r in pe.DIRECTORY_ENTRY_RESOURCE.entries:
//             self.resource(pe, 0, r, [])