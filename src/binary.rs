use std::ops::Range;

use fxprof_processed_profile::{LibraryHandle, LibraryInfo};
use object::read::Object;
use object::{CompressionFormat, File, SectionKind};
use wholesym::AccessPatternHint;
use wholesym::samply_symbols::object;
use wholesym::samply_symbols::relative_address_base;

use crate::emit::{ProfileBuilder, Region};
use crate::symbols::BinarySymbols;
use crate::text;

/// One section of a binary, with its file range already made absolute, i.e.
/// adjusted for the offset of the containing fat archive member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub file_range: Range<u64>,
    pub svma: u64,
    pub kind: SectionKind,
    pub name: String,
    pub is_compressed: bool,
}

/// Everything needed to symbolicate addresses in one binary.
pub struct BinaryContext<'a> {
    pub symbol_map: &'a wholesym::SymbolMap,
    pub library_handle: LibraryHandle,
    pub base_addr: u64,
}

/// Break `region`, which covers one binary, down into its sections.
pub async fn process_binary(
    b: &mut ProfileBuilder,
    region: &mut Region,
    object_file: &File<'_>,
    symbols: BinarySymbols,
) {
    let BinarySymbols {
        lib_info,
        symbol_map,
    } = symbols;

    let name = lib_info.name.unwrap();
    let debug_name = lib_info.debug_name.unwrap_or_else(|| name.clone());
    let path = lib_info.path.unwrap_or_else(|| name.clone());
    let debug_path = lib_info.debug_path.unwrap_or_else(|| path.clone());
    let lib = LibraryInfo {
        name,
        debug_name,
        path,
        debug_path,
        debug_id: lib_info.debug_id.unwrap_or_default(),
        code_id: lib_info.code_id.map(|ci| ci.to_string()),
        arch: lib_info.arch,
    };

    let base_addr = relative_address_base(object_file);

    // We look up every address of the text section in ascending order. Telling the symbol map
    // about this lets it throw away the per-function information it has already moved past,
    // rather than accumulating it for every function in the binary.
    symbol_map.set_access_pattern_hint(AccessPatternHint::SequentialLookup);

    let ctx = BinaryContext {
        symbol_map: &symbol_map,
        library_handle: b.profile.add_lib(lib),
        base_addr,
    };

    for section in sections(object_file, region.range().start) {
        process_section(b, region, &section, &ctx).await;
    }
}

/// The binary's sections in ascending file order. `binary_start` is where the
/// binary begins in the file, which is not zero for a fat archive member.
fn sections(object_file: &File<'_>, binary_start: u64) -> Vec<Section> {
    let mut sections: Vec<_> = object_file
        .sections()
        .filter_map(|s| {
            use object::ObjectSection;
            let file_range = s.compressed_file_range().unwrap();
            let is_compressed = file_range.format != CompressionFormat::None;
            if file_range.uncompressed_size == 0 {
                return None;
            }

            let start = binary_start + file_range.offset;
            Some(Section {
                file_range: start..start + file_range.compressed_size,
                svma: s.address(),
                kind: s.kind(),
                name: s.name().unwrap().to_string(),
                is_compressed,
            })
        })
        .collect();

    sections.sort_by_key(|s| s.file_range.start);
    sections
}

async fn process_section(
    b: &mut ProfileBuilder,
    binary_region: &mut Region,
    section: &Section,
    ctx: &BinaryContext<'_>,
) {
    let mut region = binary_region.child(b, section.file_range.clone(), &section.name);

    if section.kind == SectionKind::Text {
        text::process_text_section(b, &mut region, section, ctx).await;
    } else {
        // We have nothing to say about the contents, so attribute the whole
        // section to a frame naming its kind.
        let kind = region.child(
            b,
            section.file_range.clone(),
            &format!("{:?}", section.kind),
        );
        kind.finish(b);
    }

    region.finish(b);
}
