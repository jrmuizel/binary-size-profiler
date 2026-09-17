use std::mem;
use std::ops::Range;

use object::read::macho::{LoadCommandVariant, MachHeader, MachOFile, MachOFile32, MachOFile64};
use object::read::{Object, ObjectSegment};
use object::{Endianness, File, FileKind, macho};
use wholesym::samply_symbols::object;

use crate::binary::{LayoutNode, Section};

/// Break a Mach-O binary down into segments, with sections and the regions
/// described by load commands nested inside the segment that contains them.
///
/// Sections alone are not enough to account for the file: `__LINKEDIT` has no
/// sections at all, so the symbol table, string table, code signature and the
/// rest of its contents would be attributed to the binary as one big lump of
/// unrecognised padding. The Mach header and load commands are in no section
/// either.
pub fn layout(
    object_file: &File<'_>,
    data: &[u8],
    binary_start: u64,
    sections: Vec<Section>,
) -> Vec<LayoutNode> {
    let mut nodes: Vec<LayoutNode> = sections.into_iter().map(|s| s.into_node(0)).collect();
    nodes.extend(
        load_command_regions(data, binary_start)
            .into_iter()
            .map(|(range, label)| LayoutNode::opaque(range, label)),
    );

    let mut segments: Vec<(Range<u64>, String, Vec<LayoutNode>)> = object_file
        .segments()
        .filter_map(|s| {
            let (offset, size) = s.file_range();
            // __PAGEZERO occupies no file bytes.
            if size == 0 {
                return None;
            }
            let name = match s.name().ok().flatten() {
                Some(name) => name.to_owned(),
                None => "<unnamed segment>".to_owned(),
            };
            let start = binary_start + offset;
            Some((start..start + size, name, Vec::new()))
        })
        .collect();

    // Anything that isn't contained in a segment stays at the top level rather
    // than being dropped or forced into the wrong parent.
    let mut top = Vec::new();
    for node in nodes {
        let segment = segments
            .iter_mut()
            .find(|(r, _, _)| r.start <= node.range.start && node.range.end <= r.end);
        match segment {
            Some((_, _, children)) => children.push(node),
            None => top.push(node),
        }
    }

    for (range, name, mut children) in segments {
        children.sort_by_key(|n| n.range.start);
        top.push(LayoutNode::parent(range, name, children));
    }
    top.sort_by_key(|n| n.range.start);
    top
}

/// The file ranges that load commands point at: the header and the load commands
/// themselves, plus the contents of `__LINKEDIT`.
///
/// These are collected rather than emitted in load-command order, because a
/// single command can describe several ranges that are not adjacent, and ranges
/// from different commands interleave. `LC_SYMTAB`'s symbol table and string
/// table, for instance, usually have `LC_DYSYMTAB`'s indirect symbol table
/// sitting between them.
fn load_command_regions(data: &[u8], binary_start: u64) -> Vec<(Range<u64>, String)> {
    match FileKind::parse(data) {
        Ok(FileKind::MachO64) => match MachOFile64::<Endianness>::parse(data) {
            Ok(file) => regions_of(&file, binary_start),
            Err(_) => Vec::new(),
        },
        Ok(FileKind::MachO32) => match MachOFile32::<Endianness>::parse(data) {
            Ok(file) => regions_of(&file, binary_start),
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn regions_of<'d, Mach: MachHeader<Endian = Endianness>>(
    file: &MachOFile<'d, Mach, &'d [u8]>,
    binary_start: u64,
) -> Vec<(Range<u64>, String)> {
    let endian = file.endian();
    let header = file.macho_header();
    let mut regions: Vec<(Range<u64>, String)> = Vec::new();

    {
        let mut add = |offset: u64, size: u64, label: &str| {
            // An absent table has both offset and size zero.
            if size != 0 {
                let start = binary_start + offset;
                regions.push((start..start + size, label.to_owned()));
            }
        };

        add(
            0,
            mem::size_of::<Mach>() as u64 + header.sizeofcmds(endian) as u64,
            "Mach header and load commands",
        );

        let mut commands = match file.macho_load_commands() {
            Ok(commands) => commands,
            Err(_) => return regions,
        };
        while let Ok(Some(command)) = commands.next() {
            match command.variant() {
                Ok(LoadCommandVariant::Symtab(symtab)) => {
                    let nsyms = symtab.nsyms.get(endian) as u64;
                    add(
                        symtab.symoff.get(endian) as u64,
                        nsyms * mem::size_of::<Mach::Nlist>() as u64,
                        "Symbol table",
                    );
                    add(
                        symtab.stroff.get(endian) as u64,
                        symtab.strsize.get(endian) as u64,
                        "String table",
                    );
                }
                Ok(LoadCommandVariant::Dysymtab(dysymtab)) => {
                    // sizeof(dylib_module_64) / sizeof(dylib_module).
                    let module_size = if header.is_type_64() { 56 } else { 52 };
                    add(
                        dysymtab.tocoff.get(endian) as u64,
                        dysymtab.ntoc.get(endian) as u64 * 8,
                        "Table of contents",
                    );
                    add(
                        dysymtab.modtaboff.get(endian) as u64,
                        dysymtab.nmodtab.get(endian) as u64 * module_size,
                        "Module table",
                    );
                    add(
                        dysymtab.extrefsymoff.get(endian) as u64,
                        dysymtab.nextrefsyms.get(endian) as u64 * 4,
                        "Referenced symbol table",
                    );
                    add(
                        dysymtab.indirectsymoff.get(endian) as u64,
                        dysymtab.nindirectsyms.get(endian) as u64 * 4,
                        "Indirect symbol table",
                    );
                    add(
                        dysymtab.extreloff.get(endian) as u64,
                        dysymtab.nextrel.get(endian) as u64 * 8,
                        "External relocations",
                    );
                    add(
                        dysymtab.locreloff.get(endian) as u64,
                        dysymtab.nlocrel.get(endian) as u64 * 8,
                        "Local relocations",
                    );
                }
                Ok(LoadCommandVariant::DyldInfo(info)) => {
                    add(
                        info.rebase_off.get(endian) as u64,
                        info.rebase_size.get(endian) as u64,
                        "Rebase info",
                    );
                    add(
                        info.bind_off.get(endian) as u64,
                        info.bind_size.get(endian) as u64,
                        "Bind info",
                    );
                    add(
                        info.weak_bind_off.get(endian) as u64,
                        info.weak_bind_size.get(endian) as u64,
                        "Weak bind info",
                    );
                    add(
                        info.lazy_bind_off.get(endian) as u64,
                        info.lazy_bind_size.get(endian) as u64,
                        "Lazy bind info",
                    );
                    add(
                        info.export_off.get(endian) as u64,
                        info.export_size.get(endian) as u64,
                        "Export info",
                    );
                }
                Ok(LoadCommandVariant::LinkeditData(linkedit)) => {
                    add(
                        linkedit.dataoff.get(endian) as u64,
                        linkedit.datasize.get(endian) as u64,
                        linkedit_data_label(command.cmd()),
                    );
                }
                _ => {}
            }
        }
    }

    regions
}

/// `LC_CODE_SIGNATURE` and friends all use the same command struct, so the
/// command type is the only thing that says what the data is.
fn linkedit_data_label(cmd: macho::LoadCommandType) -> &'static str {
    match cmd {
        macho::LC_CODE_SIGNATURE => "Code signature",
        macho::LC_SEGMENT_SPLIT_INFO => "Segment split info",
        macho::LC_FUNCTION_STARTS => "Function starts",
        macho::LC_DATA_IN_CODE => "Data in code",
        macho::LC_DYLIB_CODE_SIGN_DRS => "Code signing DRs",
        macho::LC_LINKER_OPTIMIZATION_HINT => "Linker optimization hints",
        macho::LC_DYLD_EXPORTS_TRIE => "Exports trie",
        macho::LC_DYLD_CHAINED_FIXUPS => "Chained fixups",
        _ => "Other linkedit data",
    }
}
