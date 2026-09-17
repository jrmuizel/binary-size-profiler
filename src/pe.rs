use std::collections::HashMap;

use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile, PeFile32, PeFile64};
use object::{FileKind, LittleEndian as LE};
use wholesym::samply_symbols::object;

use crate::binary::{LayoutNode, Section};

/// Break a PE binary down into its headers and its sections.
///
/// `object` reports a section's file range as `min(VirtualSize, SizeOfRawData)`,
/// because that is the part of it that gets mapped. But the file also holds the
/// bytes between there and `SizeOfRawData`, which exist only to round the
/// section up to `FileAlignment`. Handing those to the section they follow gets
/// them attributed to the section that causes them, instead of leaving them to
/// the enclosing region as unrecognised bytes alongside the headers.
///
/// The headers are in no section at all, so they need a node of their own.
pub fn layout(data: &[u8], binary_start: u64, sections: Vec<Section>) -> Vec<LayoutNode> {
    let Some(pe) = PeInfo::parse(data) else {
        return sections.into_iter().map(|s| s.into_node(0)).collect();
    };

    let mut nodes = Vec::new();
    if pe.size_of_headers != 0 {
        nodes.push(LayoutNode::opaque(
            binary_start..binary_start + pe.size_of_headers,
            "PE headers",
        ));
    }

    nodes.extend(sections.into_iter().map(|section| {
        // A section whose SizeOfRawData runs past the end of the file only owns
        // the bytes that are actually there.
        let on_disk_end = match pe.on_disk_size_at.get(&(section.file_range.start - binary_start)) {
            Some(size) => (section.file_range.start + size).min(binary_start + data.len() as u64),
            None => section.file_range.end,
        };
        let padding = on_disk_end.saturating_sub(section.file_range.end);
        section.into_node(padding)
    }));

    nodes
}

/// The parts of the PE headers we need, pulled out so that the rest of this
/// module doesn't have to be generic over PE32 vs PE32+.
struct PeInfo {
    size_of_headers: u64,
    /// `SizeOfRawData` by `PointerToRawData`, which is how `object` reports a
    /// section's file offset and is unique among the sections that have any
    /// bytes in the file.
    on_disk_size_at: HashMap<u64, u64>,
}

impl PeInfo {
    fn parse(data: &[u8]) -> Option<Self> {
        match FileKind::parse(data) {
            Ok(FileKind::Pe32) => Self::of(&PeFile32::parse(data).ok()?),
            Ok(FileKind::Pe64) => Self::of(&PeFile64::parse(data).ok()?),
            _ => None,
        }
    }

    fn of<'d, Pe: ImageNtHeaders>(file: &PeFile<'d, Pe, &'d [u8]>) -> Option<Self> {
        let on_disk_size_at = file
            .section_table()
            .iter()
            .map(|s| {
                (
                    s.pointer_to_raw_data.get(LE) as u64,
                    s.size_of_raw_data.get(LE) as u64,
                )
            })
            .collect();
        Some(Self {
            size_of_headers: file.nt_headers().optional_header().size_of_headers() as u64,
            on_disk_size_at,
        })
    }
}
