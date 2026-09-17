use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Range;

use object::pe;
use object::read::pe::{
    ImageNtHeaders, ImageOptionalHeader, PeFile, PeFile32, PeFile64, ResourceDirectory,
    ResourceDirectoryEntryData, ResourceDirectoryTable, ResourceNameOrId, SectionTable,
};
use object::{FileKind, LittleEndian as LE};
use wholesym::samply_symbols::object;

use crate::binary::{Contents, LayoutNode, Section};

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
///
/// The section that holds the resources, normally `.rsrc`, is broken down by
/// resource, which matters a lot more than it sounds: in a shippable
/// `firefox.exe` the resources are over half the file, almost all of it icons.
pub fn layout(data: &[u8], binary_start: u64, sections: Vec<Section>) -> Vec<LayoutNode> {
    let Some(pe) = PeInfo::parse(data, binary_start) else {
        return sections.into_iter().map(|s| s.into_node(0)).collect();
    };

    let mut nodes = Vec::new();
    if pe.size_of_headers != 0 {
        nodes.push(LayoutNode::opaque(
            binary_start..binary_start + pe.size_of_headers,
            "PE headers",
        ));
    }

    let mut resources = pe.resources.into_iter().peekable();
    nodes.extend(sections.into_iter().map(|section| {
        // A section whose SizeOfRawData runs past the end of the file only owns
        // the bytes that are actually there.
        let on_disk_end = match pe
            .on_disk_size_at
            .get(&(section.file_range.start - binary_start))
        {
            Some(size) => (section.file_range.start + size).min(binary_start + data.len() as u64),
            None => section.file_range.end,
        };
        let padding = on_disk_end.saturating_sub(section.file_range.end);
        let mut node = section.into_node(padding);

        // The resources are sorted by file offset and the sections are in
        // ascending file order, so each section can take the ones that start
        // inside it off the front. Anything that starts before it is either
        // already spoken for or in a gap we can't attribute.
        let mut entries = Vec::new();
        while let Some((r, _)) = resources.peek() {
            if r.start >= node.range.end {
                break;
            }
            let entry = resources.next().expect("peeked");
            if node.range.contains(&entry.0.start) {
                entries.push(entry);
            }
        }

        // Resources live in read-only data, so in practice this never displaces
        // a text section's per-address breakdown, but check rather than risk
        // silently throwing one away.
        let is_opaque = matches!(&node.contents, Contents::Children(c) if c.is_empty());
        if !entries.is_empty() && is_opaque {
            node.contents = Contents::Scattered(entries);
        }
        node
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
    /// The resource data entries, sorted by file offset.
    resources: Vec<(Range<u64>, Vec<String>)>,
}

impl PeInfo {
    fn parse(data: &[u8], binary_start: u64) -> Option<Self> {
        match FileKind::parse(data) {
            Ok(FileKind::Pe32) => Self::of(&PeFile32::parse(data).ok()?, binary_start),
            Ok(FileKind::Pe64) => Self::of(&PeFile64::parse(data).ok()?, binary_start),
            _ => None,
        }
    }

    fn of<'d, Pe: ImageNtHeaders>(
        file: &PeFile<'d, Pe, &'d [u8]>,
        binary_start: u64,
    ) -> Option<Self> {
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
            resources: resources(file, binary_start),
        })
    }
}

/// Every resource's bytes, labelled with its position in the resource tree and
/// with whatever we can tell about its contents.
fn resources<'d, Pe: ImageNtHeaders>(
    file: &PeFile<'d, Pe, &'d [u8]>,
    binary_start: u64,
) -> Vec<(Range<u64>, Vec<String>)> {
    let sections = file.section_table();
    let Ok(Some(directory)) = file
        .data_directories()
        .resource_directory(file.data(), &sections)
    else {
        return Vec::new();
    };
    let Ok(root) = directory.root() else {
        return Vec::new();
    };

    let walk = ResourceWalk {
        directory,
        sections,
        data: file.data(),
        binary_start,
    };
    let mut found = Vec::new();
    walk.collect(&root, 0, &mut Vec::new(), None, &mut found);
    found.sort_by_key(|(range, _)| (range.start, range.end));

    // Two resources can point at the same bytes, which are then shared rather
    // than duplicated. Count them once, under the first resource that uses them,
    // so that the section's byte counts still add up.
    let mut claimed = 0;
    found.retain(|(range, _)| {
        let unclaimed = range.start >= claimed;
        if unclaimed {
            claimed = range.end;
        }
        unclaimed
    });

    found
}

struct ResourceWalk<'d> {
    directory: ResourceDirectory<'d>,
    sections: SectionTable<'d>,
    data: &'d [u8],
    binary_start: u64,
}

impl<'d> ResourceWalk<'d> {
    fn bytes(&self, range: &Range<u64>) -> &'d [u8] {
        let start = (range.start - self.binary_start) as usize;
        let end = (range.end - self.binary_start) as usize;
        &self.data[start..end]
    }

    /// Walk the resource tree, which has a fixed shape: type, then name or ID,
    /// then language, then the data entry. Recursing on the depth keeps the label
    /// choices in one place, and stops a malformed file from looping forever.
    ///
    /// The language level gets no frame of its own. In a binary built for one
    /// locale every single resource would carry an identical "language 1033"
    /// frame, which says nothing at all. The leaf frame describes the bytes
    /// instead; see [`contents_label`].
    fn collect(
        &self,
        table: &ResourceDirectoryTable<'d>,
        depth: usize,
        labels: &mut Vec<String>,
        type_id: Option<u16>,
        found: &mut Vec<(Range<u64>, Vec<String>)>,
    ) {
        for entry in table.entries {
            let name_or_id = entry.name_or_id();
            let id = match &name_or_id {
                ResourceNameOrId::Id(id) => Some(*id),
                ResourceNameOrId::Name(_) => None,
            };
            let pushed = depth < 2;
            if pushed {
                let Some(label) = self.label(name_or_id, depth) else {
                    continue;
                };
                labels.push(label);
            }

            match entry.data(self.directory) {
                Ok(ResourceDirectoryEntryData::Table(sub)) if depth < 2 => {
                    let type_id = if depth == 0 { id } else { type_id };
                    self.collect(&sub, depth + 1, labels, type_id, found);
                }
                Ok(ResourceDirectoryEntryData::Data(data)) => {
                    if let Some(range) = self.range_of(data) {
                        let mut labels = labels.clone();
                        labels.push(contents_label(type_id, id, self.bytes(&range)));
                        found.push((range, labels));
                    }
                }
                _ => {}
            }

            if pushed {
                labels.pop();
            }
        }
    }

    fn label(&self, name_or_id: ResourceNameOrId, depth: usize) -> Option<String> {
        match name_or_id {
            ResourceNameOrId::Name(name) => name.to_string_lossy(self.directory).ok(),
            ResourceNameOrId::Id(id) if depth == 0 => {
                Some(resource_type_name(id).map_or_else(|| format!("type {id}"), str::to_owned))
            }
            ResourceNameOrId::Id(id) => Some(format!("#{id}")),
        }
    }

    /// A resource points at its bytes by virtual address, and neither its own
    /// size nor the size of the section it points into is guaranteed to stay
    /// inside the file.
    fn range_of(&self, data: &pe::ImageResourceDataEntry) -> Option<Range<u64>> {
        let (offset, available) = self
            .sections
            .pe_file_range_at(data.offset_to_data.get(LE))?;
        let file_end = self.binary_start + self.data.len() as u64;
        let start = self.binary_start + offset as u64;
        let end = (start + data.size.get(LE).min(available) as u64).min(file_end);
        (start < end).then_some(start..end)
    }
}

/// What to call a resource's bytes: for an image its dimensions, which say far
/// more about it than its numeric ID does, and in every case a hash of the bytes
/// themselves.
///
/// The hash is what makes duplicated resources findable. Resources with
/// identical bytes get identical labels, so they collapse into a single node in
/// the profiler's inverted call tree, with one caller per copy — anything with
/// more than one caller there is stored more than once in the file. Truncating
/// the hash to 32 bits keeps the label readable, and only becomes likely to
/// invent a duplicate that isn't there at some tens of thousands of resources in
/// one binary.
fn contents_label(type_id: Option<u16>, language: Option<u16>, bytes: &[u8]) -> String {
    let description = match image_dimensions(type_id, bytes) {
        Some(dimensions) => dimensions,
        // Nothing to say about the bytes themselves, so fall back to the one
        // thing the tree still has left to tell us.
        None => match language {
            Some(id) => format!("language {id}"),
            None => "contents".to_owned(),
        },
    };
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{description} ({:08x})", hasher.finish() as u32)
}

/// The dimensions of an icon, cursor or bitmap resource.
fn image_dimensions(type_id: Option<u16>, bytes: &[u8]) -> Option<String> {
    // Icons of 256x256 and up are stored as PNGs rather than as bitmaps.
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let ihdr: &[u8; 8] = bytes.get(16..24)?.try_into().ok()?;
        let width = u32::from_be_bytes(ihdr[..4].try_into().unwrap());
        let height = u32::from_be_bytes(ihdr[4..].try_into().unwrap());
        return Some(format!("{width}x{height} PNG"));
    }

    // A cursor stores its hotspot ahead of the bitmap header.
    let type_id = type_id?;
    let header = match type_id {
        pe::RT_ICON | pe::RT_BITMAP => bytes,
        pe::RT_CURSOR => bytes.get(4..)?,
        _ => return None,
    };
    let header: &[u8; 16] = header.get(..16)?.try_into().ok()?;
    // Insist on a plain BITMAPINFOHEADER, so that we never report dimensions for
    // bytes that merely happen to start with a plausible-looking number.
    if u32::from_le_bytes(header[..4].try_into().unwrap()) != 40 {
        return None;
    }
    let width = i32::from_le_bytes(header[4..8].try_into().unwrap());
    let height = i32::from_le_bytes(header[8..12].try_into().unwrap());
    let bit_count = u16::from_le_bytes(header[14..16].try_into().unwrap());
    // An icon or cursor bitmap stacks the image on top of its transparency mask,
    // so the header's height is twice the image's.
    let height = if type_id == pe::RT_BITMAP {
        height
    } else {
        height / 2
    };
    Some(format!("{width}x{height} {bit_count}bpp"))
}

/// <https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types>
fn resource_type_name(id: u16) -> Option<&'static str> {
    Some(match id {
        pe::RT_CURSOR => "CURSOR",
        pe::RT_BITMAP => "BITMAP",
        pe::RT_ICON => "ICON",
        pe::RT_MENU => "MENU",
        pe::RT_DIALOG => "DIALOG",
        pe::RT_STRING => "STRING",
        pe::RT_FONTDIR => "FONTDIR",
        pe::RT_FONT => "FONT",
        pe::RT_ACCELERATOR => "ACCELERATOR",
        pe::RT_RCDATA => "RCDATA",
        pe::RT_MESSAGETABLE => "MESSAGETABLE",
        pe::RT_GROUP_CURSOR => "GROUP_CURSOR",
        pe::RT_GROUP_ICON => "GROUP_ICON",
        pe::RT_VERSION => "VERSION",
        pe::RT_DLGINCLUDE => "DLGINCLUDE",
        pe::RT_PLUGPLAY => "PLUGPLAY",
        pe::RT_VXD => "VXD",
        pe::RT_ANICURSOR => "ANICURSOR",
        pe::RT_ANIICON => "ANIICON",
        pe::RT_HTML => "HTML",
        pe::RT_MANIFEST => "MANIFEST",
        _ => return None,
    })
}
