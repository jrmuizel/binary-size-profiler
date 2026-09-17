use std::future::Future;
use std::ops::Range;
use std::pin::Pin;

use fxprof_processed_profile::{LibraryHandle, LibraryInfo};
use object::read::Object;
use object::{File, FileKind, SectionKind};
use wholesym::AccessPatternHint;
use wholesym::samply_symbols::object;
use wholesym::samply_symbols::relative_address_base;

use crate::emit::{ProfileBuilder, Region};
use crate::macho;
use crate::pe;
use crate::symbols::BinarySymbols;
use crate::text;

/// One section of a binary, with its file range already made absolute, i.e.
/// adjusted for the offset of the containing fat archive member.
///
/// `file_range` covers the section's contents. A section can occupy more of the
/// file than that — see [`Section::into_node`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub file_range: Range<u64>,
    pub svma: u64,
    pub kind: SectionKind,
    pub name: String,
}

/// A labelled file range in the binary's layout. Each node becomes one frame in
/// the profile's call tree.
///
/// Building the layout first, and emitting it second, keeps the format-specific
/// knowledge (what a Mach-O segment is, where the symbol table lives) separate
/// from the mechanics of turning ranges into samples.
pub struct LayoutNode {
    pub range: Range<u64>,
    pub label: String,
    pub contents: Contents,
}

pub enum Contents {
    /// Subdivided into non-overlapping children in ascending file order. Bytes
    /// that no child covers are attributed to the node itself, so padding and
    /// unrecognised data stay visible instead of disappearing.
    Children(Vec<LayoutNode>),
    /// Machine code, broken down per address by symbol, inline frames and source
    /// location. `svma` is the address the node's first byte is mapped at, and
    /// `code_size` is how many bytes from there are code. Any bytes of the node
    /// after that are padding, which has no address to look anything up at.
    Text { svma: u64, code_size: u64 },
}

impl LayoutNode {
    /// A range we can label but not break down any further.
    pub fn opaque(range: Range<u64>, label: impl Into<String>) -> Self {
        LayoutNode {
            range,
            label: label.into(),
            contents: Contents::Children(Vec::new()),
        }
    }

    pub fn parent(range: Range<u64>, label: impl Into<String>, children: Vec<LayoutNode>) -> Self {
        LayoutNode {
            range,
            label: label.into(),
            contents: Contents::Children(children),
        }
    }
}

impl Section {
    /// `trailing_padding` is the number of bytes after the section's contents
    /// that belong to it but aren't part of it, such as the bytes a PE section
    /// takes up to satisfy `FileAlignment`. They become part of the node's range,
    /// so they end up attributed to the section that causes them rather than to
    /// the enclosing region.
    pub fn into_node(self, trailing_padding: u64) -> LayoutNode {
        let code_size = self.file_range.end - self.file_range.start;
        let range = self.file_range.start..self.file_range.end + trailing_padding;
        if self.kind == SectionKind::Text {
            return LayoutNode {
                range,
                label: self.name,
                contents: Contents::Text { svma: self.svma, code_size },
            };
        }
        // The section kind goes into the section's own label rather than into a
        // child node. A child would carry the same byte count as its parent, and
        // because its label is just the kind, every section of the same kind would
        // share it: the profiler's function list and bottom-up view would merge
        // `.rdata`, `.rsrc` and `.pdata` into one "ReadOnlyData" entry whose byte
        // count describes nothing in particular.
        LayoutNode::opaque(range, format!("{} ({:?})", self.name, self.kind))
    }
}

/// Everything needed to symbolicate addresses in one binary.
pub struct BinaryContext<'a> {
    pub symbol_map: &'a wholesym::SymbolMap,
    pub library_handle: LibraryHandle,
    pub base_addr: u64,
}

/// Break `region`, which covers one binary, down into its parts.
pub async fn process_binary(
    b: &mut ProfileBuilder,
    region: &mut Region,
    data: &[u8],
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

    // Section file offsets are relative to the start of this binary, which is not
    // the start of the file when the binary is a fat archive member.
    let binary_start = region.range().start;
    let sections = sections(object_file, binary_start);

    let nodes = match FileKind::parse(data) {
        Ok(FileKind::MachO32) | Ok(FileKind::MachO64) => {
            macho::layout(object_file, data, binary_start, sections)
        }
        Ok(FileKind::Pe32) | Ok(FileKind::Pe64) => pe::layout(data, binary_start, sections),
        _ => sections.into_iter().map(|s| s.into_node(0)).collect(),
    };

    emit_nodes(b, region, nodes, &ctx).await;
}

/// The binary's sections in ascending file order.
fn sections(object_file: &File<'_>, binary_start: u64) -> Vec<Section> {
    let mut sections: Vec<_> = object_file
        .sections()
        .filter_map(|s| {
            use object::ObjectSection;
            let file_range = s.compressed_file_range().unwrap();
            if file_range.uncompressed_size == 0 {
                return None;
            }

            let start = binary_start + file_range.offset;
            Some(Section {
                file_range: start..start + file_range.compressed_size,
                svma: s.address(),
                kind: s.kind(),
                name: s.name().unwrap().to_string(),
            })
        })
        .collect();

    sections.sort_by_key(|s| s.file_range.start);
    sections
}

/// Emit `nodes` as children of `region`. Boxed because it recurses.
fn emit_nodes<'a>(
    b: &'a mut ProfileBuilder,
    region: &'a mut Region,
    nodes: Vec<LayoutNode>,
    ctx: &'a BinaryContext<'a>,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(async move {
        for node in nodes {
            let mut child = region.child(b, node.range.clone(), &node.label);
            match node.contents {
                Contents::Text { svma, code_size } => {
                    text::process_text_section(b, &mut child, svma, code_size, ctx).await
                }
                Contents::Children(children) => emit_nodes(b, &mut child, children, ctx).await,
            }
            child.finish(b);
        }
    })
}
