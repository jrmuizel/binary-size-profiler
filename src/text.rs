use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

use fxprof_processed_profile::{
    FrameAddress, FrameFlags, FrameHandle, FrameSymbolInfo, SourceLocation, StackHandle,
    StringHandle,
};
use indicatif::{ProgressBar, ProgressStyle};
use wholesym::samply_symbols::{SourceFilePath, SourceFilePathHandle};

use crate::binary::BinaryContext;
use crate::categories::Kind;
use crate::emit::{ProfileBuilder, Region};

/// Walks a text section one byte at a time, looking up the symbol, inline stack
/// and source location for each address, and emitting one sample per run of
/// addresses that share the same information.
///
/// `code_size` is how many bytes at the start of `region` are code. Any bytes of
/// the region beyond that are padding, and are left to `region` to attribute to
/// itself, because they are not mapped and so have no address to look up.
pub async fn process_text_section(
    b: &mut ProfileBuilder,
    region: &mut Region,
    svma: u64,
    code_size: u64,
    ctx: &BinaryContext<'_>,
) {
    let file_range = region.range();
    let section_start_rel = svma - ctx.base_addr;
    let section_end_rel = svma + code_size - ctx.base_addr;

    let mut walk = TextWalk::new(b, region.stack());

    let pb = ProgressBar::new(code_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut pending_sample_relative_address = 0;
    let mut pending_sample_addr_info = None;
    let mut pending_sample_bytes = 0;
    let mut pending_sample_file_offset = file_range.start;

    for addr in section_start_rel..section_end_rel {
        if addr & 0xffff == 0 {
            pb.set_position(addr - section_start_rel);
        }

        let addr_info = ctx
            .symbol_map
            .lookup(wholesym::LookupAddress::Relative(addr as u32))
            .await;

        if pending_sample_bytes == 0 {
            pending_sample_addr_info = addr_info;
            pending_sample_relative_address = addr as u32;
        } else if addr_info != pending_sample_addr_info {
            walk.emit_sample_for_address(
                b,
                region,
                ctx,
                pending_sample_relative_address,
                pending_sample_addr_info,
                pending_sample_file_offset..pending_sample_file_offset + pending_sample_bytes,
            );
            pending_sample_file_offset += pending_sample_bytes;
            pending_sample_relative_address = addr as u32;
            pending_sample_addr_info = addr_info;
            pending_sample_bytes = 0;
        }
        pending_sample_bytes += 1;
    }
    walk.emit_sample_for_address(
        b,
        region,
        ctx,
        pending_sample_relative_address,
        pending_sample_addr_info,
        pending_sample_file_offset..pending_sample_file_offset + pending_sample_bytes,
    );

    pb.finish_with_message("Section processed");
}

/// Where Firefox's Windows builders check out the source. Stripping it keeps six
/// frames that say nothing out of every Windows profile. There is no general way
/// to know a build machine's checkout root, so this is just the one we know.
const BUILDER_CHECKOUT_ROOT: &str = "C:\\b\\s\\w\\ir\\cache\\builder\\";

/// State carried across the addresses of a single text section.
struct TextWalk {
    section_stack: StackHandle,
    unknown_path_stack: StackHandle,
    unknown_bytes_frame: FrameHandle,
    stack_prefix_for_path: HashMap<SourceFilePathHandle, StackHandle>,
}

impl TextWalk {
    fn new(b: &mut ProfileBuilder, section_stack: StackHandle) -> Self {
        // Bytes we can't name are worth spotting, so they get a category of their
        // own rather than being coloured like the code around them.
        let category = b.category(Kind::Unattributed);
        let unknown_path_str = b.profile.handle_for_string("<unknown path>");
        let unknown_path_frame =
            b.profile
                .handle_for_frame_with_label(unknown_path_str, category, FrameFlags::empty());

        let unknown_bytes_str = b.profile.handle_for_string("<unknown bytes>");
        let unknown_bytes_frame =
            b.profile
                .handle_for_frame_with_label(unknown_bytes_str, category, FrameFlags::empty());

        let unknown_path_stack = b
            .profile
            .handle_for_stack(unknown_path_frame, Some(section_stack));

        Self {
            section_stack,
            unknown_path_stack,
            unknown_bytes_frame,
            stack_prefix_for_path: HashMap::new(),
        }
    }

    fn emit_sample_for_address(
        &mut self,
        b: &mut ProfileBuilder,
        region: &mut Region,
        ctx: &BinaryContext<'_>,
        relative_address: u32,
        addr_info: Option<wholesym::AddressInfo>,
        range: Range<u64>,
    ) {
        let category = b.category(Kind::Code);
        let path_stack = self
            .path_stack(b, ctx, &addr_info)
            .unwrap_or(self.unknown_path_stack);

        let stack = if let Some(addr_info) = addr_info {
            let symbol = addr_info.symbol;
            let symbol_name = b
                .profile
                .handle_for_string(&ctx.symbol_map.resolve_symbol_name(symbol.name));
            let native_symbol = b.profile.handle_for_native_symbol(
                ctx.library_handle,
                symbol.address,
                symbol.size,
                symbol_name,
            );
            let mut s = path_stack;
            if let Some(mut frames) = addr_info.frames {
                frames.reverse();
                for (inline_depth, f) in frames.into_iter().enumerate() {
                    let name = match f.function {
                        Some(function) => b
                            .profile
                            .handle_for_string(&ctx.symbol_map.resolve_function_name(function)),
                        None => symbol_name,
                    };
                    let file_path = special_path(b, ctx, f.file_path);
                    let frame = b.profile.handle_for_frame_with_address_and_symbol(
                        FrameAddress::RelativeAddressFromInstructionPointer(
                            ctx.library_handle,
                            relative_address,
                        ),
                        FrameSymbolInfo {
                            name: Some(name),
                            native_symbol,
                            source_location: SourceLocation {
                                file_path,
                                line: f.line_number,
                                col: None,
                                function_start_line: f.function_start_line,
                                function_start_col: f.function_start_column,
                            },
                        },
                        inline_depth as u16,
                        category,
                        FrameFlags::empty(),
                    );
                    s = b.profile.handle_for_stack(frame, Some(s));
                }
            } else {
                let frame = b.profile.handle_for_frame_with_address_and_symbol(
                    FrameAddress::RelativeAddressFromInstructionPointer(
                        ctx.library_handle,
                        relative_address,
                    ),
                    FrameSymbolInfo {
                        name: Some(symbol_name),
                        native_symbol,
                        source_location: SourceLocation::default(),
                    },
                    0,
                    category,
                    FrameFlags::empty(),
                );
                s = b.profile.handle_for_stack(frame, Some(s));
            }
            s
        } else {
            b.profile
                .handle_for_stack(self.unknown_bytes_frame, Some(path_stack))
        };

        region.leaf(b, range, stack);
    }

    /// A stack of one frame per component of the source file path that the
    /// address's outermost function was defined in, cached per path.
    fn path_stack(
        &mut self,
        b: &mut ProfileBuilder,
        ctx: &BinaryContext<'_>,
        addr_info: &Option<wholesym::AddressInfo>,
    ) -> Option<StackHandle> {
        let path_handle = outer_function_location(addr_info)?;
        if let Some(ps) = self.stack_prefix_for_path.get(&path_handle) {
            return Some(*ps);
        }
        let source_file_path = ctx.symbol_map.resolve_source_file_path(path_handle);
        let display_path = source_file_path.display_path();
        let path = display_path
            .strip_prefix(BUILDER_CHECKOUT_ROOT)
            .unwrap_or(&display_path);

        let file_path = source_path(&source_file_path);
        let mut path_stack = self.section_stack;

        // Each component is labelled with just its own name, and gets the path
        // up to and including it as its file path. The path is what tells two
        // directories of the same name apart, so the labels can stay short
        // without, say, every `src` in the build collapsing into one in the
        // inverted view.
        let mut offset = 0;
        for component in path.split(['/', '\\']) {
            let end = offset + component.len();
            offset = end + 1; // Skip the separator.

            // An absolute path splits into an empty first component, and a UNC
            // or doubled separator into an empty one further in. Neither is
            // worth a frame of its own.
            if component.is_empty() {
                continue;
            }

            // A directory gets the displayable path down to it, which is only
            // ever shown. The last component is the file itself, and gets the
            // same path as the function frames below it, so that the source
            // view can fetch it.
            let is_file = end == path.len();
            let frame_path = if is_file { &file_path } else { &path[..end] };

            path_stack = b.labelled_stack_with_file_path(
                Some(path_stack),
                component,
                frame_path,
                Kind::Code,
            );
        }
        self.stack_prefix_for_path.insert(path_handle, path_stack);
        Some(path_stack)
    }
}

fn outer_function_location(
    addr_info: &Option<wholesym::AddressInfo>,
) -> Option<SourceFilePathHandle> {
    let frames = addr_info.as_ref()?.frames.as_ref()?;
    frames.last()?.file_path
}

fn special_path(
    b: &mut ProfileBuilder,
    ctx: &BinaryContext<'_>,
    file_path: Option<SourceFilePathHandle>,
) -> Option<StringHandle> {
    let p = ctx.symbol_map.resolve_source_file_path(file_path?);
    Some(b.profile.handle_for_string(&source_path(&p)))
}

/// The path to put on a frame for a source file. The special path, where the
/// file has one, is what the front-end's source view needs in order to fetch
/// the file, so every frame that stands for a file uses it.
fn source_path<'a>(p: &'a SourceFilePath<'a>) -> Cow<'a, str> {
    p.special_path_str().unwrap_or(Cow::Borrowed(p.raw_path()))
}
