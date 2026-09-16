mod emit;

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;

use fxprof_processed_profile::{
    CategoryHandle, FrameAddress, FrameFlags, FrameHandle, FrameSymbolInfo, LibraryHandle,
    LibraryInfo, Profile, ProfileFormat, ReferenceTimestamp, SamplingInterval, SourceLocation,
    StackHandle, StringHandle, TimelineUnit, Timestamp, WeightType,
};
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use mimalloc::MiMalloc;
use object::read::Object;
use object::read::macho::{FatArch, MachOFatFile32};
use object::{CompressionFormat, File, FileKind, SectionKind};
use uuid::Uuid;
use wholesym::debugid::DebugId;
use wholesym::samply_symbols::relative_address_base;
use wholesym::samply_symbols::{SourceFilePathHandle, object};
use wholesym::{AccessPatternHint, MultiArchDisambiguator, SymbolManager, SymbolManagerConfig};

use crate::emit::{ProfileBuilder, Region};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = &std::env::args().nth(1).unwrap();
    let file_name = Path::new(path).file_name().unwrap().to_str().unwrap();

    // Map the binary instead of reading it: for a universal XUL this is ~466MB of
    // resident memory we never have to hold, and the pages we touch are read once.
    let file = std::fs::File::open(path).unwrap();
    let data = unsafe { Mmap::map(&file).unwrap() };

    let file_kind = FileKind::parse(&data[..]).unwrap();

    let mut profile = Profile::new(
        "size-profiler",
        ReferenceTimestamp::from_millis_since_unix_epoch(0.),
        SamplingInterval::from_hz(1000.),
    );

    profile.set_timeline_unit(TimelineUnit::Bytes);

    let process = profile.add_process(file_name, 0, Timestamp::from_millis_since_reference(0.));
    let thread = profile.add_thread(process, 0, Timestamp::from_millis_since_reference(0.), true);
    profile.set_thread_samples_weight_type(thread, WeightType::Bytes);
    profile.set_symbolicated(true);

    let mut b = ProfileBuilder::new(profile, thread, CategoryHandle::OTHER);
    let root_stack = b.labelled_stack(None, "(root)");
    let mut root = Region::new(0..data.len() as u64, root_stack, "the file");

    let config = SymbolManagerConfig::default()
        .respect_nt_symbol_path(true)
        .breakpad_symbol_server(
            "https://symbols.mozilla.org/try/",
            "./breakpad-symbol-cache/",
        )
        .breakpad_symindex_cache_dir("./breakpad-symindex-cache/");
    let symbol_manager = SymbolManager::with_config(config);

    if file_kind == FileKind::MachOFat32 {
        for member in MachOFatFile32::parse(&data[..]).unwrap().arches() {
            let member_range =
                member.offset() as u64..(member.offset() as u64 + member.size() as u64);

            let member_data = &data[member_range.start as usize..member_range.end as usize];
            let object_file = File::parse(member_data).unwrap();

            let disambiguator = if let Ok(Some(uuid)) = object_file.mach_uuid() {
                let uuid = Uuid::from_bytes(uuid);
                Some(MultiArchDisambiguator::DebugId(DebugId::from_uuid(uuid)))
            } else {
                None
            };

            let lib_info = SymbolManager::library_info_for_binary_at_path(
                Path::new(path),
                disambiguator.clone(),
            )
            .await
            .unwrap();

            let member_name = match &lib_info.arch {
                Some(name) => name.to_owned(),
                None => format!(
                    "Fat32 archive member with cputype {} and cpusubtype {}",
                    member.cputype(),
                    member.cpusubtype()
                ),
            };

            let mut member_region = root.child(&mut b, member_range, &member_name);

            let symbol_map = symbol_manager
                .load_symbol_map_for_binary_at_path(Path::new(path), disambiguator)
                .await
                .unwrap();

            process_binary(
                &mut b,
                &mut member_region,
                &object_file,
                lib_info,
                symbol_map,
            )
            .await;

            member_region.finish(&mut b);
        }
    } else {
        let object_file = File::parse(&data[..]).unwrap();

        let lib_info = SymbolManager::library_info_for_binary_at_path(Path::new(path), None)
            .await
            .unwrap();

        let symbol_map = symbol_manager
            .load_symbol_map_for_binary_at_path(Path::new(path), None)
            .await
            .unwrap();

        process_binary(&mut b, &mut root, &object_file, lib_info, symbol_map).await;
    }

    root.finish(&mut b);

    // Add a final sample with zero weight, so that the profiler's automatic time range detection
    // includes all the file bytes.
    b.weighted_sample(data.len() as u64, 0, root_stack);

    let output_file = std::fs::File::create("output.jslb").unwrap();
    let writer = std::io::BufWriter::new(output_file);
    b.profile
        .to_writer(writer, ProfileFormat::JsonSlabs)
        .unwrap();

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    /// Absolute offset in the file, i.e. already adjusted for the containing fat
    /// archive member.
    file_range: Range<u64>,
    svma: u64,
    kind: SectionKind,
    name: String,
    is_compressed: bool,
}

/// Everything needed to symbolicate addresses in one binary.
struct BinaryContext<'a> {
    symbol_map: &'a wholesym::SymbolMap,
    library_handle: LibraryHandle,
    base_addr: u64,
}

async fn process_binary(
    b: &mut ProfileBuilder,
    region: &mut Region,
    object_file: &File<'_>,
    lib_info: wholesym::LibraryInfo,
    symbol_map: wholesym::SymbolMap,
) {
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

    for section in &sections {
        process_section(b, region, section, &ctx).await;
    }
}

async fn process_section(
    b: &mut ProfileBuilder,
    binary_region: &mut Region,
    section: &Section,
    ctx: &BinaryContext<'_>,
) {
    let mut region = binary_region.child(b, section.file_range.clone(), &section.name);

    if section.kind != SectionKind::Text {
        // We have nothing to say about the contents, so attribute the whole
        // section to a frame naming its kind.
        let kind = region.child(
            b,
            section.file_range.clone(),
            &format!("{:?}", section.kind),
        );
        kind.finish(b);
        region.finish(b);
        return;
    }

    process_text_section(b, &mut region, section, ctx).await;
    region.finish(b);
}

/// Walks a text section one byte at a time, looking up the symbol, inline stack
/// and source location for each address, and emitting one sample per run of
/// addresses that share the same information.
async fn process_text_section(
    b: &mut ProfileBuilder,
    region: &mut Region,
    section: &Section,
    ctx: &BinaryContext<'_>,
) {
    let section_size = section.file_range.end - section.file_range.start;
    let section_start_rel = section.svma - ctx.base_addr;
    let section_end_rel = section.svma + section_size - ctx.base_addr;

    let category = b.category();
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
        .handle_for_stack(unknown_path_frame, Some(region.stack()));

    let mut walk = TextWalk {
        section_stack: region.stack(),
        unknown_path_stack,
        unknown_bytes_frame,
        stack_prefix_for_path: HashMap::new(),
    };

    let pb = ProgressBar::new(section_size);
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
    let mut pending_sample_file_offset = section.file_range.start;

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

/// State carried across the addresses of a single text section.
struct TextWalk {
    section_stack: StackHandle,
    unknown_path_stack: StackHandle,
    unknown_bytes_frame: FrameHandle,
    stack_prefix_for_path: HashMap<SourceFilePathHandle, StackHandle>,
}

impl TextWalk {
    fn emit_sample_for_address(
        &mut self,
        b: &mut ProfileBuilder,
        region: &mut Region,
        ctx: &BinaryContext<'_>,
        relative_address: u32,
        addr_info: Option<wholesym::AddressInfo>,
        range: Range<u64>,
    ) {
        let category = b.category();
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
        let path = ctx.symbol_map.resolve_source_file_path(path_handle);
        let path = path.display_path();
        let path = path.trim_start_matches("C:\\b\\s\\w\\ir\\cache\\builder\\");
        let mut accum_path = String::new();

        let mut path_stack = self.section_stack;

        for p in path.split(['/', '\\']) {
            accum_path.push('/');
            accum_path.push_str(p);
            path_stack = b.labelled_stack(Some(path_stack), &accum_path);
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
    let file_path = file_path?;
    let p = ctx.symbol_map.resolve_source_file_path(file_path);
    let s = match p.special_path_str() {
        Some(special_path) => b.profile.handle_for_string(&special_path),
        None => b.profile.handle_for_string(p.raw_path()),
    };
    Some(s)
}
