use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;

use fxprof_processed_profile::{
    CategoryHandle, CpuDelta, FrameAddress, FrameFlags, FrameHandle, FrameSymbolInfo,
    LibraryHandle, LibraryInfo, Profile, ProfileFormat, ReferenceTimestamp, SamplingInterval,
    SourceLocation, StackHandle, StringHandle, ThreadHandle, TimelineUnit, Timestamp, WeightType,
};
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use mimalloc::MiMalloc;
use object::read::macho::{FatArch, MachOFatFile32};
use object::read::Object;
use object::{CompressionFormat, File, FileKind, SectionKind};
use uuid::Uuid;
use wholesym::debugid::DebugId;
use wholesym::samply_symbols::relative_address_base;
use wholesym::samply_symbols::{object, SourceFilePathHandle};
use wholesym::{AccessPatternHint, MultiArchDisambiguator, SymbolManager, SymbolManagerConfig};

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
    let category = CategoryHandle::OTHER;

    let root_s = profile.handle_for_string("(root)");
    let root_frame = profile.handle_for_frame_with_label(root_s, category, FrameFlags::empty());
    let root_stack = profile.handle_for_stack(root_frame, None);

    let config = SymbolManagerConfig::default()
        .respect_nt_symbol_path(true)
        .breakpad_symbol_server(
            "https://symbols.mozilla.org/try/",
            "./breakpad-symbol-cache/",
        )
        .breakpad_symindex_cache_dir("./breakpad-symindex-cache/");
    let symbol_manager = SymbolManager::with_config(config);

    // If we got a fat binary, pick the first member.
    if file_kind == FileKind::MachOFat32 {
        let mut previous_member_end_file_offset = 0;
        let mut previous_member_name = None;
        for member in MachOFatFile32::parse(&data[..]).unwrap().arches() {
            let member_start_file_offset = member.offset() as u64;
            let member_size = member.size() as u64;

            let data = &data[member_start_file_offset as usize..][..member_size as usize];
            let object_file = File::parse(data).unwrap();

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

            if member_start_file_offset < previous_member_end_file_offset {
                panic!("Overlapping fat archive members: Member with arch {member_name} starts at file offset {member_start_file_offset:#x} which is before the end file offset {previous_member_end_file_offset:#x} of member with arch {}", previous_member_name.unwrap());
            }

            if member_start_file_offset > previous_member_end_file_offset {
                let padding_bytes_before_member =
                    member_start_file_offset - previous_member_end_file_offset;
                profile.add_sample(
                    thread,
                    Timestamp::from_millis_since_reference(previous_member_end_file_offset as f64),
                    Some(root_stack),
                    CpuDelta::ZERO,
                    i32::try_from(padding_bytes_before_member).unwrap(),
                );
            }

            let member_s = profile.handle_for_string(&member_name);
            let member_frame =
                profile.handle_for_frame_with_label(member_s, category, FrameFlags::empty());
            let member_stack = profile.handle_for_stack(member_frame, Some(root_stack));

            let symbol_map = symbol_manager
                .load_symbol_map_for_binary_at_path(Path::new(path), disambiguator)
                .await
                .unwrap();

            process_binary(
                &mut profile,
                thread,
                member_stack,
                &object_file,
                lib_info,
                symbol_map,
                category,
                member_start_file_offset,
                member_size,
            )
            .await;

            previous_member_end_file_offset = member_start_file_offset + member_size;
            previous_member_name = Some(member_name);
        }

        let file_end_file_offset = data.len() as u64;
        if file_end_file_offset < previous_member_end_file_offset {
            panic!("Truncated fat archive member: File size is {file_end_file_offset:#x} which is less than the end file offset {previous_member_end_file_offset:#x} of member {}", previous_member_name.unwrap());
        }

        if file_end_file_offset > previous_member_end_file_offset {
            let padding_bytes_after_section =
                file_end_file_offset - previous_member_end_file_offset;
            profile.add_sample(
                thread,
                Timestamp::from_millis_since_reference(previous_member_end_file_offset as f64),
                Some(root_stack),
                CpuDelta::ZERO,
                i32::try_from(padding_bytes_after_section).unwrap(),
            );
        }
    } else {
        let data = &data[..];

        let object_file = File::parse(data).unwrap();

        let lib_info = SymbolManager::library_info_for_binary_at_path(Path::new(path), None)
            .await
            .unwrap();

        let symbol_map = symbol_manager
            .load_symbol_map_for_binary_at_path(Path::new(path), None)
            .await
            .unwrap();

        process_binary(
            &mut profile,
            thread,
            root_stack,
            &object_file,
            lib_info,
            symbol_map,
            category,
            0,
            data.len() as u64,
        )
        .await;
    }

    // Add a final sample with zero weight, so that the profiler's automatic time range detection
    // includes all the file bytes.
    profile.add_sample(
        thread,
        Timestamp::from_millis_since_reference(data.len() as f64),
        Some(root_stack),
        CpuDelta::ZERO,
        0,
    );

    let output_file = std::fs::File::create("output.jslb").unwrap();
    let writer = std::io::BufWriter::new(output_file);
    profile.to_writer(writer, ProfileFormat::JsonSlabs).unwrap();

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    file_offset: u64,
    svma: u64,
    size: u64,
    kind: SectionKind,
    name: String,
    is_compressed: bool,
}

#[allow(clippy::too_many_arguments)]
async fn process_binary(
    profile: &mut Profile,
    thread: ThreadHandle,
    root_stack: StackHandle,
    object_file: &File<'_>,
    lib_info: wholesym::LibraryInfo,
    symbol_map: wholesym::SymbolMap,
    category: CategoryHandle,
    timestamp_offset: u64,
    binary_file_size: u64,
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

    let library_handle = profile.add_lib(lib);

    let mut sections: Vec<_> = object_file
        .sections()
        .filter_map(|s| {
            use object::ObjectSection;
            let file_range = s.compressed_file_range().unwrap();
            let is_compressed = file_range.format != CompressionFormat::None;
            if file_range.uncompressed_size == 0 {
                return None;
            }

            Some(Section {
                file_offset: file_range.offset,
                svma: s.address(),
                size: file_range.compressed_size,
                kind: s.kind(),
                name: s.name().unwrap().to_string(),
                is_compressed,
            })
        })
        .collect();

    sections.sort_by_key(|s| s.file_offset);

    let mut previous_section_end_file_offset = 0;
    let mut previous_section_name = None;

    for s in sections {
        let section_name = &s.name;
        let section_start_file_offset = s.file_offset;

        if section_start_file_offset < previous_section_end_file_offset {
            panic!("Overlapping sections: Section {section_name} starts at file offset {section_start_file_offset:#x} which is before the end file offset {previous_section_end_file_offset:#x} of section {}", previous_section_name.unwrap());
        }

        if section_start_file_offset > previous_section_end_file_offset {
            let padding_bytes_before_section =
                section_start_file_offset - previous_section_end_file_offset;
            profile.add_sample(
                thread,
                Timestamp::from_millis_since_reference(
                    (timestamp_offset + previous_section_end_file_offset) as f64,
                ),
                Some(root_stack),
                CpuDelta::ZERO,
                i32::try_from(padding_bytes_before_section).unwrap(),
            );
        }

        process_section(
            profile,
            thread,
            root_stack,
            &s,
            &symbol_map,
            base_addr,
            library_handle,
            category,
            timestamp_offset,
        )
        .await;

        previous_section_end_file_offset = s.file_offset + s.size;
        previous_section_name = Some(s.name);
    }

    let file_end_file_offset = binary_file_size;
    if file_end_file_offset < previous_section_end_file_offset {
        panic!("Truncated section: File size is {file_end_file_offset:#x} which is less than the end file offset {previous_section_end_file_offset:#x} of section {}", previous_section_name.unwrap());
    }

    if file_end_file_offset > previous_section_end_file_offset {
        let padding_bytes_after_section = file_end_file_offset - previous_section_end_file_offset;
        profile.add_sample(
            thread,
            Timestamp::from_millis_since_reference(
                (timestamp_offset + previous_section_end_file_offset) as f64,
            ),
            Some(root_stack),
            CpuDelta::ZERO,
            i32::try_from(padding_bytes_after_section).unwrap(),
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_section(
    profile: &mut Profile,
    thread: ThreadHandle,
    root_stack: StackHandle,
    section: &Section,
    symbol_map: &wholesym::SymbolMap,
    base_addr: u64,
    library_handle: LibraryHandle,
    category: CategoryHandle,
    timestamp_offset: u64,
) {
    let section_s = profile.handle_for_string(&section.name);
    let section_frame =
        profile.handle_for_frame_with_label(section_s, category, FrameFlags::empty());
    let section_stack = profile.handle_for_stack(section_frame, Some(root_stack));

    if section.kind != SectionKind::Text {
        let section_kind_str = profile.handle_for_string(&format!("{:?}", section.kind));
        let section_kind_frame =
            profile.handle_for_frame_with_label(section_kind_str, category, FrameFlags::empty());
        let section_kind_stack = profile.handle_for_stack(section_kind_frame, Some(section_stack));
        profile.add_sample(
            thread,
            Timestamp::from_millis_since_reference((timestamp_offset + section.file_offset) as f64),
            Some(section_kind_stack),
            CpuDelta::ZERO,
            i32::try_from(section.size).unwrap(),
        );
        return;
    }

    let section_size = section.size;
    let section_start_rel = section.svma - base_addr;
    let section_end_rel = section.svma + section_size - base_addr;

    let unknown_path_str = profile.handle_for_string("<unknown path>");
    let unknown_path_frame =
        profile.handle_for_frame_with_label(unknown_path_str, category, FrameFlags::empty());

    let unknown_bytes_str = profile.handle_for_string("<unknown bytes>");
    let unknown_bytes_frame =
        profile.handle_for_frame_with_label(unknown_bytes_str, category, FrameFlags::empty());

    let unknown_path_stack = profile.handle_for_stack(unknown_path_frame, Some(section_stack));

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
    let mut pending_sample_file_offset = section.file_offset;

    let mut stack_prefix_for_path: HashMap<SourceFilePathHandle, StackHandle> = HashMap::new();
    for addr in dbg!(section_start_rel..section_end_rel /* .min(40326317)*/) {
        if addr & 0xffff == 0 {
            pb.set_position(addr - section_start_rel);
        }

        let addr_info = symbol_map
            .lookup(wholesym::LookupAddress::Relative(addr as u32))
            .await;

        if pending_sample_bytes == 0 {
            pending_sample_addr_info = addr_info;
            pending_sample_relative_address = addr as u32;
        } else if addr_info != pending_sample_addr_info {
            emit_sample_for_address(
                pending_sample_relative_address,
                pending_sample_addr_info,
                symbol_map,
                Timestamp::from_millis_since_reference(
                    (timestamp_offset + pending_sample_file_offset) as f64,
                ),
                pending_sample_bytes,
                section_stack,
                unknown_path_stack,
                unknown_bytes_frame,
                thread,
                library_handle,
                category,
                profile,
                &mut stack_prefix_for_path,
            );
            pending_sample_file_offset += pending_sample_bytes;
            pending_sample_relative_address = addr as u32;
            pending_sample_addr_info = addr_info;
            pending_sample_bytes = 0;
        }
        pending_sample_bytes += 1;
    }
    emit_sample_for_address(
        pending_sample_relative_address,
        pending_sample_addr_info,
        symbol_map,
        Timestamp::from_millis_since_reference(
            (timestamp_offset + pending_sample_file_offset) as f64,
        ),
        pending_sample_bytes,
        section_stack,
        unknown_path_stack,
        unknown_bytes_frame,
        thread,
        library_handle,
        category,
        profile,
        &mut stack_prefix_for_path,
    );
    pending_sample_file_offset += pending_sample_bytes;

    assert_eq!(
        pending_sample_file_offset,
        section.file_offset + section.size,
        "Unexpected file offset after processing section {}",
        &section.name
    );

    pb.finish_with_message("Section processed");
}

fn get_outer_function_location(
    addr_info: &Option<wholesym::AddressInfo>,
) -> Option<SourceFilePathHandle> {
    let frames = addr_info.as_ref()?.frames.as_ref()?;
    frames.last()?.file_path
}

fn get_path_stack(
    addr_info: &Option<wholesym::AddressInfo>,
    symbol_map: &wholesym::SymbolMap,
    root_stack: StackHandle,
    category: CategoryHandle,
    profile: &mut Profile,
    stack_prefix_for_path: &mut HashMap<SourceFilePathHandle, StackHandle>,
) -> Option<StackHandle> {
    let path_handle = get_outer_function_location(addr_info)?;
    if let Some(ps) = stack_prefix_for_path.get(&path_handle) {
        return Some(*ps);
    }
    let path = symbol_map.resolve_source_file_path(path_handle);
    let path = path.display_path();
    let path = path.trim_start_matches("C:\\b\\s\\w\\ir\\cache\\builder\\");
    let mut accum_path = String::new();

    let mut path_stack = root_stack;

    for p in path.split(['/', '\\']) {
        accum_path.push('/');
        accum_path.push_str(p);
        let frame_str = profile.handle_for_string(&accum_path);
        let frame = profile.handle_for_frame_with_label(frame_str, category, FrameFlags::empty());
        path_stack = profile.handle_for_stack(frame, Some(path_stack));
    }
    stack_prefix_for_path.insert(path_handle, path_stack);
    Some(path_stack)
}

fn get_special_path(
    file_path: Option<SourceFilePathHandle>,
    symbol_map: &wholesym::SymbolMap,
    profile: &mut Profile,
) -> Option<StringHandle> {
    let file_path = file_path?;
    let p = symbol_map.resolve_source_file_path(file_path);
    let s = match p.special_path_str() {
        Some(special_path) => profile.handle_for_string(&special_path),
        None => profile.handle_for_string(p.raw_path()),
    };
    Some(s)
}

#[allow(clippy::too_many_arguments)]
fn emit_sample_for_address(
    relative_address: u32,
    addr_info: Option<wholesym::AddressInfo>,
    symbol_map: &wholesym::SymbolMap,
    timestamp: Timestamp,
    bytes: u64,
    root_stack: StackHandle,
    unknown_path_stack: StackHandle,
    unknown_bytes_frame: FrameHandle,
    thread: ThreadHandle,
    library_handle: LibraryHandle,
    category: CategoryHandle,
    profile: &mut Profile,
    stack_prefix_for_path: &mut HashMap<SourceFilePathHandle, StackHandle>,
) {
    let path_stack = get_path_stack(
        &addr_info,
        symbol_map,
        root_stack,
        category,
        profile,
        stack_prefix_for_path,
    )
    .unwrap_or(unknown_path_stack);

    let stack = if let Some(addr_info) = addr_info {
        let symbol = addr_info.symbol;
        let symbol_name = profile.handle_for_string(&symbol_map.resolve_symbol_name(symbol.name));
        let native_symbol = profile.handle_for_native_symbol(
            library_handle,
            symbol.address,
            symbol.size,
            symbol_name,
        );
        let mut s = path_stack;
        if let Some(mut frames) = addr_info.frames {
            frames.reverse();
            for (inline_depth, f) in frames.into_iter().enumerate() {
                let name = match f.function {
                    Some(function) => {
                        profile.handle_for_string(&symbol_map.resolve_function_name(function))
                    }
                    None => symbol_name,
                };
                let file_path = get_special_path(f.file_path, symbol_map, profile);
                let frame = profile.handle_for_frame_with_address_and_symbol(
                    FrameAddress::RelativeAddressFromInstructionPointer(
                        library_handle,
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
                s = profile.handle_for_stack(frame, Some(s));
            }
        } else {
            let frame = profile.handle_for_frame_with_address_and_symbol(
                FrameAddress::RelativeAddressFromInstructionPointer(
                    library_handle,
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
            s = profile.handle_for_stack(frame, Some(s));
        }
        s
    } else {
        profile.handle_for_stack(unknown_bytes_frame, Some(path_stack))
    };

    profile.add_sample(
        thread,
        timestamp,
        Some(stack),
        CpuDelta::ZERO,
        i32::try_from(bytes).unwrap(),
    );
}
