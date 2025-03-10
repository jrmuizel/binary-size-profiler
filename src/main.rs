use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;

use fxprof_processed_profile::{
    CategoryHandle, CategoryPairHandle, CpuDelta, Frame, FrameFlags, FrameInfo, LibraryInfo,
    Profile, ReferenceTimestamp, SamplingInterval, StackHandle, ThreadHandle, Timestamp,
    WeightType,
};
use indicatif::{ProgressBar, ProgressStyle};
use mimalloc::MiMalloc;
use object::read::macho::{FatArch, MachOFatFile32};
use object::read::Object;
use object::{CompressionFormat, File, FileKind, SectionKind};
use uuid::Uuid;
use wholesym::debugid::DebugId;
use wholesym::samply_symbols::relative_address_base;
use wholesym::{MultiArchDisambiguator, SymbolManager, SymbolManagerConfig};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let path = &std::env::args().nth(1).unwrap();
    let file_name = Path::new(path).file_name().unwrap().to_str().unwrap();

    let mut data = Vec::new();
    let mut file = std::fs::File::open(path).unwrap();
    file.read_to_end(&mut data).unwrap();

    let file_kind = FileKind::parse(&data[..]).unwrap();

    let mut profile = Profile::new(
        "size-profiler",
        ReferenceTimestamp::from_millis_since_unix_epoch(0.),
        SamplingInterval::from_hz(1000.),
    );

    let process = profile.add_process(file_name, 0, Timestamp::from_millis_since_reference(0.));
    let thread = profile.add_thread(process, 0, Timestamp::from_millis_since_reference(0.), true);
    profile.set_thread_samples_weight_type(thread, WeightType::Bytes);
    let category = CategoryHandle::OTHER.into();

    let root_s = profile.intern_string("(root)");
    let root_frame = profile.intern_frame(
        thread,
        FrameInfo {
            frame: Frame::Label(root_s),
            category_pair: category,
            flags: FrameFlags::empty(),
        },
    );
    let root_stack = profile.intern_stack(thread, None, root_frame);

    let config = SymbolManagerConfig::default()
        .respect_nt_symbol_path(true)
        .breakpad_symbols_server(
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

            let member_s = profile.intern_string(&member_name);
            let member_frame = profile.intern_frame(
                thread,
                FrameInfo {
                    frame: Frame::Label(member_s),
                    category_pair: category,
                    flags: FrameFlags::empty(),
                },
            );
            let member_stack = profile.intern_stack(thread, Some(root_stack), member_frame);

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

    let output_file = std::fs::File::create("output.json").unwrap();
    let writer = std::io::BufWriter::new(output_file);
    serde_json::to_writer(writer, &profile).unwrap();

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
    category: CategoryPairHandle,
    timestamp_offset: u64,
    binary_file_size: u64,
) {
    let lib = LibraryInfo {
        name: lib_info.name.unwrap(),
        debug_name: lib_info.debug_name.unwrap(),
        path: lib_info.path.unwrap(),
        debug_path: lib_info.debug_path.unwrap(),
        debug_id: lib_info.debug_id.unwrap(),
        code_id: lib_info.code_id.map(|ci| ci.to_string()),
        arch: lib_info.arch,
        symbol_table: None,
    };

    let base_addr = relative_address_base(object_file);

    let _lib = profile.add_lib(lib);

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
    category: CategoryPairHandle,
    timestamp_offset: u64,
) {
    let section_s = profile.intern_string(&section.name);
    let section_frame = profile.intern_frame(
        thread,
        FrameInfo {
            frame: Frame::Label(section_s),
            category_pair: category,
            flags: FrameFlags::empty(),
        },
    );
    let section_stack = profile.intern_stack(thread, Some(root_stack), section_frame);

    if section.kind != SectionKind::Text {
        let section_kind_str = profile.intern_string(&format!("{:?}", section.kind));
        let section_kind_frame = profile.intern_frame(
            thread,
            FrameInfo {
                frame: Frame::Label(section_kind_str),
                category_pair: category,
                flags: FrameFlags::empty(),
            },
        );
        let section_kind_stack =
            profile.intern_stack(thread, Some(section_stack), section_kind_frame);
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

    let unknown_path_str = profile.intern_string("<unknown path>");
    let unknown_path_frame = profile.intern_frame(
        thread,
        FrameInfo {
            frame: Frame::Label(unknown_path_str),
            category_pair: category,
            flags: FrameFlags::empty(),
        },
    );

    let unknown_bytes_str = profile.intern_string("<unknown bytes>");
    let unknown_bytes_frame = profile.intern_frame(
        thread,
        FrameInfo {
            frame: Frame::Label(unknown_bytes_str),
            category_pair: category,
            flags: FrameFlags::empty(),
        },
    );

    let unknown_path_stack = profile.intern_stack(thread, Some(section_stack), unknown_path_frame);

    let pb = ProgressBar::new(section_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut last_stack = None;
    let mut last_stack_bytes = 0;

    let mut next_sample_file_offset = section.file_offset;

    let mut stack_prefix_for_path: HashMap<String, StackHandle> = HashMap::new();
    for addr in section_start_rel..section_end_rel {
        if addr & 0xffff == 0 {
            pb.set_position(addr - section_start_rel);
        }

        let addr_info = symbol_map
            .lookup(wholesym::LookupAddress::Relative(addr as u32))
            .await;

        fn get_outer_function_location(
            addr_info: &Option<wholesym::AddressInfo>,
        ) -> Option<String> {
            let frames = addr_info.as_ref()?.frames.as_ref()?;
            let file_path = frames.last()?.file_path.as_ref()?;
            Some(file_path.display_path())
        }

        let path_stack = if let Some(path) = get_outer_function_location(&addr_info) {
            match stack_prefix_for_path.get(&path) {
                Some(ps) => *ps,
                None => {
                    let path = path.trim_start_matches("C:\\b\\s\\w\\ir\\cache\\builder\\");
                    let mut accum_path = String::new();

                    let mut path_stack = section_stack;

                    for p in path.split(['/', '\\']) {
                        use std::fmt::Write;
                        write!(&mut accum_path, "/{p}").unwrap();
                        let frame_str = profile.intern_string(&accum_path);
                        let frame = profile.intern_frame(
                            thread,
                            FrameInfo {
                                frame: Frame::Label(frame_str),
                                flags: FrameFlags::empty(),
                                category_pair: category,
                            },
                        );
                        path_stack = profile.intern_stack(thread, Some(path_stack), frame);
                    }
                    stack_prefix_for_path.insert(path.to_owned(), path_stack);
                    path_stack
                }
            }
        } else {
            unknown_path_stack
        };

        let stack = if let Some(addr_info) = addr_info {
            let symbol_addr = addr_info.symbol.address;
            let mut s = path_stack;
            if let Some(mut frames) = addr_info.frames {
                frames.reverse();
                for f in frames {
                    let name = f
                        .function
                        .unwrap_or_else(|| format!("unnamed_{symbol_addr:x}"));
                    let name = profile.intern_string(&name);
                    let frame = profile.intern_frame(
                        thread,
                        FrameInfo {
                            frame: Frame::Label(name),
                            flags: FrameFlags::empty(),
                            category_pair: category,
                        },
                    );
                    s = profile.intern_stack(thread, Some(s), frame);
                }
            } else {
                let name = profile.intern_string(&addr_info.symbol.name);
                let frame = profile.intern_frame(
                    thread,
                    FrameInfo {
                        frame: Frame::Label(name),
                        flags: FrameFlags::empty(),
                        category_pair: category,
                    },
                );
                s = profile.intern_stack(thread, Some(s), frame);
            }
            s
        } else {
            profile.intern_stack(thread, Some(path_stack), unknown_bytes_frame)
        };

        if let Some(last_stack) = last_stack {
            if stack != last_stack {
                profile.add_sample(
                    thread,
                    Timestamp::from_millis_since_reference(
                        (timestamp_offset + next_sample_file_offset) as f64,
                    ),
                    Some(last_stack),
                    CpuDelta::ZERO,
                    i32::try_from(last_stack_bytes).unwrap(),
                );
                next_sample_file_offset += last_stack_bytes;
                last_stack_bytes = 0;
            }
        }
        last_stack = Some(stack);
        last_stack_bytes += 1;
    }
    profile.add_sample(
        thread,
        Timestamp::from_millis_since_reference((timestamp_offset + next_sample_file_offset) as f64),
        last_stack,
        CpuDelta::ZERO,
        i32::try_from(last_stack_bytes).unwrap(),
    );
    next_sample_file_offset += last_stack_bytes;

    assert_eq!(
        next_sample_file_offset,
        section.file_offset + section.size,
        "Unexpected file offset after processing section {}",
        &section.name
    );

    pb.finish_with_message("Section processed");
}
