use std::borrow;
use std::path::Path;
use std::str::from_utf8;
use std::{collections::HashMap, usize};

use addr2line::FunctionName;
use cpp_demangle::DemangleOptions;
use rustc_demangle::demangle;
use object::read::{ElfFile, Object, MachOFile, PeFile};
use object::SymbolKind;
use object::ObjectSection;
use object::File;
use capstone::{arch::{ArchOperand, arm::{ArmOperand, ArmOperandType}}, prelude::*};
use wholesym::SymbolManager;
use wholesym::SymbolManagerConfig;
use futures::executor::block_on;
use fxprof_processed_profile::{CategoryHandle, CategoryPairHandle, CpuDelta, Frame, FrameFlags, FrameInfo, Profile, ReferenceTimestamp, SamplingInterval, Timestamp, WeightType};

fn main() {
    let mut file = std::fs::File::open(std::env::args().nth(1).unwrap()).unwrap();
    let mut data = Vec::new();
    use std::io::Read;
    file.read_to_end(&mut data).unwrap();
    main_win(&std::env::args().nth(1).unwrap());
    //main_macos(data);
}

fn main_win(path: &str) {
    let mut data = Vec::new();
    let mut file = std::fs::File::open(std::env::args().nth(1).unwrap()).unwrap();

    use std::io::Read;
    file.read_to_end(&mut data).unwrap();
    let object_file = File::parse(&data).unwrap();

    let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default().verbose(true));
    let symbol_map = block_on(symbol_manager
        .load_symbol_map_for_binary_at_path(Path::new(path), None)).unwrap();

    let mut profile = Profile::new("size-profiler", ReferenceTimestamp::from_millis_since_unix_epoch(0.), SamplingInterval::from_hz(1000.));
    let process = profile.add_process("foo", 0, Timestamp::from_millis_since_reference(0.));
    let thread = profile.add_thread(process, 0, Timestamp::from_millis_since_reference(0.), true);
    profile.set_thread_samples_weight_type(thread, WeightType::Bytes);
    let category = CategoryHandle::OTHER.into();

    for s in object_file.sections() {
        let mut addr = s.address();
        let mut time = 0;
        eprintln!("{:?}", s.name());
        let mut last_stack = None;
        let mut weight = 1;
        for _ in 0..s.data().len() {
            if addr & 0xffff == 0 {
                eprintln!("{:x}/{:x} = {:.2?}%", addr, s.data().len(), 100. * addr as f64 / s.data().len() as f64);
            }
            // if time & 0x3 != 0 {
            //     time += 1;
            //     addr += 1;
            //     continue;
            // }
            let mut addr_info = block_on(symbol_map.lookup(wholesym::LookupAddress::Relative(addr as u32)));
            //dbg!(&addr_info);
            let Some(addr_info) = addr_info  else { addr +=1; time +=1; continue };
            let mut last_location = None;
            let mut sample_frames: Vec<_> = Vec::new();

 
            if let Some (frames) = &addr_info.frames {
                let mut frames = frames.iter();

                //let mut funcs = Vec::new();


                while let Some(f) = frames.next() {
                    let fname = f.function.as_ref().map(|x| x.as_str()).unwrap_or("unnamed");
                    let demang_sym = cpp_demangle::Symbol::new(&*fname);
                    let name = if let Ok(sym) = demang_sym {
                        sym.demangle(&DemangleOptions::default().no_params().no_return_type()).unwrap()
                    } else {
                        let demang_sym = rustc_demangle::try_demangle(&fname);
                        if let Ok(sym) = demang_sym {
                            sym.to_string()
                        } else {
                            fname.to_owned()
                        }
                    };
                    last_location = f.file_path.clone();
                    //.map(|x| x.demangle(&DemangleOptions::default()));
                    sample_frames.push(FrameInfo { frame: Frame::Label(profile.intern_string(&name)), flags: FrameFlags::empty(), category_pair: category});

                    //funcs.push(name);
                }

                //println!("swapper     0/0     [000] {}:          1 cycles:", time);
                /*for f in &funcs {
                    let module = "bar";
                    let ip = addr;
                    println!("\t{:x} {} ({})", ip, f, module);
                }*/
                if let Some(location) = last_location {
                    let path = location.raw_path();
                    //eprintln!("{:?}", path);
                    let path = path.trim_start_matches("C:\\b\\s\\w\\ir\\cache\\builder\\");
                    let mut accum = String::new();
                    let mut paths = Vec::new();
                    for p in path.split(|c| c == '/' || c == '\\') {
                        accum = format!("{}/{}", accum, p);
                        paths.push(accum.clone());
                    }
                    
                    for p in paths.iter().rev() {
                        let module = "bar";
                        let ip = addr;
                        sample_frames.push(FrameInfo { frame: Frame::Label(profile.intern_string(&p)), flags: FrameFlags::empty(), category_pair: category});

                        //println!("\t{:x} {} ({})", ip, p, module);
                    }

                }
            } else {
                sample_frames.push(FrameInfo { frame: Frame::Label(profile.intern_string(&addr_info.symbol.name)), flags: FrameFlags::empty(), category_pair: category});

            }
            //dbg!(&sample_frames);
            sample_frames.reverse();
            let stack = profile.intern_stack_frames(thread, sample_frames.into_iter());
            if stack != last_stack {
                profile.add_sample(thread, Timestamp::from_millis_since_reference(time as f64), last_stack, CpuDelta::ZERO, weight);
                weight = 1;
            } else {
                weight += 1;
            }
            last_stack = stack;


            //println!("");
            time += 1;
            addr += 1;
        }
        profile.add_sample(thread, Timestamp::from_millis_since_reference(time as f64), last_stack, CpuDelta::ZERO, weight);

    }
    let mut output_file = std::fs::File::create("output.json").unwrap();
     let writer = std::io::BufWriter::new(output_file);
      serde_json::to_writer(writer, &profile).unwrap();

    

}

fn main_macos(data: Vec<u8>) {
    let object_file = MachOFile::parse(&data).unwrap();
    let debug = locate_dwarf::locate_dsym("", *object_file.mach_uuid().unwrap().as_bytes());
    dbg!(&debug);
    let endian = if object_file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };


    let mut debug_file = std::fs::File::open(debug.unwrap()).unwrap();

    let mut debug_data = Vec::new();
    use std::io::Read;
    debug_file.read_to_end(&mut debug_data).unwrap();
    let debug_object = symbolic_debuginfo::Object::parse(&debug_data).unwrap();

    let ao = addr2line::object::File::parse(&debug_data[..]).unwrap();
    let context = addr2line::Context::new(&ao).unwrap();
    for s in object_file.sections() {
        let mut addr = s.address();
        let mut time = 0;
        for _ in 0..s.data().len() {
            if time & 0x3 != 0 {
                time += 1;
                addr += 1;
                continue;
            }
            let mut frames = context.find_frames(addr).unwrap();
            let mut funcs = Vec::new();
            let mut last_location = None;
            while let Some(f) = frames.next().unwrap() {
                let fname = f.function.unwrap().name;
                let demang_sym = cpp_demangle::Symbol::new(&*fname);
                let name = if let Ok(sym) = demang_sym {
                    sym.demangle(&DemangleOptions::default().no_params().no_return_type()).unwrap()
                } else {
                    let demang_sym = rustc_demangle::try_demangle((from_utf8(&*fname).unwrap()));
                    if let Ok(sym) = demang_sym {
                        sym.to_string()
                    } else {
                        std::str::from_utf8(&fname).unwrap().to_owned()
                    }
                };
                last_location = f.location;
                //.map(|x| x.demangle(&DemangleOptions::default()));
                funcs.push(name);
            }
            let location = context.find_location(addr).unwrap();
            println!("swapper     0/0     [000] {}:          1 cycles:", time);
            for f in &funcs {
                let module = "bar";
                let ip = addr;
                println!("\t{:x} {} ({})", ip, f, module);
            }
            if let Some(location) = last_location {
                let path = Path::new(location.file.unwrap());
                let mut accum = String::new();
                let mut paths = Vec::new();
                for p in path.components() {
                    accum = format!("{}/{}", accum, p.as_os_str().to_str().unwrap());
                    paths.push(accum.clone());
                }
                for p in paths.iter().rev() {
                    let module = "bar";
                    let ip = addr;
                    println!("\t{:x} {} ({})", ip, p, module);
                }

            }

            println!("");
            time += 1;
            addr += 1;
        }
    }

    /* 
    let perf = true;
    for s in debug_object.debug_session().unwrap().functions() {
        let f = s.unwrap();
        if f.name.as_str().contains(&pattern) {
            dbg!(f.name, f.address, f.size);
            for s in object_file.sections() {
                let addr = f.address + debug_object.load_address();                ;
                if addr > s.address() && addr <= s.address() + s.size() {
                    assert!(f.address + f.size <= s.address() + s.size());
                    let func = &s.data()[dbg!((addr - s.address()) as usize..(addr - s.address() + f.size) as usize)];
                    let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().unwrap();
                    let insns = cs.disasm_all(func, addr).unwrap();
                    let mut time = 0;
                    for i in insns.iter() {
                        let mut frames = context.find_frames(i.address()).unwrap();
                        let mut funcs = Vec::new();
                        while let Some(f) = frames.next().unwrap() {
                            let fname = f.function.unwrap().name;
                            let demang_sym = cpp_demangle::Symbol::new(&*fname);
                            let name = if let Ok(sym) = demang_sym {
                                sym.demangle(&DemangleOptions::default().no_params().no_return_type()).unwrap()
                            } else {
                                std::str::from_utf8(&fname).unwrap().to_owned()
                            };
                            //.map(|x| x.demangle(&DemangleOptions::default()));
                            funcs.push(name);
                        }
                        if perf {
                            for _ in 0..i.bytes().len() {
                                println!("swapper     0/0     [000] {}:          1 cycles:", time);
                                for f in &funcs {
                                    let module = "bar";
                                    let ip = i.address();
                                    println!("\t{:x} {} ({})", ip, f, module);
                                }
                                println!("");
                                time += 1;
                            }
                        } else {
                            println!("{:40} {}", format!("{}", i), funcs.join(" "));
                        }                        
                    }
                } 
            }
        }
        
    }*/
    /*
    let debug_object = MachOFile::parse(&debug_data).unwrap();
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        match debug_object.section_by_name(id.name()) {
            Some(ref section) => Ok(section
                .uncompressed_data()
                ),
            None => Ok(borrow::Cow::Borrowed(&[][..])),
        }
    };
    let dwarf_cow = gimli::Dwarf::load(&load_section).unwrap();
    let borrow_section: &dyn for<'a> Fn(
        &'a borrow::Cow<[u8]>,
    ) -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
        &|section| gimli::EndianSlice::new(&*section, endian);    //gimli::Dwarf::open(debug.unwrap()).unwrap();

    let dwarf = dwarf_cow.borrow(&borrow_section);
    let mut iter = dwarf.units();
    
    while let Some(header) = iter.next().unwrap() {
        println!(
            "Unit at <.debug_info+0x{:x}>",
            header.offset().as_debug_info_offset().unwrap().0
        );
        let unit = dwarf.unit(header).unwrap();

        // Iterate over the Debugging Information Entries (DIEs) in the unit.
        let mut depth = 0;
        let mut entries = unit.entries();
        while let Some((delta_depth, entry)) = entries.next_dfs().unwrap() {
            depth += delta_depth;
            println!("<{}><{:x}> {}", depth, entry.offset().0, entry.tag());

            // Iterate over the attributes in the DIE.
            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next().unwrap() {
                println!("   {}: {:?}", attr.name(), attr.value());
            }
        }
    }*/

/* *

    for s in object_file.dynamic_symbols().chain(object_file.symbols())
     {
         let sym = s.1;
        if sym.name().unwrap().contains(&pattern) {
            println!("{:?}", sym);
            let mut frames = context.find_frames(sym.address()).unwrap();
            while let Some(f) = frames.next().unwrap() {
                let fname = f.function.unwrap().name;
                let name = std::str::from_utf8(&fname).unwrap().to_owned();
                dbg!(name);
            }

        }
    }*/

}
fn main_arm(data: Vec<u8>) {
    let object_file = ElfFile::parse(&data).unwrap();
    let ao = addr2line::object::File::parse(&data[..]).unwrap();
    let context = addr2line::Context::new(&ao).unwrap();

    let pattern = std::env::args().nth(2).unwrap();
    for s in object_file
        .dynamic_symbols()
        .chain(object_file.symbols())
        .filter(|(_, symbol)| symbol.kind() == SymbolKind::Text && !symbol.is_undefined()) {
            let sym = s.1;
    //syms.sort_by_key(|x| x.addr);
        if sym.name().unwrap().contains(&pattern) {
                    dbg!(&sym);
                    dbg!(cpp_demangle::Symbol::new(sym.name().unwrap().as_bytes()).map(|x| x.demangle(&DemangleOptions::default())));
            
            let sec = object_file.section_by_index(sym.section_index().unwrap()).unwrap();
            let mode = if sym.address() % 2 == 1 {
                arch::arm::ArchMode::Thumb
            } else {
                arch::arm::ArchMode::Arm
            };
            let address = sym.address() & !1;
            let func_indx = (address - sec.address()) as usize;
            let func = &sec.data()[func_indx .. func_indx + sym.size() as usize];
            dbg!(func.len());

            let cs = Capstone::new().arm().mode(mode).detail(true).build().unwrap();
            let insns = cs.disasm_all(func, address).unwrap();
            let mut branch_targets = Vec::new();
            for i in insns.iter() {
                let detail = cs.insn_detail(&i).unwrap();
                let groups = detail.groups();
                let branch = groups.map(|g| cs.group_name(g).unwrap()).any(|x| x == "branch_relative" || x == "jump");
                if branch {

                    let operands = detail.arch_detail().operands();
                    match &operands[0] {
                        ArchOperand::ArmOperand(ArmOperand {op_type: ArmOperandType::Imm(i), .. }) => { branch_targets.push(*i); },
                        _ => {},
                    }

                }
            }
            branch_targets.sort();
            for b in &branch_targets {
                println!("{:x}", b);
            }
            let mut branch_index = 0;
            for i in insns.iter() {
                if branch_index < branch_targets.len() {
                    if branch_targets[branch_index] == i.address() as i32 {
                        println!("L:");
                        //branch_index += 1;
                    }
                    while branch_targets[branch_index] <= i.address() as i32 {
                        branch_index += 1;
                    }
                }
                let mut frames = context.find_frames(i.address()).unwrap();
                let mut funcs = Vec::new();
                while let Some(f) = frames.next().unwrap() {
                    let fname = f.function.unwrap().name;
                    let demang_sym = cpp_demangle::Symbol::new(&*fname);
                    let name = if let Ok(sym) = demang_sym {
                        sym.demangle(&DemangleOptions::default().no_params().no_return_type()).unwrap()
                    } else {
                        std::str::from_utf8(&fname).unwrap().to_owned()
                    };
                    //.map(|x| x.demangle(&DemangleOptions::default()));
                    funcs.push(name);
                }
                //println!("");
                //println!("Hello {:400}!", format!("{}", i));
                println!("{:40} {}", format!("{}", i), funcs.join(" "));
            }
            //dbg!(sec.data()[(sym.address() - sec.address()) as usize]);
        }
    }
    /* 
    let mut new_syms = Vec::with_capacity(syms.len());
    new_syms.extend(syms[0..1].iter().map(|x| x.clone()));
    for s in syms.windows(2) {
        let end = s[0].addr + s[0].size;
        if end < s[1].addr {
            new_syms.push(Sym{ name: format!("FUN_{:x}", end), addr: end, size: s[1].addr - end})
        }
        new_syms.push(s[1].clone());
    }
    for s in &new_syms {
        
        dbg!(s);
    }*/

    println!("Hello, world!");
}
