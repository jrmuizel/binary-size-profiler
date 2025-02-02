use std::path::Path;

use object::read::Object;
use object::ObjectSection;
use object::File;
use wholesym::SymbolManager;
use wholesym::SymbolManagerConfig;
use futures::executor::block_on;
use fxprof_processed_profile::{CategoryHandle, CpuDelta, Frame, FrameFlags, FrameInfo, Profile, ReferenceTimestamp, SamplingInterval, Timestamp, WeightType};

fn main() {

    use std::io::Read;

    let path = &std::env::args().nth(1).unwrap();
    let file_name = Path::new(path).file_name().unwrap().to_str().unwrap();

    let mut data = Vec::new();
    let mut file = std::fs::File::open(path).unwrap();

    file.read_to_end(&mut data).unwrap();
    let object_file = File::parse(&data).unwrap();

    let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default().verbose(true));
    let symbol_map = block_on(symbol_manager
        .load_symbol_map_for_binary_at_path(Path::new(path), None)).unwrap();

    let mut profile = Profile::new("size-profiler", ReferenceTimestamp::from_millis_since_unix_epoch(0.), SamplingInterval::from_hz(1000.));
    let process = profile.add_process(file_name, 0, Timestamp::from_millis_since_reference(0.));
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

            let addr_info = block_on(symbol_map.lookup(wholesym::LookupAddress::Relative(addr as u32)));
            //dbg!(&addr_info);
            let Some(addr_info) = addr_info  else { addr +=1; time +=1; continue };
            let mut last_location = None;
            let mut sample_frames: Vec<_> = Vec::new();

 
            if let Some (frames) = &addr_info.frames {
                let mut frames = frames.iter();

                while let Some(f) = frames.next() {
                    let name = f.function.as_ref().map(|x| x.as_str()).unwrap_or("unnamed");
                    last_location = f.file_path.clone();
                    sample_frames.push(FrameInfo { frame: Frame::Label(profile.intern_string(&name)), flags: FrameFlags::empty(), category_pair: category});
                }

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
                        sample_frames.push(FrameInfo { frame: Frame::Label(profile.intern_string(&p)), flags: FrameFlags::empty(), category_pair: category});
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
    let output_file = std::fs::File::create("output.json").unwrap();
    let writer = std::io::BufWriter::new(output_file);
    serde_json::to_writer(writer, &profile).unwrap();
}
