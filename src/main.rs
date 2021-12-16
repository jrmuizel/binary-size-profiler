use std::{collections::HashMap, usize};

use cpp_demangle::DemangleOptions;
use object::read::{ElfFile, Object};
use object::SymbolKind;
use object::ObjectSection;
use capstone::{arch::{ArchOperand, arm::{ArmOperand, ArmOperandType}}, prelude::*};
fn main() {
    let mut file = std::fs::File::open(std::env::args().nth(1).unwrap()).unwrap();
    let mut data = Vec::new();
    use std::io::Read;
    file.read_to_end(&mut data).unwrap();
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
