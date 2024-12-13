use std::fs::File;
use std::io::{self, Read};
use capstone::prelude::*;

fn main() -> io::Result<()> {
    // Step 1: Read the binary executable
    let mut file = File::open("target/debug/sasha_rs")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    println!("File size : {}",buffer.len());

    // Step 2: Initialize the Capstone disassembler
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64) // Assuming a 64-bit binary
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    // Step 3: Disassemble the binary
    let instructions = cs.disasm_all(&buffer, 0x1000) // Assuming a base address of 0x1000
        .expect("Failed to disassemble the binary");

    println!("Nb of instructions : {}", instructions.len());

    // Step 4: Translate disassembled instructions to Lean syntax
    for insn in instructions.iter() {
        println!("; Address: {:#x}", insn.address());
        println!("; Instruction: {}", insn);
        println!("{}", translate_to_lean(insn));
    }

    Ok(())
}

// Translate an instruction to Lean representation
fn translate_to_lean(insn: &capstone::Insn) -> String {
    // Placeholder: Define rules for translating each assembly instruction to Lean.
    // For example:
    match insn.mnemonic().unwrap_or_default() {
        "mov" => {
            let operands = insn.op_str().unwrap_or_default();
            format!("-- mov operation\nlean_mov({});", operands)
        }
        "add" => {
            let operands = insn.op_str().unwrap_or_default();
            format!("-- add operation\nlean_add({});", operands)
        }
        "sub" => {
            let operands = insn.op_str().unwrap_or_default();
            format!("-- sub operation\nlean_sub({});", operands)
        }
        "mul" => {
            let operands = insn.op_str().unwrap_or_default();
            format!("-- mul operation\nlean_mul({});", operands)
        }
        "div" => {
            let operands = insn.op_str().unwrap_or_default();
            format!("-- div operation\nlean_div({});", operands)
        }
        
        _ => format!("-- Unsupported instruction: {}", insn.mnemonic().unwrap_or_default()),
    }
}
