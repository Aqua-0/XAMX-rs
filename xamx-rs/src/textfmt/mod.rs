use std::collections::{BTreeMap, HashMap, HashSet};

use crate::amx::Amx;
use crate::common::error::{Error, Result};
use crate::common::util::{
    print_bytes_block, read_bytes_block, read_i32_le, read_u16_le, read_u32_le, vm_param_str, write_i32_le,
    write_u16_le, write_u32_le,
};
use crate::meta::{command_hash_for_name, command_name_for_hash, is_known_command_name, opcode_by_id, require_opcode_id};

pub fn disassemble(amx: &Amx) -> Result<String> {
    let (header, mut links) = print_header(amx);
    analyze_disassembly(amx, &mut links)?;
    let mut lines = vec![
        "// Please read the example disassembly in the examples folder if you haven't done so yet".to_string(),
    ];
    lines.extend(header);
    lines.push(String::new());
    lines.push(String::new());
    lines.push(String::new());
    lines.extend(print_disassembly(amx, &links)?);
    lines.push(String::new());
    lines.push(String::new());
    lines.push(String::new());
    lines.push("Data:".to_string());
    lines.extend(print_bytes_block(&amx.data_section, 4));
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn get_sysreq(number: u32) -> String {
    command_name_for_hash(number)
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("  #{number}"))
}

fn get_sysreq_param(amx: &Amx, number: u32) -> String {
    amx.native_functions
        .iter()
        .find(|(index, _)| *index == number)
        .and_then(|(_, hash)| command_name_for_hash(*hash))
        .map(ToString::to_string)
        .unwrap_or_else(|| number.to_string())
}

fn print_header(amx: &Amx) -> (Vec<String>, BTreeMap<i32, String>) {
    let mut lines = vec![
        format!("Allocated memory: {} //{:#x}", amx.allocated_memory, amx.allocated_memory),
        "Main function: funcmain".to_string(),
        format!("Cell size: {}", amx.cell_size),
        format!("Flags: {}", amx.flags),
        format!("Table record size: {}", amx.def_size),
    ];
    let mut links = BTreeMap::new();
    if !amx.public_functions.is_empty() {
        lines.push(String::new());
        lines.push("Public functions:".to_string());
        for (address, name) in &amx.public_functions {
            let func_name = format!("func_{}", command_name_for_hash(*name).unwrap_or(&format!("pub{name}")));
            lines.push(format!("    #{func_name} {}", get_sysreq(*name)));
            links.insert(*address as i32, func_name);
        }
    }
    if !amx.native_functions.is_empty() {
        lines.push(String::new());
        lines.push("Native functions:".to_string());
        for (index, name) in &amx.native_functions {
            lines.push(format!("    {index} {}", get_sysreq(*name)));
        }
    }
    if !amx.libraries.is_empty() {
        lines.push(String::new());
        lines.push("Libraries:".to_string());
        for (index, name) in &amx.libraries {
            lines.push(format!("    {index} {}", get_sysreq(*name)));
        }
    }
    if !amx.public_variables.is_empty() {
        lines.push(String::new());
        lines.push("Public variables:".to_string());
        for (address, name) in &amx.public_variables {
            lines.push(format!("    {address:#x} {}", get_sysreq(*name)));
        }
    }
    if !amx.public_tags.is_empty() {
        lines.push(String::new());
        lines.push("Public tags:".to_string());
        for (address, name) in &amx.public_tags {
            lines.push(format!("    {address:#x} {}", get_sysreq(*name)));
        }
    }
    if !amx.overlays.is_empty() {
        lines.push(String::new());
        lines.push("Overlays:".to_string());
        lines.extend(print_bytes_block(&amx.overlays, 4));
    }
    if !amx.symbol_names.is_empty() {
        lines.push(String::new());
        lines.push("Symbol names:".to_string());
        lines.extend(print_bytes_block(&amx.symbol_names, 4));
    }
    (lines, links)
}

fn analyze_disassembly(amx: &Amx, links: &mut BTreeMap<i32, String>) -> Result<()> {
    if amx.main_address != -1 {
        links.insert(amx.main_address, "funcmain".to_string());
    }
    let mut code_ptr = 0i32;
    for cell in &amx.code_section {
        let opcode = read_u16_le(cell, 0)?;
        if let Some(def) = opcode_by_id(opcode) {
            let opcode_ptr = code_ptr;
            let mut cursor = 4usize;
            for param in &def.params {
                if *param == "offset" || *param == "call_offset" {
                    let offset = read_i32_le(cell, cursor)?;
                    let target = opcode_ptr + offset;
                    if !links.contains_key(&target) {
                        let label = if *param == "offset" {
                            format!("lbl{}", links.len())
                        } else {
                            format!("func{}", links.len())
                        };
                        links.insert(target, label);
                    }
                }
                cursor += 4;
            }
            if opcode == 0x82 {
                let case_count = read_u32_le(cell, 4)? as usize;
                let mut ptr = 4usize;
                for _ in 0..=case_count {
                    let offset = read_i32_le(cell, ptr + 4)?;
                    let origin = code_ptr + (ptr as i32);
                    let target = origin + offset;
                    if !links.contains_key(&target) {
                        let label = format!("lbl{}", links.len());
                        links.insert(target, label);
                    }
                    ptr += 8;
                }
            }
        }
        code_ptr += cell.len() as i32;
    }
    Ok(())
}

fn print_disassembly(amx: &Amx, links: &BTreeMap<i32, String>) -> Result<Vec<String>> {
    let mut lines = vec!["Code:".to_string()];
    let mut code_ptr = 0i32;
    let mut printed_links = HashSet::new();

    for cell in &amx.code_section {
        let opcode = read_u16_le(cell, 0)?;
        let opcode_param = read_u16_le(cell, 2)?;
        if let Some(name) = links.get(&code_ptr) {
            lines.push(String::new());
            lines.push(format!(
                "{}#{} //{:#x}",
                if name.starts_with("func") { "  " } else { "   " },
                name,
                code_ptr
            ));
            printed_links.insert(code_ptr);
        }
        if let Some(def) = opcode_by_id(opcode) {
            let mut line = format!("    {:17} {}", def.name, vm_param_str(u64::from(opcode_param), 2));
            let opcode_ptr = code_ptr;
            let mut cursor = 4usize;
            for param in &def.params {
                if *param == "offset" || *param == "call_offset" {
                    let offset = read_i32_le(cell, cursor)?;
                    let target = opcode_ptr + offset;
                    let name = links
                        .get(&target)
                        .ok_or_else(|| Error::msg(format!("missing link target at {target:#x}")))?;
                    line.push(' ');
                    line.push_str(name);
                } else {
                    let value = read_u32_le(cell, cursor)?;
                    line.push(' ');
                    line.push_str(&vm_param_str(u64::from(value), 4));
                }
                cursor += 4;
            }
            if opcode == 0x82 {
                let case_count = read_u32_le(cell, 4)? as usize;
                let mut ptr = 4usize;
                for _ in 0..=case_count {
                    let value = read_u32_le(cell, ptr)?;
                    let offset = read_i32_le(cell, ptr + 4)?;
                    let target = code_ptr + (ptr as i32) + offset;
                    let name = links
                        .get(&target)
                        .ok_or_else(|| Error::msg(format!("missing case target at {target:#x}")))?;
                    line.push(' ');
                    line.push_str(&vm_param_str(u64::from(value), 4));
                    line.push(' ');
                    line.push_str(name);
                    ptr += 8;
                }
            } else if opcode == 0x87 {
                let native = read_u32_le(cell, cursor)?;
                let pop_count = read_u32_le(cell, cursor + 4)?;
                line.push(' ');
                line.push_str(&get_sysreq_param(amx, native));
                line.push(' ');
                line.push_str(&pop_count.to_string());
            }
            lines.push(line);
        } else {
            lines.push(format!("    {:17} {}", "raw", cell.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")));
        }
        code_ptr += cell.len() as i32;
    }

    let _ = printed_links;
    Ok(lines)
}

pub fn assemble_text(lines: &[String]) -> Result<Amx> {
    let mut iter_index = 0usize;
    let mut amx = Amx {
        main_address: -1,
        ..Amx::default()
    };
    let mut main_func_name = "funcmain".to_string();
    let mut pub_func_defs: Vec<(String, u32)> = Vec::new();
    let mut label_defs: HashMap<String, i32> = HashMap::new();
    let mut label_calls: Vec<(i32, usize, String)> = Vec::new();
    let mut sysreq_calls: Vec<(usize, String)> = Vec::new();
    let mut native_by_hash: HashMap<u32, u32> = HashMap::new();
    let mut code_buf = Vec::new();

    while let Some(line) = next_line(lines, &mut iter_index) {
        if line.starts_with(&["Allocated", "memory:"]) {
            amx.allocated_memory = parse_u32(line[2])?;
        } else if line.starts_with(&["Main", "function:"]) {
            main_func_name = line[2].to_string();
        } else if line.starts_with(&["Cell", "size:"]) {
            amx.cell_size = parse_u16(line[2])?;
        } else if line.first() == Some(&"Flags:") {
            amx.flags = parse_u16(line[1])?;
        } else if line.starts_with(&["Table", "record", "size:"]) {
            amx.def_size = parse_u16(line[3])?;
        } else if line.starts_with(&["Public", "functions:"]) {
            while let Some(peek) = next_line(lines, &mut iter_index) {
                if peek.len() != 2 || !peek[0].starts_with('#') {
                    iter_index = iter_index.saturating_sub(1);
                    break;
                }
                pub_func_defs.push((peek[0][1..].to_string(), parse_hash_or_name(peek[1])?));
            }
        } else if line.starts_with(&["Native", "functions:"]) {
            while let Some(peek) = next_line(lines, &mut iter_index) {
                if peek.len() != 2 || peek[0].parse::<u32>().is_err() {
                    iter_index = iter_index.saturating_sub(1);
                    break;
                }
                let num = parse_u32(peek[0])?;
                let hash = parse_hash_or_name(peek[1])?;
                amx.native_functions.push((num, hash));
                native_by_hash.insert(hash, num);
            }
        } else if line.starts_with(&["Libraries:"]) {
            while let Some(peek) = next_line(lines, &mut iter_index) {
                if peek.len() != 2 || peek[0].parse::<u32>().is_err() {
                    iter_index = iter_index.saturating_sub(1);
                    break;
                }
                amx.libraries.push((parse_u32(peek[0])?, parse_hash_or_name(peek[1])?));
            }
        } else if line.starts_with(&["Public", "variables:"]) {
            while let Some(peek) = next_line(lines, &mut iter_index) {
                if peek.len() != 2 || !peek[0].starts_with("0x") {
                    iter_index = iter_index.saturating_sub(1);
                    break;
                }
                amx.public_variables.push((parse_u32(peek[0])?, parse_hash_or_name(peek[1])?));
            }
        } else if line.starts_with(&["Public", "tags:"]) {
            while let Some(peek) = next_line(lines, &mut iter_index) {
                if peek.len() != 2 || !peek[0].starts_with("0x") {
                    iter_index = iter_index.saturating_sub(1);
                    break;
                }
                amx.public_tags.push((parse_u32(peek[0])?, parse_hash_or_name(peek[1])?));
            }
        } else if line.starts_with(&["Overlays:"]) {
            let block = collect_hex_lines(lines, &mut iter_index);
            amx.overlays = read_bytes_block(&block)?;
        } else if line.starts_with(&["Symbol", "names:"]) {
            let block = collect_hex_lines(lines, &mut iter_index);
            amx.symbol_names = read_bytes_block(&block)?;
        } else if line.starts_with(&["Code:"]) {
            while let Some(code_line) = next_line(lines, &mut iter_index) {
                if code_line[0].starts_with('#') {
                    let label = &code_line[0][1..];
                    if label_defs.insert(label.to_string(), code_buf.len() as i32).is_some() {
                        return Err(Error::msg(format!("duplicate label definition #{label}")));
                    }
                } else if code_line.len() == 5 && code_line[0] == "raw" {
                    for byte in &code_line[1..] {
                        code_buf.push(u8::from_str_radix(byte, 16).map_err(|_| Error::msg("invalid raw byte"))?);
                    }
                } else if code_line.len() > 1 {
                    let opcode_name = code_line[0];
                    let opcode_id = match require_opcode_id(opcode_name) {
                        Ok(value) => value,
                        Err(_) => {
                            iter_index = iter_index.saturating_sub(1);
                            break;
                        }
                    };
                    let opcode_ptr = code_buf.len() as i32;
                    write_u16_le(opcode_id, &mut code_buf);
                    if code_line[1].starts_with("0x") {
                        write_u16_le(parse_u16(code_line[1])?, &mut code_buf);
                    } else {
                        write_u16_le(parse_i16(code_line[1])? as u16, &mut code_buf);
                    }
                    for param in &code_line[2..] {
                        if is_decimal(param) {
                            write_i32_le(param.parse::<i32>().map_err(|_| Error::msg("invalid signed param"))?, &mut code_buf);
                        } else if param.starts_with("0x") {
                            write_u32_le(parse_u32(param)?, &mut code_buf);
                        } else if is_known_command_name(param) {
                            sysreq_calls.push((code_buf.len(), (*param).to_string()));
                            write_u32_le(0, &mut code_buf);
                        } else {
                            let origin = if opcode_name == "OP_CASETBL" {
                                code_buf.len() as i32 - 4
                            } else {
                                opcode_ptr
                            };
                            label_calls.push((origin, code_buf.len(), (*param).to_string()));
                            write_u32_le(0, &mut code_buf);
                        }
                    }
                } else {
                    iter_index = iter_index.saturating_sub(1);
                    break;
                }
            }
        } else if line.starts_with(&["Data:"]) {
            let block = collect_hex_lines(lines, &mut iter_index);
            amx.data_section = read_bytes_block(&block)?;
        }
    }

    if amx.allocated_memory == 0 {
        return Err(Error::msg("allocated memory not defined"));
    }
    if amx.cell_size == 0 {
        return Err(Error::msg("cell size not defined"));
    }
    if amx.def_size == 0 {
        return Err(Error::msg("table record size not defined"));
    }

    for (address, name) in sysreq_calls {
        let hash = command_hash_for_name(&name);
        let native = native_by_hash
            .get(&hash)
            .ok_or_else(|| Error::msg(format!("calling native function that was not imported: {name}")))?;
        code_buf[address..address + 4].copy_from_slice(&native.to_le_bytes());
    }
    for (name, hash) in pub_func_defs {
        let address = label_defs
            .get(&name)
            .ok_or_else(|| Error::msg(format!("label {name} not defined")))?;
        amx.public_functions.push((*address as u32, hash));
    }
    for (calling_addr, param_addr, label_name) in label_calls {
        let target = label_defs
            .get(&label_name)
            .ok_or_else(|| Error::msg(format!("label {label_name} not defined")))?;
        let offset = *target - calling_addr;
        code_buf[param_addr..param_addr + 4].copy_from_slice(&offset.to_le_bytes());
    }
    amx.main_address = *label_defs
        .get(&main_func_name)
        .ok_or_else(|| Error::msg(format!("main function label {main_func_name} not defined")))?;
    amx.code_section = crate::amx::decode_cells(&code_buf)?;
    Ok(amx)
}

fn next_line<'a>(lines: &'a [String], index: &mut usize) -> Option<Vec<&'a str>> {
    while *index < lines.len() {
        let raw = &lines[*index];
        *index += 1;
        let without_comment = raw.split_once("//").map_or(raw.as_str(), |(head, _)| head);
        let parts = without_comment.split_whitespace().collect::<Vec<_>>();
        if !parts.is_empty() {
            return Some(parts);
        }
    }
    None
}

fn collect_hex_lines(lines: &[String], index: &mut usize) -> Vec<String> {
    let mut out = Vec::new();
    while *index < lines.len() {
        let line = lines[*index].clone();
        let uncommented = line.split_once("//").map_or(line.as_str(), |(head, _)| head);
        let parts = uncommented.split_whitespace().collect::<Vec<_>>();
        if parts.is_empty() {
            *index += 1;
            continue;
        }
        let is_hex = parts
            .iter()
            .all(|word| word.chars().all(|ch| ch.is_ascii_hexdigit() || ch == 'x'));
        if !is_hex {
            break;
        }
        out.push(line);
        *index += 1;
    }
    out
}

trait LinePrefix<'a> {
    fn starts_with(&self, expected: &[&str]) -> bool;
}

impl<'a> LinePrefix<'a> for Vec<&'a str> {
    fn starts_with(&self, expected: &[&str]) -> bool {
        self.len() >= expected.len() && self.iter().zip(expected.iter()).all(|(a, b)| a == b)
    }
}

fn parse_u32(value: &str) -> Result<u32> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|_| Error::msg(format!("invalid integer {value}")))
    } else {
        value.parse::<u32>().map_err(|_| Error::msg(format!("invalid integer {value}")))
    }
}

fn parse_u16(value: &str) -> Result<u16> {
    parse_u32(value)?
        .try_into()
        .map_err(|_| Error::msg(format!("value out of range for u16: {value}")))
}

fn parse_i16(value: &str) -> Result<i16> {
    value.parse::<i16>().map_err(|_| Error::msg(format!("invalid integer {value}")))
}

fn parse_hash_or_name(value: &str) -> Result<u32> {
    if let Some(hash) = value.strip_prefix('#') {
        hash.parse::<u32>().map_err(|_| Error::msg(format!("invalid hash {value}")))
    } else {
        Ok(command_hash_for_name(value))
    }
}

fn is_decimal(value: &str) -> bool {
    value.chars().all(|ch| ch.is_ascii_digit()) || (value.starts_with('-') && value[1..].chars().all(|ch| ch.is_ascii_digit()))
}
