use std::collections::HashMap;
use std::sync::OnceLock;

use crate::common::error::{Error, Result};
use crate::common::util::hash_name;

#[derive(Clone, Debug)]
pub struct OpcodeDef {
    pub id: u16,
    pub name: &'static str,
    pub params: Vec<&'static str>,
}

#[derive(Debug)]
pub struct Metadata {
    pub opcodes_by_id: HashMap<u16, OpcodeDef>,
    pub opcode_ids_by_name: HashMap<&'static str, u16>,
    pub script_commands: HashMap<u32, &'static str>,
}

static METADATA: OnceLock<Metadata> = OnceLock::new();

pub fn metadata() -> &'static Metadata {
    METADATA.get_or_init(load_metadata)
}

fn load_metadata() -> Metadata {
    let mut opcodes_by_id = HashMap::new();
    let mut opcode_ids_by_name = HashMap::new();
    for line in include_str!("../../data/metadata/opcodes.txt").lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.first().is_some_and(|part| part.starts_with("OP")) {
            let id = parts[1].parse::<u16>().unwrap();
            let name: &'static str = Box::leak(parts[0].to_string().into_boxed_str());
            let def = OpcodeDef {
                id,
                name,
                params: parts[3..].iter().map(|part| Box::leak((*part).to_string().into_boxed_str()) as &'static str).collect(),
            };
            opcode_ids_by_name.insert(def.name, id);
            opcodes_by_id.insert(id, def);
        }
    }

    let mut script_commands = HashMap::new();
    for line in include_str!("../../data/metadata/commands.txt").lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.is_empty() || parts[0].starts_with("//") {
            continue;
        }
        let command: &'static str = Box::leak(parts[0].to_string().into_boxed_str());
        let hash = hash_name(command);
        script_commands.entry(hash).or_insert(command);
    }

    Metadata {
        opcodes_by_id,
        opcode_ids_by_name,
        script_commands,
    }
}

pub fn command_name_for_hash(hash: u32) -> Option<&'static str> {
    metadata().script_commands.get(&hash).copied()
}

pub fn command_hash_for_name(value: &str) -> u32 {
    hash_name(value)
}

pub fn is_known_command_name(value: &str) -> bool {
    metadata().script_commands.contains_key(&hash_name(value))
}

pub fn opcode_by_id(id: u16) -> Option<&'static OpcodeDef> {
    metadata().opcodes_by_id.get(&id)
}

pub fn opcode_id_by_name(name: &str) -> Option<u16> {
    metadata().opcode_ids_by_name.get(name).copied()
}

pub fn require_opcode_id(name: &str) -> Result<u16> {
    opcode_id_by_name(name).ok_or_else(|| Error::msg(format!("unknown opcode {name}")))
}
