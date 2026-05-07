use crate::amx::{Amx, AMX_MAGIC_32, AMX_MAGIC_BTLAI};
use crate::common::error::{Error, Result};
use crate::common::util::{print_bytes_block, read_bytes_block, read_u32_le, write_u32_le};

#[derive(Clone, Debug)]
pub struct MixedAmx {
    pub data: Vec<u8>,
    pub script: Amx,
}

#[derive(Clone, Debug)]
pub enum MapPart {
    Raw(Vec<u8>),
    Amx(Amx),
    Mixed(MixedAmx),
}

#[derive(Clone, Debug)]
pub enum XamxFile {
    RawScript(Amx),
    BtlAiScript { script: Amx, other: Vec<u8> },
    MapFile { abbreviation: [u8; 2], alignment: usize, parts: Vec<MapPart> },
}

impl XamxFile {
    pub fn load_compiled(data: &[u8]) -> Result<Self> {
        if data.get(4..8) == Some(&AMX_MAGIC_32) {
            let length = read_u32_le(data, 0)? as usize;
            if length == data.len() {
                return Ok(Self::RawScript(Amx::load_compiled(data)?));
            }
            if data.get(length + 4..length + 8) == Some(&AMX_MAGIC_BTLAI)
                && (read_u32_le(data, length)? as usize + length) == data.len()
            {
                return Ok(Self::BtlAiScript {
                    script: Amx::load_compiled(&data[..length])?,
                    other: data[length..].to_vec(),
                });
            }
            return Err(Error::msg(format!("unknown AMX-based file type: {:?}", &data[..data.len().min(10)])));
        }

        match data.get(..2) {
            Some([0x5a, 0x53] | [0x5a, 0x49] | [0x5a, 0x4f]) => load_map_file(data),
            _ => Err(Error::msg(format!("unknown file type: {:?}", &data[..data.len().min(10)]))),
        }
    }

    pub fn assemble_xamx(text: &str) -> Result<Self> {
        let lines = text.lines().map(ToString::to_string).collect::<Vec<_>>();
        let first = lines
            .first()
            .ok_or_else(|| Error::msg("empty text file"))?
            .split_whitespace()
            .collect::<Vec<_>>();
        if first.len() < 3 || first[0] != "File" || first[1] != "type:" {
            return Err(Error::msg("need to specify file type"));
        }
        match first[2] {
            "RawScript" => Ok(Self::RawScript(Amx::assemble_xamx(&lines[1..])?)),
            "BtlAiScript" => assemble_btl_ai(&lines),
            "MapFile" => assemble_map_file(&lines),
            other => Err(Error::msg(format!("unknown file type: {other}"))),
        }
    }

    pub fn dump(&self) -> Result<Vec<u8>> {
        match self {
            Self::RawScript(script) => script.dump(),
            Self::BtlAiScript { script, other } => {
                let mut out = script.dump()?;
                out.extend_from_slice(other);
                Ok(out)
            }
            Self::MapFile {
                abbreviation,
                alignment,
                parts,
            } => dump_map_file(*abbreviation, *alignment, parts, false),
        }
    }

    pub fn disassemble(&self) -> Result<String> {
        match self {
            Self::RawScript(script) => Ok(format!("File type: RawScript\n{}", script.disassemble()?)),
            Self::BtlAiScript { script, other } => {
                let mut out = vec!["File type: BtlAiScript".to_string(), script.disassemble()?];
                out.push(String::new());
                out.push(String::new());
                out.push("Other script:".to_string());
                out.extend(print_bytes_block(other, 4));
                Ok(out.join("\n"))
            }
            Self::MapFile {
                abbreviation,
                alignment,
                parts,
            } => {
                let mut out = vec![
                    "File type: MapFile".to_string(),
                    format!("Abbreviation: {}", String::from_utf8_lossy(abbreviation)),
                    format!("Alignment: {alignment}"),
                ];
                for part in parts {
                    match part {
                        MapPart::Amx(amx) => {
                            out.push(String::new());
                            out.push("--- AMX".to_string());
                            out.push(String::new());
                            out.push(amx.disassemble()?);
                        }
                        MapPart::Mixed(mixed) => {
                            out.push(String::new());
                            out.push("--- MixedAMX".to_string());
                            out.push(String::new());
                            out.push("Extra:".to_string());
                            out.extend(print_bytes_block(&mixed.data, 4));
                            out.push("End extra".to_string());
                            out.push(String::new());
                            out.push(mixed.script.disassemble()?);
                        }
                        MapPart::Raw(raw) => {
                            out.push(String::new());
                            out.push("--- Raw".to_string());
                            out.push(String::new());
                            out.extend(print_bytes_block(raw, 0));
                        }
                    }
                }
                Ok(out.join("\n"))
            }
        }
    }
}

fn load_map_file(data: &[u8]) -> Result<XamxFile> {
    let abbreviation = data
        .get(..2)
        .ok_or_else(|| Error::msg("map file header too short"))?
        .try_into()
        .map_err(|_| Error::msg("invalid map file abbreviation"))?;
    let parts_count = u16::from_le_bytes([data[2], data[3]]) as usize;
    let alignment = if data[4] == 0x80 { 0x80 } else { 4 };
    let mut parts = Vec::new();

    for p_num in 0..parts_count {
        let start = read_u32_le(data, p_num * 4 + 4)? as usize;
        let end = read_u32_le(data, p_num * 4 + 8)? as usize;
        if p_num == 1 && abbreviation == *b"ZO" {
            let offset = read_u32_le(data, start)? as usize;
            let script_len = read_u32_le(data, start + 4 + offset)? as usize;
            parts.push(MapPart::Mixed(MixedAmx {
                data: data[start + 4..start + 4 + offset].to_vec(),
                script: Amx::load_compiled(&data[start + 4 + offset..start + 4 + offset + script_len])?,
            }));
        } else if data.get(start + 4..start + 8) == Some(&AMX_MAGIC_32) {
            let script_len = read_u32_le(data, start)? as usize;
            parts.push(MapPart::Amx(Amx::load_compiled(&data[start..start + script_len])?));
        } else {
            parts.push(MapPart::Raw(data[start..end].to_vec()));
        }
    }

    Ok(XamxFile::MapFile {
        abbreviation,
        alignment,
        parts,
    })
}

fn assemble_btl_ai(lines: &[String]) -> Result<XamxFile> {
    let mut split_index = None;
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "Other script:" {
            split_index = Some(i);
            break;
        }
    }
    let split_index = split_index.ok_or_else(|| Error::msg("BtlAiScript is missing 'Other script:'"))?;
    let script = Amx::assemble_xamx(&lines[1..split_index])?;
    let other = read_bytes_block(&lines[split_index + 1..])?;
    Ok(XamxFile::BtlAiScript { script, other })
}

fn assemble_map_file(lines: &[String]) -> Result<XamxFile> {
    let mut abbreviation = None;
    let mut alignment = None;
    let mut separators = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let split = line.split_whitespace().collect::<Vec<_>>();
        if split.first() == Some(&"---") && split.len() > 1 {
            separators.push(i);
        } else if split.first() == Some(&"Abbreviation:") {
            abbreviation = Some(
                split
                    .get(1)
                    .ok_or_else(|| Error::msg("missing map abbreviation"))?
                    .as_bytes()
                    .try_into()
                    .map_err(|_| Error::msg("map abbreviation must be two bytes"))?,
            );
        } else if split.first() == Some(&"Alignment:") {
            alignment = Some(
                split
                    .get(1)
                    .ok_or_else(|| Error::msg("missing map alignment"))?
                    .parse::<usize>()
                    .map_err(|_| Error::msg("invalid map alignment"))?,
            );
        }
    }
    let abbreviation = abbreviation.ok_or_else(|| Error::msg("MapFile disassembly requires an abbreviation"))?;
    let alignment = alignment.ok_or_else(|| Error::msg("MapFile disassembly requires an alignment"))?;

    let mut parts = Vec::new();
    for (i, start) in separators.iter().enumerate() {
        let end = separators.get(i + 1).copied().unwrap_or(lines.len());
        let split = lines[*start].split_whitespace().collect::<Vec<_>>();
        match split.get(1).copied() {
            Some("AMX") => parts.push(MapPart::Amx(Amx::assemble_xamx(&lines[*start + 1..end])?)),
            Some("MixedAMX") => {
                let extra = lines[*start + 1..end]
                    .iter()
                    .position(|line| line.trim() == "Extra:")
                    .ok_or_else(|| Error::msg("MixedAMX section is missing 'Extra:'"))?
                    + *start
                    + 1;
                let end_extra = lines[extra + 1..end]
                    .iter()
                    .position(|line| line.trim() == "End extra")
                    .ok_or_else(|| Error::msg("MixedAMX section is missing 'End extra'"))?
                    + extra
                    + 1;
                parts.push(MapPart::Mixed(MixedAmx {
                    data: read_bytes_block(&lines[extra + 1..end_extra])?,
                    script: Amx::assemble_xamx(&lines[end_extra + 1..end])?,
                }));
            }
            Some("Raw") => parts.push(MapPart::Raw(read_bytes_block(&lines[*start + 1..end])?)),
            Some(other) => return Err(Error::msg(format!("unknown map section '{other}'"))),
            None => return Err(Error::msg("malformed map section header")),
        }
    }

    Ok(XamxFile::MapFile {
        abbreviation,
        alignment,
        parts,
    })
}

fn dump_map_file(abbreviation: [u8; 2], alignment: usize, parts: &[MapPart], debug_dump: bool) -> Result<Vec<u8>> {
    let mut out_parts = Vec::new();
    for part in parts {
        match part {
            MapPart::Amx(amx) => out_parts.push(amx.dump()?),
            MapPart::Mixed(mixed) => {
                let payload = mixed.script.dump()?;
                let mut out = Vec::new();
                write_u32_le((mixed.data.len() + if debug_dump { 4 } else { 0 }) as u32, &mut out);
                out.extend_from_slice(&mixed.data);
                out.extend_from_slice(&payload);
                out_parts.push(out);
            }
            MapPart::Raw(raw) => out_parts.push(raw.clone()),
        }
    }

    let mut head = vec![0u8; out_parts.len() * 4 + 8];
    if !head.len().is_multiple_of(alignment) {
        head.resize(head.len() + (alignment - (head.len() % alignment)), 0);
    }
    head[0..2].copy_from_slice(&abbreviation);
    head[2..4].copy_from_slice(&(out_parts.len() as u16).to_le_bytes());
    for (i, part) in out_parts.iter().enumerate() {
        let current_len = head.len() as u32;
        head[i * 4 + 4..i * 4 + 8].copy_from_slice(&current_len.to_le_bytes());
        head.extend_from_slice(part);
        if !head.len().is_multiple_of(alignment) {
            head.resize(head.len() + (alignment - (head.len() % alignment)), 0);
        }
    }
    let tail = out_parts.len() * 4 + 4;
    let final_len = head.len() as u32;
    head[tail..tail + 4].copy_from_slice(&final_len.to_le_bytes());
    if !head.len().is_multiple_of(alignment) {
        head.resize(head.len() + (alignment - (head.len() % alignment)), 0);
    }
    Ok(head)
}
