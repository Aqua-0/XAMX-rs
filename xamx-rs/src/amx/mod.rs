use crate::common::error::{Error, Result};
use crate::common::util::{
    compress_bytes, decompress_bytes, read_i32_le, read_u16_le, read_u32_le, write_i32_le, write_u16_le,
    write_u32_le,
};
use crate::meta::opcode_by_id;
use crate::textfmt::{assemble_text, disassemble};

pub const AMX_MAGIC_32: [u8; 4] = [0xe0, 0xf1, 0x0a, 0x0a];
pub const AMX_MAGIC_64: [u8; 4] = [0xe1, 0xf1, 0x0a, 0x0a];
pub const AMX_MAGIC_BTLAI: [u8; 4] = [0xef, 0xf1, 0x0a, 0x0a];

#[derive(Clone, Debug, Default)]
pub struct Amx {
    pub code_section: Vec<Vec<u8>>,
    pub data_section: Vec<u8>,
    pub allocated_memory: u32,
    pub main_address: i32,
    pub cell_size: u16,
    pub def_size: u16,
    pub flags: u16,
    pub public_functions: Vec<(u32, u32)>,
    pub native_functions: Vec<(u32, u32)>,
    pub libraries: Vec<(u32, u32)>,
    pub public_variables: Vec<(u32, u32)>,
    pub public_tags: Vec<(u32, u32)>,
    pub overlays: Vec<u8>,
    pub symbol_names: Vec<u8>,
}

impl Amx {
    pub fn load_compiled(data: &[u8]) -> Result<Self> {
        let length = read_u32_le(data, 0)? as usize;
        let magic = data.get(4..8).ok_or_else(|| Error::msg("AMX header too short"))?;
        let cell_size = if magic == AMX_MAGIC_32 {
            4
        } else if magic == AMX_MAGIC_64 {
            8
        } else {
            return Err(Error::msg("unsupported AMX magic"));
        };

        let def_size = read_u16_le(data, 10)?;
        let flags = read_u16_le(data, 8)?;
        let code_section_start = read_u32_le(data, 12)? as usize;
        let data_section_start = read_u32_le(data, 16)? as usize;
        let heap_start = read_u32_le(data, 20)? as usize;
        let allocated_memory = read_u32_le(data, 24)?;
        let main_address = read_i32_le(data, 28)?;
        let public_functions_start = read_u32_le(data, 32)? as usize;
        let native_functions_start = read_u32_le(data, 36)? as usize;
        let libraries_start = read_u32_le(data, 40)? as usize;
        let public_variables_start = read_u32_le(data, 44)? as usize;
        let public_tags_start = read_u32_le(data, 48)? as usize;
        let overlays_start = read_u32_le(data, 52)? as usize;
        let symbol_names_start = read_u32_le(data, 56)? as usize;

        let header_data = data
            .get(..code_section_start)
            .ok_or_else(|| Error::msg("invalid code section offset"))?;
        let compressed = data
            .get(code_section_start..length)
            .ok_or_else(|| Error::msg("invalid AMX compressed payload length"))?;
        let decompressed = decompress_bytes(compressed, heap_start.saturating_sub(code_section_start))?;
        let code_bytes = decompressed
            .get(..data_section_start.saturating_sub(code_section_start))
            .ok_or_else(|| Error::msg("invalid data section offset"))?;
        let data_section = decompressed
            .get(data_section_start.saturating_sub(code_section_start)..)
            .ok_or_else(|| Error::msg("invalid heap start"))?
            .to_vec();

        let symbol_end = header_data
            .windows(4)
            .rposition(|window| window == [0x3f, 0, 0, 0])
            .unwrap_or(header_data.len());

        Ok(Self {
            code_section: decode_cells(code_bytes)?,
            data_section,
            allocated_memory,
            main_address,
            cell_size,
            def_size,
            flags,
            public_functions: read_table_pairs(header_data, public_functions_start, native_functions_start, def_size)?,
            native_functions: read_indexed_table(header_data, native_functions_start, libraries_start, def_size)?,
            libraries: read_indexed_table(header_data, libraries_start, public_variables_start, def_size)?,
            public_variables: read_table_pairs(header_data, public_variables_start, public_tags_start, def_size)?,
            public_tags: read_table_pairs(header_data, public_tags_start, overlays_start, def_size)?,
            overlays: header_data
                .get(overlays_start..symbol_names_start)
                .ok_or_else(|| Error::msg("invalid overlays offset"))?
                .to_vec(),
            symbol_names: header_data
                .get(symbol_names_start..symbol_end)
                .ok_or_else(|| Error::msg("invalid symbol names offset"))?
                .to_vec(),
        })
    }

    pub fn assemble_xamx(lines: &[String]) -> Result<Self> {
        assemble_text(lines)
    }

    pub fn disassemble(&self) -> Result<String> {
        disassemble(self)
    }

    pub fn dump(&self) -> Result<Vec<u8>> {
        if self.cell_size != 4 {
            return Err(Error::msg("writing only supports 32-bit AMX"));
        }
        let mut data = Vec::new();
        self.assemble_header(&mut data)?;
        let code = self.code_section.iter().flat_map(|cell| cell.iter().copied()).collect::<Vec<_>>();
        let payload = [code, self.data_section.clone()].concat();
        data.extend_from_slice(&compress_bytes(&payload)?);
        let total_len = data.len() as u32;
        data[0..4].copy_from_slice(&total_len.to_le_bytes());
        Ok(data)
    }

    fn assemble_header(&self, data: &mut Vec<u8>) -> Result<()> {
        write_u32_le(0, data);
        data.extend_from_slice(&AMX_MAGIC_32);
        write_u16_le(self.flags, data);
        write_u16_le(8, data);
        write_u32_le(0, data);
        write_u32_le(0, data);
        write_u32_le(0, data);
        write_u32_le(self.allocated_memory, data);
        write_i32_le(self.main_address, data);
        self.write_tables(data)?;
        let sum_code = self.code_section.iter().map(Vec::len).sum::<usize>();
        let data_len = data.len() as u32;
        let data_and_code_len = (data.len() + sum_code) as u32;
        let decompressed_len = (data.len() + sum_code + self.data_section.len()) as u32;
        data[12..16].copy_from_slice(&data_len.to_le_bytes());
        data[16..20].copy_from_slice(&data_and_code_len.to_le_bytes());
        data[20..24].copy_from_slice(&decompressed_len.to_le_bytes());
        Ok(())
    }

    fn write_tables(&self, data: &mut Vec<u8>) -> Result<()> {
        data.resize(data.len() + 28, 0);
        let section_start = data.len() as u32;
        data[0x20..0x24].copy_from_slice(&section_start.to_le_bytes());

        for (address, name) in &self.public_functions {
            write_u32_le(*address, data);
            write_u32_le(*name, data);
        }
        let after_public_functions = data.len() as u32;
        data[0x24..0x28].copy_from_slice(&after_public_functions.to_le_bytes());

        write_indexed_table(data, &self.native_functions)?;
        let after_native_functions = data.len() as u32;
        data[0x28..0x2c].copy_from_slice(&after_native_functions.to_le_bytes());

        write_indexed_table(data, &self.libraries)?;
        let after_libraries = data.len() as u32;
        data[0x2c..0x30].copy_from_slice(&after_libraries.to_le_bytes());

        for (address, name) in &self.public_variables {
            write_u32_le(*address, data);
            write_u32_le(*name, data);
        }
        let after_public_variables = data.len() as u32;
        data[0x30..0x34].copy_from_slice(&after_public_variables.to_le_bytes());

        for (address, name) in &self.public_tags {
            write_u32_le(*address, data);
            write_u32_le(*name, data);
        }
        let after_public_tags = data.len() as u32;
        data[0x34..0x38].copy_from_slice(&after_public_tags.to_le_bytes());

        data.extend_from_slice(&self.overlays);
        let after_overlays = data.len() as u32;
        data[0x38..0x3c].copy_from_slice(&after_overlays.to_le_bytes());
        data.extend_from_slice(&self.symbol_names);
        data.extend_from_slice(&[0x3f, 0, 0, 0]);
        Ok(())
    }
}

fn read_table_pairs(data: &[u8], start: usize, end: usize, def_size: u16) -> Result<Vec<(u32, u32)>> {
    let mut out = Vec::new();
    let step = usize::from(def_size);
    if step == 0 {
        return Err(Error::msg("definition size cannot be zero"));
    }
    for i in (start..end).step_by(step) {
        out.push((read_u32_le(data, i)?, read_u32_le(data, i + 4)?));
    }
    Ok(out)
}

fn read_indexed_table(data: &[u8], start: usize, end: usize, def_size: u16) -> Result<Vec<(u32, u32)>> {
    let mut out = Vec::new();
    let step = usize::from(def_size);
    if step == 0 {
        return Err(Error::msg("definition size cannot be zero"));
    }
    for i in (start..end).step_by(step) {
        out.push((((i - start) / step) as u32, read_u32_le(data, i + 4)?));
    }
    Ok(out)
}

fn write_indexed_table(data: &mut Vec<u8>, values: &[(u32, u32)]) -> Result<()> {
    let max_index = values.iter().map(|(index, _)| *index as usize).max().unwrap_or(0);
    let mut ordered = vec![0u32; if values.is_empty() { 0 } else { max_index + 1 }];
    for (index, name) in values {
        let slot = ordered
            .get_mut(*index as usize)
            .ok_or_else(|| Error::msg("indexed table contained an invalid index"))?;
        *slot = *name;
    }
    for name in ordered {
        write_u32_le(0, data);
        write_u32_le(name, data);
    }
    Ok(())
}

pub fn decode_cells(code: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut cells = Vec::new();
    let mut pos = 0usize;
    while pos < code.len() {
        if pos + 4 > code.len() {
            return Err(Error::msg("code section ended in the middle of an instruction"));
        }
        let opcode = read_u16_le(code, pos)?;
        let size = if opcode == 0x82 {
            let case_count = read_u32_le(code, pos + 4)? as usize;
            (case_count + 1) * 8 + 4
        } else if opcode == 0x87 {
            12
        } else if let Some(def) = opcode_by_id(opcode) {
            (def.params.len() + 1) * 4
        } else {
            4
        };
        let slice = code
            .get(pos..pos + size)
            .ok_or_else(|| Error::msg(format!("opcode at {pos:#x} overflowed the code section")))?;
        cells.push(slice.to_vec());
        pos += size;
    }
    Ok(cells)
}
