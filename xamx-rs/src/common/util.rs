use crate::common::error::{Error, Result};

pub fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| Error::msg(format!("expected u16 at offset {offset:#x}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::msg(format!("expected u32 at offset {offset:#x}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn read_i32_le(data: &[u8], offset: usize) -> Result<i32> {
    Ok(read_u32_le(data, offset)? as i32)
}

pub fn write_u16_le(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u32_le(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn write_i32_le(value: i32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn hash_name(name: &str) -> u32 {
    let mut hash = 0u32;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(131) ^ u32::from(byte);
    }
    hash
}

pub fn vm_param_str(value: u64, size: usize) -> String {
    if (0x8000..0x8100).contains(&value) || (0x4000..=0x4200).contains(&value) {
        format!("{value:#x}")
    } else if size == 2 && (value & 0x8000) != 0 {
        ((value as i16) as i32).to_string()
    } else if size == 4 && (value & 0x8000_0000) != 0 {
        (value as i32).to_string()
    } else if size == 8 && (value & 0x8000_0000_0000_0000) != 0 {
        (value as i64).to_string()
    } else {
        value.to_string()
    }
}

pub fn print_bytes_block(data: &[u8], indent: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for i in (0..data.len()).step_by(16) {
        if i % 0x80 == 0 {
            lines.push(format!("{:indent$}// {i:#x}", "", indent = indent));
        }
        let line = &data[i..data.len().min(i + 16)];
        let parts = line
            .chunks(4)
            .map(|chunk| chunk.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join("   ");
        lines.push(format!("{:indent$}{parts}", "", indent = indent));
    }
    lines
}

pub fn read_bytes_block(lines: &[String]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for line in lines {
        for part in line.split_whitespace() {
            if part.starts_with("//") {
                break;
            }
            if part.len() > 2 {
                return Err(Error::msg("raw byte blocks have to be written in single bytes"));
            }
            out.push(u8::from_str_radix(part, 16).map_err(|_| Error::msg(format!("invalid byte {part}")))?);
        }
    }
    Ok(out)
}

pub fn decompress_bytes(data: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut code = vec![0u8; length];
    let (mut i, mut j, mut x, mut f) = (0usize, 0usize, 0i32, 0usize);
    while i < code.len() {
        let b = *data
            .get(f)
            .ok_or_else(|| Error::msg("compressed AMX payload ended early"))?;
        f += 1;
        let v = i32::from(b & 0x7f);
        j += 1;
        if j == 1 {
            x = ((((if (v >> 6) == 0 { 1 } else { 0 }) - 1) << 6) | v) as i32;
        } else {
            x = (x << 7) | (v & 0xff);
        }
        if (b & 0x80) != 0 {
            continue;
        }
        code[i..i + 4].copy_from_slice(&x.to_le_bytes());
        i += 4;
        j = 0;
    }
    Ok(code)
}

pub fn compress_bytes(data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(4) {
        return Err(Error::msg("AMX payload length must be divisible by 4"));
    }

    let mut pointer = 0usize;
    let mut out = Vec::new();
    while pointer < data.len() {
        let mut instruction = u32::from_le_bytes(
            data[pointer..pointer + 4]
                .try_into()
                .map_err(|_| Error::msg("invalid cell boundary"))?,
        );
        let sign = (instruction & 0x8000_0000) != 0;
        let mut shadow = if sign { instruction ^ 0xffff_ffff } else { instruction };
        let mut bytes = Vec::new();

        loop {
            let mut byte_val = (instruction & 0x7f) as u8;
            if !bytes.is_empty() {
                byte_val |= 0x80;
            }
            bytes.push(byte_val);
            instruction >>= 7;
            shadow >>= 7;
            if shadow == 0 {
                break;
            }
        }

        if bytes.len() < 5 {
            let sign_bit = if sign { 0x40 } else { 0 };
            if (bytes[bytes.len() - 1] & 0x40) != sign_bit {
                bytes.push(if sign { 0xff } else { 0x80 });
            }
        }

        bytes.reverse();
        out.extend_from_slice(&bytes);
        pointer += 4;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{compress_bytes, decompress_bytes};

    #[test]
    fn codec_roundtrip() {
        let words: [i32; 12] = [0, 1, -1, 4, -4, 255, -255, 0x7fff, -0x8000, 0x12345678, i32::MIN, i32::MAX];
        let mut bytes = Vec::new();
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let compressed = compress_bytes(&bytes).expect("compress");
        let decompressed = decompress_bytes(&compressed, bytes.len()).expect("decompress");
        assert_eq!(bytes, decompressed);
    }
}
