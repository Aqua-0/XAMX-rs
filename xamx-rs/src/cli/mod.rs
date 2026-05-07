use std::fs;
use std::path::{Path, PathBuf};

use crate::common::error::{Error, Result};
use crate::formats::XamxFile;

pub fn run(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() {
        return Err(Error::msg("usage: xamx-rs <file-or-.xamx> [...]"));
    }
    for path in paths {
        process_path(path)?;
    }
    Ok(())
}

fn process_path(path: &Path) -> Result<()> {
    let bytes = fs::read(path)?;
    let output = if bytes.starts_with(b"File type:") {
        let text = String::from_utf8(bytes).map_err(|_| Error::msg("text file is not valid UTF-8"))?;
        let file = XamxFile::assemble_xamx(&text)?;
        Output::Binary(file.dump()?)
    } else {
        let file = XamxFile::load_compiled(&bytes)?;
        Output::Text(file.disassemble()?)
    };

    let destination = match output {
        Output::Text(_) => PathBuf::from(format!("{}.xamx", path.display())),
        Output::Binary(_) => {
            if path.extension().and_then(|ext| ext.to_str()) == Some("xamx") {
                path.with_extension("")
            } else {
                path.to_path_buf()
            }
        }
    };

    match output {
        Output::Text(text) => fs::write(destination, text)?,
        Output::Binary(binary) => fs::write(destination, binary)?,
    }
    Ok(())
}

enum Output {
    Text(String),
    Binary(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use crate::formats::XamxFile;

    #[test]
    fn sample_map_text_roundtrip() {
        let text = include_str!("../../data/examples/xy_map_script_13.xamx");
        let file = XamxFile::assemble_xamx(text).expect("assemble sample");
        let binary = file.dump().expect("dump sample");
        let reparsed = XamxFile::load_compiled(&binary).expect("reparse dumped sample");
        let text2 = reparsed.disassemble().expect("disassemble dumped sample");
        let rebuilt = XamxFile::assemble_xamx(&text2).expect("rebuild disassembly");
        let binary2 = rebuilt.dump().expect("dump rebuilt sample");
        assert_eq!(binary, binary2);
    }
}
