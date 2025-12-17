# winpe

A lightweight Rust library for parsing Windows PE (Portable Executable) files.

## Quick Start

```rust
use winpe::parse;
use std::fs;

let data = fs::read("library.dll")?;
let pe = parse(data);

println!("Architecture: {}", if pe.is_x64() { "x64" } else { "x86" });

let exports = pe.get_export_table();
for (name, ordinal) in exports.array_of_names.iter().zip(exports.array_of_ordinals.iter()) {
    println!("  {} (ordinal {})", name, ordinal);
}
```

## Module Structure

- `constants.rs` - PE header constants (magic numbers, offsets)
- `types.rs` - Core data structures (PE, ExportTable, ExportTableData)
- `parser.rs` - PE binary parsing logic

## API

### Main Types

- `parse(data: Vec<u8>) -> PE` - Parse PE binary data
- `PE` - Represents a parsed PE file
  - `is_x64()` - Check architecture
  - `get_export_table()` - Access export table
- `ExportTable` - Export information
  - `array_of_names` - Exported function names
  - `array_of_ordinals` - Export ordinals

