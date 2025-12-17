//! Windows PE Parser Library
//!
//! A Rust library for parsing Windows PE (Portable Executable) files.
//!
//! # Example
//!
//! ```no_run
//! use winpe::parse;
//! use std::fs;
//!
//! let data = fs::read("library.dll").expect("Could not read file");
//! let pe = parse(data);
//!
//! println!("Architecture: {}", if pe.is_x64() { "x64" } else { "x86" });
//! println!("Exported functions: {}", pe.get_export_table().array_of_names.len());
//! ```

pub mod constants;
pub mod parser;
pub mod types;

pub use parser::parse;
pub use types::{ExportTable, PE};
