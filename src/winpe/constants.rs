//! PE header constants

/// Magic number for x64 PE files
pub const PE_MAGIC_X64: u16 = 0x20b;

/// Magic number for x86 PE files
pub const PE_MAGIC_X86: u16 = 0x10b;

/// Offset to magic number in NT headers
pub const PE_MAGIC_OFFSET: usize = 0x18;
