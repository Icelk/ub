#![warn(missing_debug_implementations, missing_docs)]
#![allow(dead_code)]

//! This is a lib and binary crate to bundle files to a single one, like zipping it without compression.
//! Can bundle folders and open bundles.

/// The magic number associated with bundles. Used to offset all reading and when writing.
const MAGIC_NUMBER: &[u8] = b"";

/// Parsing module, including all versions and supporting structs and enums.
pub mod parse {
    use std::{mem, ptr};

    use crate::MAGIC_NUMBER;

    /// Representation of a file in the header of the bundle. Contains info about the real file, such as path, name, and size.
    #[derive(Debug, PartialEq, Eq)]
    pub struct File {
        // Not in file, but calculated when reading for convenience; it's just a constant offset.
        path_start: u64,
        path_length: u64,
        // Not in file, calculated after reading once, since it's relatively expensive.
        file_start: u64,
        file_size: u64,
    }

    /// A parsed bundle, containing all the extracted information.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Parsed<'a> {
        files: Vec<File>,
        data: &'a [u8],
        header_size: u64,
        /// Not necessary used for something, but might as well be here.
        file_name_length: u8,
        version: u32,
    }

    /// Supporting error struct for [`parse`] and the `v_` parsing methods. Contains all parsing related errors.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum ParseError {
        /// The version is not supported by the `parse` function.
        VersionNotSupported,
        /// Signals some metadata is missing or incomplete. This is often the case when the file is smaller than the base meta size.
        MetadataIncomplete,
        /// Metadata is in some way out of boundaries, such as the file path length size being above 8.
        MetadataWrong,
    }

    /// General parse function. Will recognise version and call the appropriate function.
    ///
    /// # Errors
    /// If a function is not supported, it will return a `ParseError::VersionNotSupported`.
    /// All errors are inherited from the related `v_` functions. Check [`ParseError`] for possible values.
    pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
        let content_start = MAGIC_NUMBER.len() + 4;
        // Version type is constant; you can't change versioning formatting.
        let version = if bytes.len() < content_start {
            return Err(ParseError::MetadataIncomplete);
        } else {
            let mut value = [0; 4];
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(MAGIC_NUMBER.len()),
                    value.as_mut_ptr(),
                    4,
                )
            };
            u32::from_be_bytes(value)
        };
        match version {
            1 => v1(&bytes[content_start..]),
            _ => Err(ParseError::VersionNotSupported),
        }
    }

    /// Version 1 parser
    pub fn v1(bytes: &[u8]) -> Result<Parsed, ParseError> {
        if bytes.len() < 9 {
            return Err(ParseError::MetadataIncomplete);
        }

        // Header size is a u64 to include all
        let mut header_size = [0u8; 8];
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), header_size.as_mut_ptr(), 8) };
        let header_size = u64::from_be_bytes(header_size);

        let file_name_length = bytes[8];
        let file_name_length_bytes = file_name_length as usize;

        Ok(Parsed {
            version: 1,
            header_size,
            file_name_length,
            files: Vec::new(),
            data: bytes,
        })
    }

    /// An error for parsing unsigned integers from bytes of unknown lengths.
    #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
    pub enum ParseUintError {
        /// Size is too large to handle.
        SizeToLarge,
    }

    // If needed in the future, we can bump this to u128 (if file names are longer than what a u64 can contain. Very probable...)
    /// The type returned by [`parse_uint`]. Here to make the change easier if we need to in the future.
    pub type UintParseType = u64;

    /// Parse a uint of unknown size from bytes. Will currently return a u64.
    pub fn parse_uint(bytes: &[u8], length: usize) -> Result<UintParseType, ParseUintError> {
        const MAX_BYTES: usize = mem::size_of::<UintParseType>();
        if length >= MAX_BYTES {
            return Err(ParseUintError::SizeToLarge);
        }

        let mut array = [0u8; MAX_BYTES];
        let offset = MAX_BYTES - length;

        for byte in 0..length {
            array[byte + offset] = bytes[byte];
        }

        Ok(u64::from_be_bytes(array))
    }
}

// pub mod utility {
//     use std::{mem, ptr};

//     pub trait IntegerFromBeBytes {
//         const fn from_be_bytes (bytes: [u8; mem::size_of::<Self>()])-> Self;
//     }

//     pub const fn bytes_to_uint<I>(bytes: &[u8]) -> I {
//         const SIZE: usize = mem::size_of::<I>();
//         assert!(bytes.len() >= SIZE);
//         let mut value = [0u8; SIZE];
//         unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), value.as_mut_ptr(), SIZE) };
//         I::from_be_bytes(value)
//     }
// }

#[cfg(test)]
mod tests {
    use crate::parse;

    #[test]
    fn parse_uint() {
        // Are bytes 0, 0, 1, 5
        let bytes = b"\x00\x00\x01\x05";
        let int = parse::parse_uint(bytes, 4).expect("failed to parse bytes");
        assert_eq!(int, 261);

        // Are bytes 0, 11
        // Will only take the two first bytes in consideration!
        let bytes = b"\x00\x0b\xaf\xde";
        let int = parse::parse_uint(bytes, 2).expect("failed to parse bytes");
        assert_eq!(int, 11);
    }

    #[test]
    fn parse() {
        // First four bytes are version, 1, then comes the header startm 5F = 95. Then the size of path length
        let bytes = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x5F\x01";
        parse::parse(bytes).unwrap();
    }
}
