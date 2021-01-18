#![warn(missing_debug_implementations, missing_docs)]
#![allow(unused_labels)]
#![warn(clippy::pedantic, clippy::cargo)]

//! This is a lib and binary crate to bundle files to a single one, like zipping it without compression.
//! Can bundle folders and open bundles.

/// The magic number associated with bundles. Used to offset all reading and when writing.
const MAGIC_NUMBER: &[u8] = b"";

/// Parsing module, including all versions and supporting structs and enums.
pub mod parse {
    use std::{convert::TryFrom, mem, path::Path, ptr};

    /// Enum for errors dealing with [`File`].
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum FileError {
        /// The path contains invalid UTF8, and can't be converted to a path.
        InvalidUTF8,
    }
    /// Representation of a file in the header of the bundle. Contains info about the real file, such as path, name, and size.
    #[derive(Debug, PartialEq, Eq)]
    pub struct File {
        // Not in file, but calculated when reading for convenience.
        path_start: usize,
        path_length: usize,
        // Not in file, calculated after reading once, since it's relatively expensive.
        file_start: u64,
        file_size: u64,

        // Used to loop trough all files, so one can get the offset to apply.
        meta_length: usize,
    }
    impl File {
        /// Takes [`Data`] with a start where file metadata starts.
        ///
        /// # Errors
        /// Will fail if path is not valid UTF8. `ToDo`: Remove this limitation
        /// Might be because the path length (defined in the file) is wrong, so it reads too far.
        #[must_use]
        pub fn get_path<'a>(&self, data: &'a Data) -> Result<&'a Path, FileError> {
            let slice = &data.data()[self.path_start..self.path_start + self.path_length];
            match std::str::from_utf8(slice) {
                Ok(path) => Ok(Path::new(path)),
                Err(..) => Err(FileError::InvalidUTF8),
            }
        }
    }
    /// A [`File`] with a [`Data`] attached, to make some methods less verbose.
    /// [`Data`] should start after path bytes byte.
    #[derive(Debug, PartialEq, Eq)]
    pub struct FatFile<'a>(&'a File, Data<'a>);
    impl<'a> FatFile<'a> {
        /// Extracts the path from [`FatFile`]
        ///
        /// # Errors
        /// Will fail if path is not valid UTF8. `ToDo`: Remove this limitation
        /// Might be because the path length (defined in the file) is wrong, so it reads too far.
        #[must_use]
        pub fn get_path(&'a self) -> Result<&'a Path, FileError> {
            self.0.get_path(&self.1)
        }
    }

    /// A parsed bundle, containing all the extracted information.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Parsed<'a> {
        pub(crate) files: Vec<File>,
        data: Data<'a>,
        header_size: u64,
        /// Not necessary used for something, but might as well be here.
        path_length: u8,
        version: u32,
    }
    impl<'a> Parsed<'a> {
        /// Makes a file fat; straps self's [`data`] on to it.
        #[must_use]
        pub fn fatten_file(&self, file: &'a File) -> FatFile {
            // 9 since we discard header size (8 bytes) and path bytes length byte (1 byte).
            FatFile(&file, self.data.new_from(9))
        }
    }

    /// Representing the data (usually from a file) to make it easier to get the correct data, in the right place.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Data<'a> {
        /// Raw data to read
        raw: &'a [u8],
        /// Start of raw data, after version and magic number
        start: usize,
    }
    impl<'a> Data<'a> {
        /// Makes a new data object.
        ///
        /// # Panics
        /// Will panic if `start` is greater than the length of `bytes`.
        #[must_use]
        pub fn new(bytes: &'a [u8], start: usize) -> Self {
            assert!(bytes.len() > start);
            Self { raw: bytes, start }
        }

        /// Creates a new [`Data`] from the current with a offset, to only expose file metadata and beyond to file-metadata-related functions.
        #[must_use]
        pub fn new_from(&self, offset: usize) -> Self {
            assert!(self.data_len() >= offset);
            Self {
                raw: self.raw,
                start: self.start + offset,
            }
        }

        /// Gets the whole data, including magic number and version bytes.
        #[must_use]
        pub fn whole(&self) -> &[u8] {
            self.raw
        }
        /// Gets data from the offset.
        /// Offset is calculated from the point the data begins.
        #[must_use]
        pub fn from_offset(&self, offset: usize) -> &[u8] {
            &self.raw[self.start + offset..]
        }
        /// Gets the relevant data, without the magic number or version.
        #[must_use]
        pub fn data(&self) -> &[u8] {
            &self.raw[self.start..]
        }
        /// Gets the length of the data. More efficient than `self.data().len()`.
        #[must_use]
        pub fn data_len(&self) -> usize {
            self.raw.len() - self.start
        }
    }

    /// Supporting error struct for [`parse()`] and the [`versions`] functions. Contains all parsing related errors.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Error {
        /// The version is not supported by the [`parse()`] function.
        VersionNotSupported,
        /// Signals some metadata is missing or incomplete. This is often the case when the file is smaller than the base meta size.
        MetadataIncomplete,
        /// Metadata is in some way out of boundaries, such as the file path length size being above 8.
        MetadataWrong,
        /// Path takes more memory than can be pointed to.
        PathLengthTooLong,
        /// If the metadata for the file is incomplete, usually from outside manipulation (gone wrong). Occurs when more data is expected.
        FileMetadataIncomplete,
    }

    /// General parse function. Will recognise version and call the appropriate function.
    ///
    /// # Errors
    /// If a version is not supported, it will return a [`ParseError::VersionNotSupported`].
    /// All other errors are inherited from the related [`versions`] functions. Check [`ParseError`] for possible values.
    pub fn parse(bytes: &[u8]) -> Result<Parsed, Error> {
        let content_start = crate::MAGIC_NUMBER.len() + 4;
        // Version type is constant; you can't change versioning formatting.
        let version = if bytes.len() < content_start {
            return Err(Error::MetadataIncomplete);
        } else {
            let mut value = [0; 4];
            // Save because of the size of ↑ and the check before; both buffers must be >= 4, and we are copying integers from lists.
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(crate::MAGIC_NUMBER.len()),
                    value.as_mut_ptr(),
                    4,
                )
            };
            u32::from_be_bytes(value)
        };
        match version {
            1 => versions::v1::parse(Data::new(bytes, content_start)),
            _ => Err(Error::VersionNotSupported),
        }
    }

    /// Versions of metadata extraction.
    pub mod metadata {
        use super::{parse_uint, ptr, Data, File, ParseUintError, TryFrom, UintBytesLength};

        /// Version 1, containing all the necessary structs and functions.
        pub mod v1 {
            use super::{parse_uint, ptr, Data, File, ParseUintError, TryFrom, UintBytesLength};

            /// An error enum representing a error in parsing file metadata.
            #[derive(Debug, PartialEq, Eq)]
            pub enum ParseFileError {
                /// Does not contain all necessary data.
                TooShort,
                /// Path length is too long to fit in memory.
                PathLengthTooLong,
            }

            /// Parse a file from the offset and with data. Version 1
            ///
            /// # Errors
            /// Will not panic.
            /// When parsing path length, will return error if `path_length_bytes` is wrong (>8).
            /// If the path length cannot fit into memory, it returns an error indicating so. Will never happen; one single path can **not** be larger than whole memory.
            pub fn parse_file_meta(
                bytes: &[u8],
                file_meta_start: usize,
                path_length_bytes: UintBytesLength,
            ) -> Result<File, ParseFileError> {
                if bytes.len() < 8 + 8 + path_length_bytes.get() {
                    return Err(ParseFileError::TooShort);
                }
                let mut start = 0usize;
                let file_start = {
                    let mut file_start = [0_u8; 8];
                    // Save because of the size of ↑ and the check before; both buffers must be >= 8, and we are copying integers from lists.
                    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), file_start.as_mut_ptr(), 8) };
                    start += 8;
                    u64::from_be_bytes(file_start)
                };
                let file_size = {
                    let mut file_size = [0_u8; 8];
                    // Save because of the size of ↑ and the check before; both buffers must be >= 8, and we are copying integers from lists.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            bytes.as_ptr().add(start),
                            file_size.as_mut_ptr(),
                            8,
                        )
                    };
                    start += 8;
                    u64::from_be_bytes(file_size)
                };
                let path_length =
                    usize::try_from(match parse_uint(&bytes[start..], path_length_bytes) {
                        Ok(length) => length,
                        Err(ParseUintError::BytesMissing) => return Err(ParseFileError::TooShort),
                        Err(ParseUintError::SizeToLarge) => unreachable!(),
                    })
                    .ok()
                    .ok_or(ParseFileError::PathLengthTooLong)?;
                start += path_length_bytes.get();
                let absolute_path_start = file_meta_start + start;
                start = start
                    .checked_add(path_length)
                    .ok_or(ParseFileError::PathLengthTooLong)?;
                Ok(File {
                    path_start: absolute_path_start,
                    path_length,
                    file_start,
                    file_size,
                    meta_length: start,
                })
            }

            /// Iterator for parsing file metadata.
            #[derive(Debug)]
            pub struct Files<'a> {
                data: &'a [u8],
                current_position: usize,
                path_length: UintBytesLength,
                header_end: u64,
            }
            impl<'a> Files<'a> {
                /// Crates a new iterator.
                #[must_use]
                pub fn new(
                    data: &'a Data,
                    path_length_bytes: UintBytesLength,
                    header_end: u64,
                ) -> Self {
                    Self {
                        data: data.data(),
                        current_position: 0,
                        path_length: path_length_bytes,
                        header_end,
                    }
                }
            }
            impl<'a> Iterator for Files<'a> {
                type Item = Result<File, ParseFileError>;
                fn next(&mut self) -> Option<Self::Item> {
                    if self.current_position as u64 >= self.header_end {
                        return None;
                    }
                    let file = match parse_file_meta(
                        &self.data[self.current_position..],
                        self.current_position,
                        self.path_length,
                    ) {
                        Err(ParseFileError::TooShort) => None,
                        Err(err) => Some(Err(err)),
                        Ok(file) => Some(Ok(file)),
                    };
                    if let Some(file) = file.as_ref() {
                        if let Ok(file) = file {
                            self.current_position += file.meta_length;
                        }
                    }
                    file
                }
            }
        }
    }

    /// Here all the versions of the parser reside.
    pub mod versions {
        use super::{metadata, ptr, Data, Error, Parsed, UintBytesLength};

        /// The first parser, hopefully not here to stay.
        pub mod v1 {
            use super::{
                metadata::v1::{Files, ParseFileError},
                ptr, Data, Error, Parsed, UintBytesLength,
            };

            /// Main parse entry-point
            ///
            /// # Errors
            /// Will spew out most errors defined in [`Error`] enum.
            pub fn parse(data: Data) -> Result<Parsed, Error> {
                if data.data_len() < 9 {
                    return Err(Error::MetadataIncomplete);
                }

                // Header size is a u64 to support file headers above 4GBs.
                // Size not including version and magic number, but including itself.
                let mut header_size = [0_u8; 8];
                // Save because of the size of ↑ and the check before; both buffers must be >= 8, and we are copying integers from lists.
                unsafe {
                    ptr::copy_nonoverlapping(data.data().as_ptr(), header_size.as_mut_ptr(), 8)
                };
                let header_size = u64::from_be_bytes(header_size);

                let path_length = data.data()[8];
                let path_length_bytes = UintBytesLength::new(path_length as usize)
                    .ok()
                    .ok_or(Error::MetadataWrong)?;

                let file_data = Data::new_from(&data, 9);

                let files = {
                    let mut vec = Vec::with_capacity(512);
                    'files: for file in Files::new(&file_data, path_length_bytes, header_size - 9) {
                        let file = match file {
                            Ok(file) => file,
                            Err(ParseFileError::PathLengthTooLong) => {
                                return Err(Error::PathLengthTooLong)
                            }
                            Err(ParseFileError::TooShort) => {
                                return Err(Error::FileMetadataIncomplete)
                            }
                        };
                        vec.push(file);
                    }
                    vec
                };

                Ok(Parsed {
                    version: 1,
                    header_size,
                    path_length,
                    files,
                    data,
                })
            }
        }
    }
    /// An error for parsing unsigned integers from bytes of unknown lengths.
    #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
    pub enum ParseUintError {
        /// Size is too large to handle. Only existent in [`UintBytesLength::new`], not [`parse_uint`]
        SizeToLarge,
        /// The length is greater than the bytes supplied.
        BytesMissing,
    }

    /// Represents a length of bytes for [`parse_uint`] to take.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct UintBytesLength(usize);
    impl UintBytesLength {
        /// Creates a new [`UintBytesLength`] within restrictions.
        ///
        /// # Errors
        /// The `length` can't be higher than 8, since the value is stored in an u64 (8-byte large integer).
        pub fn new(length: usize) -> Result<Self, ParseUintError> {
            if length >= mem::size_of::<UintParseType>() {
                Err(ParseUintError::SizeToLarge)
            } else {
                Ok(UintBytesLength(length))
            }
        }

        /// Gets the inner value.
        #[must_use]
        pub fn get(self) -> usize {
            self.0
        }
    }

    // If needed in the future, we can bump this to u128 (if file names are longer than what a u64 can contain. Very probable...)
    /// The type returned by [`parse_uint`]. Here to make the change easier if we need to in the future.
    pub type UintParseType = u64;

    /// Parse a uint of unknown size from bytes. Will currently return a u64.
    ///
    /// # Errors
    /// Fails to parse if supplied bytes aren't long enough for the length.
    pub fn parse_uint(
        bytes: &[u8],
        length: UintBytesLength,
    ) -> Result<UintParseType, ParseUintError> {
        const MAX_BYTES: usize = mem::size_of::<UintParseType>();
        if length.get() > bytes.len() {
            return Err(ParseUintError::BytesMissing);
        }

        let mut array = [0_u8; MAX_BYTES];
        let offset = MAX_BYTES - length.get();

        array[offset..(length.get() + offset)].copy_from_slice(&bytes[..length.get()]);

        Ok(u64::from_be_bytes(array))
    }
}

#[cfg(test)]
mod tests {
    use parse::UintBytesLength;

    use crate::parse;

    #[test]
    fn parse_uint() {
        // Are bytes 0, 0, 1, 5
        let bytes = b"\x00\x00\x01\x05";
        let int = parse::parse_uint(bytes, UintBytesLength::new(4).unwrap())
            .expect("failed to parse bytes");
        assert_eq!(int, 261);

        // Are bytes 0, 11
        // Will only take the two first bytes in consideration!
        let bytes = b"\x00\x0b\xaf\xde";
        let int = parse::parse_uint(bytes, UintBytesLength::new(2).unwrap())
            .expect("failed to parse bytes");
        assert_eq!(int, 11);
    }

    #[test]
    fn parse() {
        // First four bytes are version, 1, then comes the end of header; 5F = 95. Then the size of path length
        let bytes = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x5F\x01";
        parse::parse(bytes).unwrap();
    }

    #[test]
    fn get_path() {
        // First four bytes are version, 1, then comes the end of header; 5F = 95. Then the size of path length.
        // then file location and size, (16 bytes, all zeroes), then path length (1 byte, data: 1), then path ("/").
        let bytes = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x5F\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02/e\x00 <- byte is to tell parser the next path is 0 bytes long. This should not register";

        let parsed = parse::parse(bytes).unwrap();
        let file = parsed.fatten_file(&parsed.files[0]);
        let path = file.get_path();
        assert_eq!(path, Ok(std::path::Path::new("/e")));
    }
}
