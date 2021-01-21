#![warn(missing_debug_implementations, missing_docs)]
#![allow(unused_labels)]
#![warn(clippy::pedantic, clippy::cargo)]

//! This is a lib and binary crate to bundle files to a single one, like zipping it without compression.
//! Can bundle folders and open bundles.
//!
//! Current structure of file:
//! - MAGIC_NUMBER
//! - 4bit version number, big endian u32
//! - Header size, including these 8 bytes (so it starts counting directly after the version)
//! - 1 byte to indicate length of length of paths (a BE value of 1 indicates a path's length will take 1 byte)
//! - list of file meta entries
//! - File size
//! - Path length
//! - Path data in UTF8

/// The magic number associated with bundles. Used to offset all reading and when writing.
pub const MAGIC_NUMBER: &[u8] = b"";

/// Parsing module, including all versions and supporting structs and enums.
pub mod deserialize {
    use super::MAGIC_NUMBER;
    use std::{
        convert::{TryFrom, TryInto},
        mem,
        path::Path,
        ptr,
    };

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
        pub fn get_path<'a>(&self, data: &'a Data) -> Result<&'a Path, FileError> {
            let slice = &data.data()[self.path_start..self.path_start + self.path_length];
            match std::str::from_utf8(slice) {
                Ok(path) => Ok(Path::new(path)),
                Err(..) => Err(FileError::InvalidUTF8),
            }
        }

        pub fn size(&self) -> u64 {
            self.file_size
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
        let content_start = MAGIC_NUMBER.len() + 4;
        // Version type is constant; you can't change versioning formatting.
        let version = if bytes.len() < content_start {
            return Err(Error::MetadataIncomplete);
        } else {
            let mut value = [0; 4];
            // Save because of the size of ↑ and the check before; both buffers must be >= 4, and we are copying integers from lists.
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
            1 => versions::v1::parse(Data::new(bytes, content_start)),
            _ => Err(Error::VersionNotSupported),
        }
    }

    /// Versions of metadata extraction.
    pub mod metadata {
        use super::{
            parse_uint, ptr, Data, File, ParseUintError, TryFrom, TryInto, UintBytesLength,
        };

        /// Version 1, containing all the necessary structs and functions.
        pub mod v1 {
            use super::{
                parse_uint, ptr, Data, File, ParseUintError, TryFrom, TryInto, UintBytesLength,
            };

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
                let mut start = 0_usize;
                let file_size = {
                    let mut file_size = bytes[start..start + 8].try_into().unwrap();
                    start += 8;
                    u64::from_be_bytes(file_size)
                };
                let path_length =
                    usize::try_from(match parse_uint(&bytes[start..], path_length_bytes) {
                        Ok(length) => length,
                        Err(ParseUintError::BytesMissing) => return Err(ParseFileError::TooShort),
                        Err(ParseUintError::SizeTooLarge) => unreachable!(),
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
                header_size: u64,
            }
            impl<'a> Files<'a> {
                /// Crates a new iterator.
                #[must_use]
                pub fn new(
                    data: &'a Data,
                    path_length_bytes: UintBytesLength,
                    header_size: u64,
                ) -> Self {
                    Self {
                        data: data.data(),
                        current_position: 0,
                        path_length: path_length_bytes,
                        header_size,
                    }
                }
            }
            impl<'a> Iterator for Files<'a> {
                type Item = Result<File, ParseFileError>;
                fn next(&mut self) -> Option<Self::Item> {
                    if self.current_position as u64 >= self.header_size {
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
            use std::convert::TryInto;

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
                let mut header_size = data.data()[0..8].try_into().unwrap();
                let header_size = u64::from_be_bytes(header_size);

                let path_length = data.data()[8];
                let path_length_bytes = UintBytesLength::new(path_length)
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
        SizeTooLarge,
        /// The length is greater than the bytes supplied.
        BytesMissing,
    }

    /// Represents a length of bytes for [`parse_uint`] to take.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct UintBytesLength(u8);
    impl UintBytesLength {
        /// Creates a new [`UintBytesLength`] within restrictions.
        ///
        /// # Errors
        /// The `length` can't be higher than 8, since the value is stored in an u64 (8-byte large integer).
        pub fn new(length: u8) -> Result<Self, ParseUintError> {
            if length as usize >= mem::size_of::<UintParseType>() {
                Err(ParseUintError::SizeTooLarge)
            } else {
                Ok(UintBytesLength(length))
            }
        }

        /// Gets the inner value.
        #[must_use]
        pub fn get(self) -> usize {
            self.0 as usize
        }
        /// Gets the inner value as a `u8`.
        /// Will not panic; the value cannot be larger than 8.
        #[must_use]
        pub fn get_u8(self) -> u8 {
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

/// Module to extract from a bundle
pub mod extract {
    use super::{deserialize, MAGIC_NUMBER};
    use std::{convert::TryFrom, fs, io, io::prelude::*, path::Path};

    /// Reads from `reader` and saturates `bytes`. Like `read_to_end` for a fixed size array, but here you can use `Vec`s.
    /// Does not increase the capacity of a `Vec`, if it's used.
    ///
    /// # Errors
    /// Will pass through the errors from [`io::Read`] except for
    /// [`io::ErrorKind::Interrupted`], where it yields before continuing and
    /// [`io::ErrorKind::WouldBlock`] where it breaks.
    pub fn read_saturate<R: Read>(bytes: &mut [u8], mut reader: R) -> Result<usize, io::Error> {
        let mut read = 0;
        loop {
            match reader.read(&mut bytes[read..]) {
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                    std::thread::yield_now();
                    continue;
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    return Err(err);
                }
                Ok(0) => break,
                Ok(rd) => read += rd,
            }
        }
        Ok(read)
    }

    /// General error enum for extraction.
    #[derive(Debug)]
    pub enum Error {
        /// Io error encountered while reading the file.
        IO(io::Error),
        /// An error occured while deserializing.
        /// Often something is wrong with the file.
        Deserialize(deserialize::Error),
        /// The file is too short to even recognise version or magic number.
        TooShort,
        /// Header does not fit in memory.
        HeaderTooLarge,
        /// File is smaller than header is supposed to be.
        HeaderUnexpectedlySmall,
        /// Path is not valid UTF8
        InvalidPath,
    }
    impl From<io::Error> for Error {
        fn from(err: io::Error) -> Self {
            Self::IO(err)
        }
    }
    impl From<deserialize::Error> for Error {
        fn from(err: deserialize::Error) -> Self {
            Self::Deserialize(err)
        }
    }

    /// Extracts all the files at `file` to `destination`. If `destination == none` it extracts to the directory `file` is located in.
    ///
    /// # Errors
    /// All kinds, mostly regarding errors in file and reading it. See [`Error`]
    pub fn all<P: AsRef<Path>>(file: P, destination: Option<P>) -> Result<(), Error> {
        let mut reader = fs::File::open(&file)?;

        let early_metadata = {
            let mut buffer = [0; MAGIC_NUMBER.len() + 4]; // Magic number + version
            let read = reader.read(&mut buffer)?;
            if read != buffer.len() {
                return Err(Error::TooShort);
            }
            buffer
        };

        let mut value = [0; 4];
        // Save because of the size of ↑ and the check before; both buffers must be >= 4, and we are copying integers from lists.
        unsafe {
            std::ptr::copy_nonoverlapping(
                early_metadata.as_ptr().add(MAGIC_NUMBER.len()),
                value.as_mut_ptr(),
                4,
            )
        };
        let version = u32::from_be_bytes(value);

        match version {
            1 => versions::v1::extract_all(reader, destination, early_metadata),
            _ => Err(deserialize::Error::VersionNotSupported.into()),
        }
    }
    /// All the extraction versions.
    pub mod versions {
        use super::{deserialize, fs, read_saturate, Error, Path, Read, TryFrom, MAGIC_NUMBER};
        /// Version one! Maybe it works?
        pub mod v1 {
            use std::{borrow::Cow, io::prelude::*};

            use deserialize::File;

            use super::{deserialize, fs, read_saturate, Error, Path, Read, TryFrom, MAGIC_NUMBER};
            /// Extracts all the content from the bundle.
            /// `file` is expected to be at (you have read to) the beginning of the files section.
            /// `early_metadata` contains the [`MAGIC_NUMBER`] and a `u32` version.
            ///
            /// # Errors2rs in the file, the size of the file, and [`io::Read`] errors.
            pub fn extract_all<P: AsRef<Path>>(
                mut file: fs::File,
                dest: Option<P>,
                early_metadata: [u8; MAGIC_NUMBER.len() + 4],
            ) -> Result<(), Error> {
                if early_metadata.starts_with(MAGIC_NUMBER) {
                    eprintln!("Trying to extract from a file without the correct magic number.");
                }

                let (header_size, path_length_bytes) = {
                    let mut buffer = [0; 8 + 1]; //  + header size + path length bytes
                    let read = file.read(&mut buffer)?;
                    if read != buffer.len() {
                        return Err(Error::TooShort);
                    }
                    let size = [
                        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5],
                        buffer[6], buffer[7],
                    ];
                    (u64::from_be_bytes(size), buffer[8])
                };

                // minus 8 + 1 since we already read that above!
                let header_size = usize::try_from(header_size - (8 + 1))
                    .ok()
                    .ok_or(Error::HeaderTooLarge)?;

                let mut header = Vec::with_capacity(header_size);
                // Is OK, since I write to all and don't read it unless all (previous random data) is overriden.
                unsafe { header.set_len(header.capacity()) };
                if read_saturate(&mut header[..], &mut file)? != header.len() {
                    return Err(Error::HeaderUnexpectedlySmall);
                };

                println!("Header: {:?}", String::from_utf8_lossy(&header));

                let path_length_bytes = deserialize::UintBytesLength::new(path_length_bytes)
                    .ok()
                    .ok_or(deserialize::Error::MetadataWrong)?;

                let data = deserialize::Data::new(&header[..], 0);

                let files = {
                    use deserialize::metadata::v1::{Files, ParseFileError};
                    let mut vec = Vec::with_capacity(512);
                    'files: for file in Files::new(&data, path_length_bytes, header_size as u64) {
                        let file = match file {
                            Ok(file) => file,
                            Err(ParseFileError::PathLengthTooLong) => {
                                return Err(deserialize::Error::PathLengthTooLong.into());
                            }
                            Err(ParseFileError::TooShort) => {
                                return Err(deserialize::Error::FileMetadataIncomplete.into());
                            }
                        };
                        vec.push(file);
                    }
                    vec
                };

                // Else rust-analyser fricks up
                let files: Vec<File> = files;

                let mut buffer = Vec::with_capacity(4 * 8 * 1024 * 1024); // 4 bytes * 1024 (4kb) * 1024 (4mb)

                // Will not read bytes not overriden
                unsafe { buffer.set_len(buffer.capacity()) };

                for file_meta in files.iter() {
                    // file.seek(io::SeekFrom::Start(
                    //     file_meta.start() + header_size as u64 + MAGIC_NUMBER.len() as u64 + 4,
                    // ))?;

                    let path = match dest.as_ref() {
                        Some(dest) => Cow::Owned(
                            dest.as_ref()
                                .join(file_meta.get_path(&data).ok().ok_or(Error::InvalidPath)?),
                        ),
                        None => {
                            Cow::Borrowed(file_meta.get_path(&data).ok().ok_or(Error::InvalidPath)?)
                        }
                    };

                    println!("Reading file {:?} with size {}", path, file_meta.size());

                    let mut dir = fs::DirBuilder::new();
                    dir.recursive(true);
                    dir.create(&path.with_file_name(""))?;

                    let mut dest = fs::File::create(&path)?;

                    println!("Created file! {:?}", &path);

                    let mut total_read = 0;

                    'copy: loop {
                        if total_read == file_meta.size() {
                            break;
                        }

                        // if file_meta.size() - total_read < buffer.len() as u64 {
                        let read = read_saturate(
                            &mut buffer[..(file_meta.size() - total_read) as usize],
                            &mut file,
                        )?;
                        total_read += read as u64;
                        // }

                        if read == 0 {
                            break;
                        }

                        dest.write_all(&buffer[..read])?;
                    }

                    println!("File path: {:?}", path);
                }

                Ok(())
            }
        }
    }
}

pub mod package {
    use super::{deserialize, extract, MAGIC_NUMBER};
    use std::{
        fs::Metadata,
        io,
        path::{Path, PathBuf},
    };

    /// Will walk a dir at `path`.
    ///
    /// # Errors
    /// Will return any errors from [`io`] functions.
    /// This function tries to read metadata from files and view content in directories.
    pub(crate) fn walk_dir<P: AsRef<Path>, F: Fn(&Metadata) -> bool>(
        path: P,
        filter: &F,
    ) -> io::Result<Vec<(PathBuf, Metadata)>> {
        fn walk<F: Fn(&Metadata) -> bool>(
            path: &Path,
            filter: &F,
            vec: &mut Vec<(PathBuf, Metadata)>,
        ) -> io::Result<()> {
            let dir = path.read_dir()?;

            for file in dir {
                let file = file?;
                let file_type = file.file_type()?;
                let metadata = file.metadata()?;
                let path = file.path();

                if file_type.is_file() {
                    if filter(&metadata) {
                        vec.push((file.path(), metadata));
                    }
                } else if file_type.is_dir() {
                    walk(path.as_path(), filter, vec)?;
                }
            }
            Ok(())
        }
        let mut files = Vec::new();

        walk(path.as_ref(), filter, &mut files)?;

        Ok(files)
    }

    #[derive(Debug)]
    pub enum Error {
        IO(io::Error),
        PathNotUTF8,
        FileDisappeared,
    }
    impl From<io::Error> for Error {
        fn from(err: io::Error) -> Self {
            Self::IO(err)
        }
    }

    pub fn package_latest<P: AsRef<Path>>(path: P, destination: P) -> Result<(), Error> {
        v1::package_dir(path, destination)
    }

    pub mod v1 {
        use super::{deserialize, extract::read_saturate, MAGIC_NUMBER};

        use super::{walk_dir, Error};
        use std::{fs, io, io::prelude::*, path::Path};

        pub fn package_dir<P: AsRef<Path>>(path: P, destination_path: P) -> Result<(), Error> {
            let files = walk_dir(path, &|_| true)?;

            println!(
                "Creating destination file at {:?}",
                destination_path.as_ref()
            );

            let mut destination = fs::File::create(destination_path.as_ref())?;

            // Magic number
            destination.write_all(MAGIC_NUMBER)?;
            // Version
            let version: u32 = 1;
            destination.write_all(&version.to_be_bytes())?;
            // Header size, u64; 8 bytes
            destination.write_all(&[0; 8])?;

            let longest_path = {
                let mut longest: deserialize::UintParseType = 0;
                for (path, _) in files.iter() {
                    let length = path.to_str().ok_or(Error::PathNotUTF8)?.len() as u64;
                    if length > longest {
                        longest = length;
                    }
                }
                longest
            };
            let bytes_needed = {
                let mut shift = longest_path >> 8;
                let mut bytes: u8 = 1;
                loop {
                    if shift > 255 {
                        shift = shift >> 8;
                        bytes += 1;
                        continue;
                    } else {
                        break;
                    }
                }
                bytes
            };
            // How many bytes to represent path.
            destination.write(&[bytes_needed])?;

            // From now on, all paths are valid UTF-8

            for (path, metadata) in files.iter() {
                destination.write_all(&metadata.len().to_be_bytes())?;

                let path_length = (path.to_str().unwrap().len() as u64).to_be_bytes();

                // The eight comes from `as u64` above.
                let bytes_to_write = 8 - bytes_needed as usize;
                destination.write_all(&path_length[bytes_to_write..])?;
                destination.write_all(path.to_str().unwrap().as_bytes())?;
            }
            let current_pos = destination.seek(io::SeekFrom::Current(0))?;

            destination.seek(io::SeekFrom::Start(MAGIC_NUMBER.len() as u64 + 4))?;
            destination
                .write_all(&(current_pos - (MAGIC_NUMBER.len() as u64 + 4)).to_be_bytes())?;
            // Back where we were!
            println!(
                "Writing header size: {}",
                current_pos - (MAGIC_NUMBER.len() as u64 + 4)
            );
            destination.seek(io::SeekFrom::Start(current_pos))?;

            // Now writing all files.

            let mut buffer = Vec::with_capacity(4 * 8 * 1024 * 1024); // 4 bytes * 1024 (4kb) * 1024 (4mb)

            // Will not read bytes not overriden
            unsafe { buffer.set_len(buffer.capacity()) };

            for (path, _) in files.iter() {
                let mut file = match fs::File::open(path) {
                    Err(_) => return Err(Error::FileDisappeared),
                    Ok(file) => file,
                };
                println!("Opened {:?}", path);

                'copy: loop {
                    let read = read_saturate(&mut buffer, &mut file)?;
                    destination.write_all(&buffer[..read])?;
                    println!("Wrote {} bytes to {:?}", read, path);
                    if read != buffer.len() {
                        break;
                    }
                }
            }

            destination.flush()?;

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::deserialize::{self, UintBytesLength};

    #[test]
    fn parse_uint() {
        // Are bytes 0, 0, 1, 5
        let bytes = b"\x00\x00\x01\x05";
        let int = deserialize::parse_uint(bytes, UintBytesLength::new(4).unwrap())
            .expect("failed to parse bytes");
        assert_eq!(int, 261);

        // Are bytes 0, 11
        // Will only take the two first bytes in consideration!
        let bytes = b"\x00\x0b\xaf\xde";
        let int = deserialize::parse_uint(bytes, UintBytesLength::new(2).unwrap())
            .expect("failed to parse bytes");
        assert_eq!(int, 11);
    }

    #[test]
    fn parse() {
        // First four bytes are version, 1, then comes the end of header; 5F = 95. Then the size of path length
        let bytes = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x5F\x01";
        deserialize::parse(bytes).unwrap();
    }

    #[test]
    fn get_path() {
        // First four bytes are version, 1, then comes the end of header; 5F = 95. Then the size of path length.
        // then file location and size, (16 bytes, all zeroes), then path length (1 byte, data: 1), then path ("/").
        let bytes = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x5F\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02/e\x00 <- byte is to tell parser the next path is 0 bytes long. This should not register";

        let parsed = deserialize::parse(bytes).unwrap();
        let file = parsed.fatten_file(&parsed.files[0]);
        let path = file.get_path();
        assert_eq!(path, Ok(std::path::Path::new("/e")));
    }
}
