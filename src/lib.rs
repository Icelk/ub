#![warn(missing_debug_implementations, missing_docs)]
#![allow(unused_labels)]
#![warn(clippy::pedantic, clippy::cargo)]

//! This is a lib and binary crate to bundle files to a single one, like zipping it without compression.
//! Can bundle folders, and open bundles.
//!
//! Current structure of file:
//! - [`MAGIC_NUMBER`]
//! - Version, `version` (u32), big endian u32 signaling the number of the bundle.
//! - Here the `header` begins. Everything after this, up to where the file data start is part of the `header`.
//! - Header size, `header_size` (u64): size of header including these 8 bytes (it starts directly after the version)
//! - Size of path length `path_length_bytes` (u8): byte to indicate length of length of paths (a big endian value of 1 indicates a path's length will take 1 byte)
//! - List of file meta entries `files` (no defined length, that is what the header size is for)
//!     - File size, `file_size` (u64): the file size. Used to calculate where the files are located in the file. (weak point for corruption, so maybe add a `file_position` too?)
//!     - Path length, `path_length` (u(`path_length_bytes * 8`); [`deserialize::UintParseType`]): how many bytes after of this will provide the path.
//!     - Path data, `path` ([u8; `path_length`]): the path for this file, used in extraction. I have plans to cluster these when files start with the same bytes to avoid repetition (have a group for a folder with many files, so the individual files don't need the whole path.)

/// The magic number associated with bundles. Used to offset all reading and when writing.
pub const MAGIC_NUMBER: &[u8] = b"";

/// Reads from `reader` and saturates `bytes`. Like `read_to_end` for a fixed size array, but here you can use `Vec`s.
/// Does not increase the capacity of a `Vec`, if it's used.
/// Will always fill `bytes` if `reader` has enough data.
///
/// # Errors
/// Will pass through the errors from [`io::Read`] except for
/// [`io::ErrorKind::Interrupted`], where it yields before continuing and
/// [`io::ErrorKind::WouldBlock`] where it breaks.
pub(crate) fn read_saturate<R: std::io::Read>(
    bytes: &mut [u8],
    mut reader: R,
) -> Result<usize, std::io::Error> {
    let mut read = 0;
    loop {
        match reader.read(&mut bytes[read..]) {
            Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => {
                std::thread::yield_now();
                continue;
            }
            Err(err) => {
                return Err(err);
            }
            Ok(0) => break,
            Ok(rd) => {
                read += rd;
                if read == bytes.len() {
                    break;
                }
            }
        }
    }
    Ok(read)
}

pub(crate) const DEFAULT_BUF_SIZE: usize = 1024 * 64; // 2^16 bytes; 1024 * 64; 64KB

/// Parsing module, including all versions and supporting structs and enums.
pub mod deserialize {
    use super::*;
    use std::{
        cell::RefCell,
        convert::{TryFrom, TryInto},
        io::{self, prelude::*, Seek, SeekFrom},
        mem,
        path::{Path, PathBuf},
    };

    pub struct File<'a, R: Read + Seek> {
        source: &'a RefCell<&'a mut R>,
        size: u64,
        /// Position in whole file, including `header`, `header_size`, and [`MAGIC_NUMBER`]
        position: u64,
        path: PathBuf,
        offset: u64,
    }
    impl<'a, R: Read + Seek> File<'a, R> {
        pub fn path(&self) -> &Path {
            self.path.as_path()
        }

        pub fn size(&self) -> u64 {
            self.size
        }

        pub fn align(&mut self) -> io::Result<()> {
            match self
                .source
                .borrow_mut()
                .seek(SeekFrom::Start(self.position + self.offset))
            {
                Err(err) => Err(err),
                Ok(_) => Ok(()),
            }
        }
        pub fn align_to_start(&mut self) -> io::Result<()> {
            match self
                .source
                .borrow_mut()
                .seek(SeekFrom::Start(self.position))
            {
                Err(err) => Err(err),
                Ok(_) => Ok(()),
            }
        }
    }
    impl<'a, R: Read + Seek> Read for File<'a, R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.align()?;

            match self.source.borrow_mut().read(buf) {
                Err(err) => Err(err),
                Ok(read) => {
                    self.offset += read as u64;
                    Ok(read)
                }
            }
        }
    }

    pub struct Files<'a, R: Read + Seek> {
        files: Vec<File<'a, R>>,
    }
    impl<'a, R: Read + Seek> Files<'a, R> {
        pub fn all(&mut self) -> &mut [File<'a, R>] {
            self.files.as_mut_slice()
        }

        pub fn filter<F: FnMut(&Path) -> bool>(&mut self, mut filter: F) -> Vec<&mut File<'a, R>> {
            self.files.iter_mut().filter(|f| filter(f.path())).collect()
        }
    }

    /// Representation of a file in the header of the bundle. Contains info about the real file, such as path, name, and size.
    #[derive(Debug, PartialEq, Eq)]
    pub struct FileMeta {
        // Not in file, but calculated when reading for convenience.
        /// Start of path from start of `files`.
        path_start: usize,
        /// Length of path
        path_length: usize,
        /// Size of file stored
        file_size: u64,
    }

    /// Supporting error struct for [`parse()`] and the [`versions`] functions. Contains all parsing related errors.
    #[derive(Debug)]
    pub enum Error {
        /// The version is not supported by the [`parse()`] function.
        VersionNotSupported,
        /// Signals some metadata is missing or incomplete. This is often the case when the file is smaller than the base meta size.
        MetadataIncomplete,
        /// Metadata is in some way out of boundaries, such as the file path length size being above 8.
        MetadataWrong,
        /// Header is too large to fit into memory. This limitation might be removed, but would probably cause severe slowdowns (having to `seek` in the file to get any header data)
        HeaderTooLarge,
        /// File is smaller than what `header_size` suggests it is.
        HeaderUnexpectedlySmall,
        /// Path takes more memory than can be pointed to.
        PathLengthTooLong,
        /// If the metadata for the file is incomplete, usually from outside manipulation (gone wrong). Occurs when more data is expected.
        FileMetadataIncomplete,
        /// An error occured while trying to read from the supplied `reader`.
        Reader(io::Error),
        /// Path contains invalid UTF8. This limitation should be removed in the future
        InvalidUTF8,
    }

    /// General parse function. Will recognise version and call the appropriate function.
    ///
    /// # Errors
    /// If a version is not supported, it will return a [`Error::VersionNotSupported`].
    /// All other errors are inherited from the related [`versions`] functions. Check [`Error`] for possible values.
    pub fn parse<'a, R: Read + Seek>(
        reader: &'a RefCell<&'a mut R>,
    ) -> Result<Files<'a, R>, Error> {
        let mut buffer = [0; MAGIC_NUMBER.len() + 4];
        let read = reader
            .borrow_mut()
            .read(&mut buffer)
            .map_err(Error::Reader)?;
        // Version type is constant; you can't change versioning formatting. I think 2^32 versions will be plenty.
        let version = if read != buffer.len() {
            return Err(Error::MetadataIncomplete);
        } else {
            let value = buffer[MAGIC_NUMBER.len()..MAGIC_NUMBER.len() + 4]
                .try_into()
                .unwrap();
            u32::from_be_bytes(value)
        };
        match version {
            1 => versions::parse_v1(reader),
            _ => Err(Error::VersionNotSupported),
        }
    }

    /// Versions of metadata extraction.
    pub mod metadata {
        use super::{parse_uint, FileMeta, ParseUintError, TryFrom, TryInto, UintBytesLength};

        /// An error enum representing a error in parsing file metadata.
        #[derive(Debug, PartialEq, Eq)]
        pub enum ParseFileErrorV1 {
            /// Does not contain all necessary data.
            TooShort,
            /// Path length is too long to fit in memory.
            PathLengthTooLong,
        }

        /// Parse a file from the offset and with data. Version 1
        ///
        /// # Errors
        /// Will not panic.
        /// (at least I think so...)
        /// When parsing path length, will return error if `path_length_bytes` is wrong (>8).
        /// If the path length cannot fit into memory, it returns an error indicating so. Will never happen; one single path can **not** be larger than whole memory.
        pub fn parse_file_meta_v1(
            bytes: &[u8],
            file_meta_start: usize,
            path_length_bytes: UintBytesLength,
        ) -> Result<FileMeta, ParseFileErrorV1> {
            if bytes.len() < 8 + 8 + path_length_bytes.get() {
                return Err(ParseFileErrorV1::TooShort);
            }
            let mut start = 0_usize;
            let file_size = {
                let file_size = bytes[start..start + 8].try_into().unwrap();
                start += 8;
                u64::from_be_bytes(file_size)
            };
            let path_length =
                usize::try_from(match parse_uint(&bytes[start..], path_length_bytes) {
                    Ok(length) => length,
                    Err(ParseUintError::BytesMissing) => return Err(ParseFileErrorV1::TooShort),
                    Err(ParseUintError::SizeTooLarge) => unreachable!(),
                })
                .ok()
                .ok_or(ParseFileErrorV1::PathLengthTooLong)?;
            start += path_length_bytes.get();
            let absolute_path_start = file_meta_start + start;
            start = start
                .checked_add(path_length)
                .ok_or(ParseFileErrorV1::PathLengthTooLong)?;
            Ok(FileMeta {
                path_start: absolute_path_start,
                path_length,
                file_size,
            })
        }

        /// Iterator for parsing file metadata.
        #[derive(Debug)]
        pub struct FileIterV1<'a> {
            bytes: &'a [u8],
            current_position: usize,
            path_length: UintBytesLength,
            header_size: u64,
        }
        impl<'a> FileIterV1<'a> {
            /// Crates a new iterator that yields [`FileMeta`]s.
            /// `bytes` should be after `path_length_bytes`; the `files` segment
            #[must_use]
            pub fn new(
                bytes: &'a [u8],
                path_length_bytes: UintBytesLength,
                header_size: u64,
            ) -> Self {
                Self {
                    bytes,
                    current_position: 0,
                    path_length: path_length_bytes,
                    header_size,
                }
            }
        }
        impl<'a> Iterator for FileIterV1<'a> {
            type Item = Result<FileMeta, ParseFileErrorV1>;
            fn next(&mut self) -> Option<Self::Item> {
                // `header_size` includes 9 bytes we don't want.
                if self.current_position as u64 >= (self.header_size - (8 + 1)) {
                    return None;
                }
                let file = match parse_file_meta_v1(
                    &self.bytes[self.current_position..],
                    // `current_position` is from start of `files`, as `FileMeta` requires
                    self.current_position,
                    self.path_length,
                ) {
                    Err(ParseFileErrorV1::TooShort) => None,
                    Err(err) => Some(Err(err)),
                    Ok(file) => Some(Ok(file)),
                };
                if let Some(file) = file.as_ref() {
                    if let Ok(file) = file {
                        self.current_position += 8 + self.path_length.get() + file.path_length;
                    }
                }
                file
            }
        }
    }

    /// Here all the versions of the parser reside.
    pub mod versions {
        use super::*;

        /// The first parser, hopefully hot here to stay.
        /// `reader` should be at the beginning of `header_size` location defined in the crate-level docs
        ///
        /// # Errors
        /// Will spew out most errors defined in [`Error`] enum.
        pub fn parse_v1<'a, R: Read + Seek>(
            reader: &'a RefCell<&'a mut R>,
        ) -> Result<Files<'a, R>, Error> {
            let mut buffer = [0; 9];
            let read = reader
                .borrow_mut()
                .read(&mut buffer)
                .map_err(Error::Reader)?;
            if read != buffer.len() {
                return Err(Error::MetadataIncomplete);
            }

            // Header size is a u64 to support file headers above 4GBs.
            // Size not including version and magic number, but including itself.
            let header_size = buffer[0..8].try_into().unwrap();
            let header_size = u64::from_be_bytes(header_size);
            let header_size_usize = usize::try_from(header_size)
                .ok()
                .ok_or(Error::HeaderTooLarge)?;

            let path_length_bytes = buffer[8];
            let path_length_bytes = UintBytesLength::new(path_length_bytes)
                .ok()
                .ok_or(Error::MetadataWrong)?;

            let header = {
                let mut header = Vec::with_capacity(header_size_usize);
                // Is OK, since I read just enough data to fill it. We don't have any problems with dropping, since they are all integers
                unsafe { header.set_len(header.capacity()) };
                if read_saturate(&mut header[..], &mut *reader.borrow_mut())
                    .map_err(Error::Reader)?
                    != header.len()
                {
                    return Err(Error::HeaderUnexpectedlySmall);
                };
                header
            };

            let mut position_in_file = MAGIC_NUMBER.len() as u64 + 4 + header_size;
            let files = {
                let mut vec = Vec::with_capacity(512);
                // Not `&header[8+1..]` since `header_size` and `path_length_bytes` bytes aren't in it.
                'files: for file in
                    metadata::FileIterV1::new(&header, path_length_bytes, header_size)
                {
                    let file = match file {
                        Ok(file_meta) => {
                            let path = {
                                let vec = header[file_meta.path_start
                                    ..file_meta.path_start + file_meta.path_length]
                                    .to_vec();
                                let string =
                                    String::from_utf8(vec).ok().ok_or(Error::InvalidUTF8)?;
                                PathBuf::from(string)
                            };
                            let file = File {
                                source: &reader,
                                size: file_meta.file_size,
                                position: position_in_file,
                                path,
                                offset: 0,
                            };
                            position_in_file += file_meta.file_size;
                            file
                        }
                        Err(metadata::ParseFileErrorV1::PathLengthTooLong) => {
                            return Err(Error::PathLengthTooLong)
                        }
                        Err(metadata::ParseFileErrorV1::TooShort) => {
                            return Err(Error::FileMetadataIncomplete)
                        }
                    };
                    vec.push(file);
                }
                vec
            };

            Ok(Files { files })
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
    #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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

        /// Gets the inner value, represented as a u8.
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

// /// Module to extract from a bundle
// pub mod extract {
//     use super::*;
//     use std::{
//         convert::{TryFrom, TryInto},
//         fs, io,
//         io::prelude::*,
//         path::Path,
//     };

//     /// General error enum for extraction.
//     #[derive(Debug)]
//     pub enum Error {
//         /// Io error encountered while reading the file.
//         IO(io::Error),
//         /// An error occured while deserializing.
//         /// Often something is wrong with the file.
//         Deserialize(deserialize::Error),
//         /// The file is too short to even recognise version or magic number.
//         TooShort,
//         /// Header does not fit in memory.
//         HeaderTooLarge,
//         /// File is smaller than header is supposed to be.
//         HeaderUnexpectedlySmall,
//         /// Path is not valid UTF8
//         InvalidPath,
//     }
//     impl From<io::Error> for Error {
//         fn from(err: io::Error) -> Self {
//             Self::IO(err)
//         }
//     }
//     impl From<deserialize::Error> for Error {
//         fn from(err: deserialize::Error) -> Self {
//             Self::Deserialize(err)
//         }
//     }

//     /// Extracts all the files at `file` to `destination`. If `destination == none` it extracts to the directory `file` is located in.
//     ///
//     /// # Errors
//     /// All kinds, mostly regarding errors in file and reading it. See [`Error`]
//     pub fn all<P: AsRef<Path>>(file: P, destination: Option<P>) -> Result<(), Error> {
//         let mut reader = fs::File::open(&file)?;

//         let early_metadata = {
//             let mut buffer = [0; MAGIC_NUMBER.len() + 4]; // Magic number + version
//             let read = reader.read(&mut buffer)?;
//             if read != buffer.len() {
//                 return Err(Error::TooShort);
//             }
//             buffer
//         };

//         let value = early_metadata[MAGIC_NUMBER.len()..].try_into().unwrap();
//         let version = u32::from_be_bytes(value);

//         match version {
//             1 => versions::v1::extract_all(reader, destination, early_metadata),
//             _ => Err(deserialize::Error::VersionNotSupported.into()),
//         }
//     }
//     /// All the extraction versions.
//     pub mod versions {
//         use super::{deserialize, fs, read_saturate, Error, Path, Read, TryFrom, MAGIC_NUMBER};
//         /// Version one! Maybe it works?
//         pub mod v1 {
//             use std::{borrow::Cow, io::prelude::*};

//             use deserialize::FileMeta;

//             use super::{deserialize, fs, read_saturate, Error, Path, Read, TryFrom, MAGIC_NUMBER};
//             /// Extracts all the content from the bundle.
//             /// `file` is expected to be at (you have read to) the beginning of the files section.
//             /// `early_metadata` contains the [`MAGIC_NUMBER`] and a `u32` version.
//             ///
//             /// # Errors in the file, the size of the file, and [`io::Read`] errors.
//             pub fn extract_all<P: AsRef<Path>>(
//                 mut file: fs::File,
//                 dest: Option<P>,
//                 early_metadata: [u8; MAGIC_NUMBER.len() + 4],
//             ) -> Result<(), Error> {
//                 if !early_metadata.starts_with(MAGIC_NUMBER) {
//                     eprintln!("Trying to extract from a file without the correct magic number.");
//                 }

//                 let (header_size, path_length_bytes) = {
//                     let mut buffer = [0; 8 + 1]; //  + header size + path length bytes
//                     let read = file.read(&mut buffer)?;
//                     if read != buffer.len() {
//                         return Err(Error::TooShort);
//                     }
//                     let size = [
//                         buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5],
//                         buffer[6], buffer[7],
//                     ];
//                     (u64::from_be_bytes(size), buffer[8])
//                 };

//                 // minus 8 + 1 since we already read that above!
//                 let header_size = usize::try_from(header_size - (8 + 1))
//                     .ok()
//                     .ok_or(Error::HeaderTooLarge)?;

//                 let mut header = Vec::with_capacity(header_size);
//                 // Is OK, since I write to all and don't read it unless all (previous random data) is overriden.
//                 unsafe { header.set_len(header.capacity()) };
//                 if read_saturate(&mut header[..], &mut file)? != header.len() {
//                     return Err(Error::HeaderUnexpectedlySmall);
//                 };

//                 println!("Header: {:?}", String::from_utf8_lossy(&header));

//                 let path_length_bytes = deserialize::UintBytesLength::new(path_length_bytes)
//                     .ok()
//                     .ok_or(deserialize::Error::MetadataWrong)?;

//                 let data = deserialize::Data::new(&header[..], 0);

//                 let files = {
//                     use deserialize::metadata::v1::{FileIter, ParseFileError};
//                     let mut vec = Vec::with_capacity(512);
//                     'files: for file in Files::new(&data, path_length_bytes, header_size as u64) {
//                         let file = match file {
//                             Ok(file) => file,
//                             Err(ParseFileError::PathLengthTooLong) => {
//                                 return Err(deserialize::Error::PathLengthTooLong.into());
//                             }
//                             Err(ParseFileError::TooShort) => {
//                                 return Err(deserialize::Error::FileMetadataIncomplete.into());
//                             }
//                         };
//                         vec.push(file);
//                     }
//                     vec
//                 };

//                 // Else rust-analyser fricks up
//                 let files: Vec<FileMeta> = files;

//                 let mut buffer = Vec::with_capacity(4 * 8 * 1024 * 1024); // 4 bytes * 1024 (4kb) * 1024 (4mb)

//                 // Will not read bytes not overriden
//                 unsafe { buffer.set_len(buffer.capacity()) };

//                 for file_meta in files.iter() {
//                     // file.seek(io::SeekFrom::Start(
//                     //     file_meta.start() + header_size as u64 + MAGIC_NUMBER.len() as u64 + 4,
//                     // ))?;

//                     let path = match dest.as_ref() {
//                         Some(dest) => Cow::Owned(
//                             dest.as_ref()
//                                 .join(file_meta.get_path(&data).ok().ok_or(Error::InvalidPath)?),
//                         ),
//                         None => {
//                             Cow::Borrowed(file_meta.get_path(&data).ok().ok_or(Error::InvalidPath)?)
//                         }
//                     };

//                     println!("Reading file {:?} with size {}", path, file_meta.size());

//                     let mut dir = fs::DirBuilder::new();
//                     dir.recursive(true);
//                     dir.create(&path.with_file_name(""))?;

//                     let mut dest = fs::File::create(&path)?;

//                     println!("Created file! {:?}", &path);

//                     let mut total_read = 0;

//                     'copy: loop {
//                         if total_read == file_meta.size() {
//                             break;
//                         }

//                         // if file_meta.size() - total_read < buffer.len() as u64 {
//                         let read = read_saturate(
//                             &mut buffer[..(file_meta.size() - total_read) as usize],
//                             &mut file,
//                         )?;
//                         total_read += read as u64;
//                         // }

//                         if read == 0 {
//                             break;
//                         }

//                         dest.write_all(&buffer[..read])?;
//                     }

//                     println!("File path: {:?}", path);
//                 }

//                 Ok(())
//             }
//         }
//     }
// }

pub mod package {
    use super::*;
    use std::{
        fs,
        fs::Metadata,
        io,
        io::prelude::*,
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
        package_dir_v1(path, destination)
    }

    pub fn package_dir_v1<P: AsRef<Path>>(path: P, destination_path: P) -> Result<(), Error> {
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
        destination.write_all(&(current_pos - (MAGIC_NUMBER.len() as u64 + 4)).to_be_bytes())?;
        // Back where we were!
        println!(
            "Writing header size: {}",
            current_pos - (MAGIC_NUMBER.len() as u64 + 4)
        );
        destination.seek(io::SeekFrom::Start(current_pos))?;

        // Now writing all files.

        let mut buffer = Vec::with_capacity(DEFAULT_BUF_SIZE);

        // Will not read bytes not overriden
        unsafe { buffer.set_len(buffer.capacity()) };

        for (path, _) in files.iter() {
            let mut file = match fs::File::open(path) {
                Err(_) => return Err(Error::FileDisappeared),
                Ok(file) => file,
            };
            println!("Opened {:?} with buffer size {}", path, buffer.len());

            'copy: loop {
                let read = file.read(&mut buffer)?;
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
