#![warn(missing_debug_implementations, missing_docs)]
#![warn(clippy::pedantic, clippy::cargo)]
#![allow(clippy::wildcard_imports, dead_code)]

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

pub use deserialize::{parse, File, Files};
pub use serialize::{walk_dir, write};

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

/// Default buffer size for this crate.
pub(crate) const DEFAULT_BUFFER_SIZE: usize = 1024 * 64; // 2^16 bytes; 1024 * 64; 64KB

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

    /// A parsed file. Contains a reference where in the reader the file is located, implements [`Read`], and contains a [`PathBuf`]
    #[derive(Debug)]
    pub struct File<'a, R: Read + Seek> {
        source: &'a RefCell<&'a mut R>,
        size: u64,
        /// Position in whole file, including `header`, `header_size`, and [`MAGIC_NUMBER`]
        position: u64,
        path: PathBuf,
        offset: u64,
    }
    impl<'a, R: Read + Seek> File<'a, R> {
        /// Get a reference of the path this file is pointing at.
        #[must_use]
        #[inline]
        pub fn path(&self) -> &Path {
            self.path.as_path()
        }
        /// Discards all information and return path. I dunno if this is useful...
        #[must_use]
        #[inline]
        pub fn into_path(self) -> PathBuf {
            self.path
        }

        /// Gets the size of this file.
        #[must_use]
        #[inline]
        pub fn size(&self) -> u64 {
            self.size
        }

        /// Aligns the underlying reader to the position we last read at.
        /// Can be used to continue reading a file.
        ///
        /// # Errors
        /// Same as [`fs::File::seek()`]
        #[inline]
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
        /// Aligns the underlying reader to the start of this file, to start over and read it from the start.
        ///
        /// # Errors
        /// Same as [`fs::File::seek()`]
        #[inline]
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

            // To remove one syscall to fill empty slice.
            if self.offset == self.size {
                return Ok(0);
            }

            let slice = if self.size - self.offset < buf.len() as u64 {
                // Will not panic; above guarantees `self.size - self.offset` is less than usize, else buf.len() could not return.
                #[allow(clippy::cast_possible_truncation)]
                &mut buf[..(self.size - self.offset) as usize]
            } else {
                buf
            };

            match self.source.borrow_mut().read(slice) {
                Err(err) => Err(err),
                Ok(read) => {
                    self.offset += read as u64;
                    Ok(read)
                }
            }
        }
    }
    impl<'a, R: Read + Seek> Seek for File<'a, R> {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            #[allow(clippy::cast_sign_loss)]
            match pos {
                io::SeekFrom::Current(offset) => {
                    if offset.is_negative() && (-offset) as u64 > self.offset {
                        Err(io::ErrorKind::InvalidInput.into())
                    } else {
                        if offset < 0 {
                            self.offset -= (-offset) as u64;
                        } else {
                            self.offset += offset as u64;
                        }
                        Ok(self.offset)
                    }
                }
                io::SeekFrom::Start(start) => {
                    if start < self.size() {
                        self.offset = start;
                        Ok(self.offset)
                    } else {
                        Err(io::ErrorKind::InvalidInput.into())
                    }
                }
                io::SeekFrom::End(end) => {
                    if end.is_negative() && (-end) as u64 > self.size() {
                        Err(io::ErrorKind::InvalidInput.into())
                    } else {
                        self.offset = if end.is_negative() {
                            self.size() - ((-end) as u64)
                        } else {
                            self.size() + (end as u64)
                        };
                        Ok(self.offset)
                    }
                }
            }
        }
    }

    /// A collection of files [`deserialize`]d by [`parse`].
    #[derive(Debug)]
    pub struct Files<'a, R: Read + Seek> {
        files: Vec<File<'a, R>>,
    }
    impl<'a, R: Read + Seek> Files<'a, R> {
        /// Get all the files.
        pub fn all(&mut self) -> &mut [File<'a, R>] {
            self.files.as_mut_slice()
        }

        /// Filter through all files by path with `filter`.
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
    /// `reader` should not be buffered.
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
        let version = if read == buffer.len() {
            let value = buffer[MAGIC_NUMBER.len()..MAGIC_NUMBER.len() + 4]
                .try_into()
                .unwrap();
            u32::from_be_bytes(value)
        } else {
            return Err(Error::MetadataIncomplete);
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
            read_cell: &'a RefCell<&'a mut R>,
        ) -> Result<Files<'a, R>, Error> {
            let mut buffer = [0; 9];
            let read = read_cell
                .borrow_mut()
                .read(&mut buffer)
                .map_err(Error::Reader)?;
            if read != buffer.len() {
                return Err(Error::MetadataIncomplete);
            }

            // Header size is a u64 to support file headers above 4GBs.
            // Size not including version and magic number, but including itself.
            let header_size = u64::from_be_bytes(buffer[0..8].try_into().unwrap());
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
                if read_saturate(&mut header[..], &mut *read_cell.borrow_mut())
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
                for file in metadata::FileIterV1::new(&header, path_length_bytes, header_size) {
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
                                source: &read_cell,
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
    /// Representing `path_length_bytes`; the amount of bytes a path length is made of.
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

/// Serializes multiple objects to a single bundle.
pub mod serialize {
    use super::*;
    use std::{
        io,
        io::prelude::*,
        path::{Path, PathBuf},
    };

    /// A general error for dealing with serializing
    #[derive(Debug)]
    pub enum Error {
        /// Supplied path contains invalid UTF-8.
        /// I plan to remove this limitation in the future.
        /// See [`deserialize::Error::InvalidUTF8`]
        InvalidUTF8,
        /// An error occurred in reading data.
        Reader(io::Error),
        /// Error while writing data to the output writer.
        Writer(io::Error),
        /// Error when opening data to include in bundle.
        Open(String),
    }

    /// Will crudely walk a dir at `path`.
    ///
    /// This does not extract the metadata; it's only cheap on Windows platforms.
    /// I do not plan to change that, as this function works well with the rest of this crate.
    ///
    /// # Errors
    /// Will return any errors from [`io`] functions.
    /// This function tries to read metadata from files and view content in directories.
    pub fn walk_dir<P: AsRef<Path>, F: Fn(&Path) -> bool>(
        path: P,
        filter: &F,
    ) -> io::Result<Vec<PathBuf>> {
        fn walk<F: Fn(&Path) -> bool>(
            path: &Path,
            filter: &F,
            vec: &mut Vec<PathBuf>,
        ) -> io::Result<()> {
            let dir = path.read_dir()?;

            for file in dir {
                let file = file?;
                let file_type = file.file_type()?;
                let path = file.path();

                if file_type.is_file() {
                    if filter(&path) {
                        vec.push(path);
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

    /// Bundle data from `paths` opened using the `open` function, and used to **write** to `dest`.
    /// `open` can be used to preprocess files without using files to store temporary data; everything can be in memory.
    /// `paths` order will be the same as in the resulting bundle.
    /// `dest` should not be buffered; only large chunks are written.
    ///
    /// # Errors
    /// This function will try to read from the supplied [`Read`] from `open` function.
    /// Then it will write to `dest` and [`Write::flush()`] it.
    pub fn write<W: Write + Seek, R: Read, F: Fn(&Path) -> Result<R, Error>, P: AsRef<Path>>(
        paths: &[P],
        dest: W,
        open: F,
    ) -> Result<(), Error> {
        versions::write_v1(paths, dest, open)
    }

    /// The versions of the [`serialize`]r. Here for legacy and support over an applications lifespan.
    pub mod versions {
        use super::*;

        /// See [`write()`].
        ///
        /// # Errors
        /// See [`write()`].
        pub fn write_v1<
            W: Write + Seek,
            R: Read,
            F: Fn(&Path) -> Result<R, Error>,
            P: AsRef<Path>,
        >(
            paths: &[P],
            mut dest: W,
            open: F,
        ) -> Result<(), Error> {
            let mut metadata = Vec::with_capacity(DEFAULT_BUFFER_SIZE);

            metadata.extend_from_slice(MAGIC_NUMBER);
            let version: u32 = 1;
            metadata.extend_from_slice(&version.to_be_bytes());

            let path_length_bytes = {
                let mut longest: deserialize::UintParseType = 0;
                for path in paths {
                    let length = path.as_ref().to_str().ok_or(Error::InvalidUTF8)?.len() as u64;
                    if length > longest {
                        longest = length;
                    }
                }

                let mut shift = longest >> 8;
                let mut bytes: u8 = 1;
                loop {
                    if shift > 255 {
                        shift >>= 8;
                        bytes += 1;
                        continue;
                    } else {
                        break;
                    }
                }
                bytes
            };
            // From now, all paths are guaranteed to be valid UTF8.

            let zero_u64 = &[0; 8];

            // Header size
            metadata.extend_from_slice(zero_u64);

            // How many bytes to represent path.
            metadata.extend_from_slice(&[path_length_bytes]);

            // From start of file.
            let mut file_size_positions = Vec::with_capacity(paths.len());
            // Not UB since we're dealing with integers.
            unsafe { file_size_positions.set_len(file_size_positions.capacity()) };

            for (file, size_pos) in paths.iter().zip(file_size_positions.iter_mut()) {
                let path = file.as_ref();
                let s = path.to_str().unwrap();

                *size_pos = metadata.len();
                metadata.extend_from_slice(zero_u64);

                let path_length = (s.len() as u64).to_be_bytes();
                let path_length_bytes = &path_length[8 - path_length_bytes as usize..];

                metadata.extend_from_slice(path_length_bytes);
                metadata.extend_from_slice(s.as_bytes());
            }

            let header_offset = MAGIC_NUMBER.len() + 4;
            let header_size = (metadata.len() - header_offset) as u64;
            metadata[header_offset..header_offset + 8].copy_from_slice(&header_size.to_be_bytes());

            dest.write_all(&metadata).map_err(Error::Writer)?;

            let mut buffer = Vec::with_capacity(DEFAULT_BUFFER_SIZE);
            // Not UB since we're dealing with integers.
            unsafe { buffer.set_len(buffer.capacity()) };

            for (file, size_pos) in paths.iter().zip(file_size_positions.iter()) {
                let path = file.as_ref();
                let mut reader = open(path)?;

                let mut size = 0;

                loop {
                    let read = match reader.read(&mut buffer) {
                        Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(err) => return Err(Error::Reader(err)),
                        Ok(0) => break,
                        Ok(read) => read,
                    };

                    size += read as u64;

                    dest.write_all(&buffer[..read]).map_err(Error::Writer)?;
                }

                metadata[*size_pos..size_pos + 8].copy_from_slice(&size.to_be_bytes());
            }

            dest.seek(io::SeekFrom::Start(0)).map_err(Error::Writer)?;
            dest.write_all(&metadata).map_err(Error::Writer)?;

            dest.flush().map_err(Error::Writer)?;

            Ok(())
        }
    }
}
