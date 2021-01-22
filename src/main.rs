use std::{
    borrow::Cow,
    cell::RefCell,
    env, fs, io,
    path::{Path, PathBuf},
};

mod lib;
use lib::*;

fn main() {
    let mut args = env::args().into_iter().skip(1);
    let verb = args
        .next()
        .expect("please enter 'extract' or 'package' as the first argument");
    let path = PathBuf::from(
        args.next()
            .expect("enter a path to the file to extract or dir to package"),
    );
    let dest = args.next().map(PathBuf::from);
    match verb.as_str() {
        "extract" => extract_all(&path, dest).unwrap(),
        "package" => package_all(&path, dest).unwrap(),
        _ => panic!("please enter 'extract' or 'package' as the first argument"),
    }
}

fn extract_all<P1: AsRef<Path>, P2: AsRef<Path>>(
    path: P1,
    dest: Option<P2>,
) -> Result<(), deserialize::Error> {
    let mut file = fs::File::open(path).map_err(deserialize::Error::Reader)?;

    let ref_cell = RefCell::new(&mut file);

    for file in parse(&ref_cell)?.all() {
        let path = match dest.as_ref() {
            Some(dest) => Cow::Owned(dest.as_ref().join(file.path())),
            None => Cow::Borrowed(file.path()),
        };

        let mut dir = fs::DirBuilder::new();
        dir.recursive(true);
        dir.create(&path.with_file_name(""))
            .map_err(deserialize::Error::Reader)?;

        let mut dest = fs::File::create(&path).map_err(deserialize::Error::Reader)?;

        io::copy(file, &mut dest).map_err(deserialize::Error::Reader)?;
    }

    Ok(())
}

fn package_all<P1: AsRef<Path>, P2: AsRef<Path>>(
    dir: P1,
    dest: Option<P2>,
) -> Result<(), serialize::Error> {
    let paths = walk_dir(&dir, &|_| true).map_err(serialize::Error::Reader)?;

    let dest_path = match dest.as_ref() {
        Some(dest) => Cow::Borrowed(dest.as_ref()),
        None => Cow::Owned(dir.as_ref().with_extension("b")),
    };
    let dest = fs::File::create(&dest_path).map_err(serialize::Error::Writer)?;

    write(&paths, dest, |path| {
        fs::File::open(path).map_err(serialize::Error::Reader)
    })
}
