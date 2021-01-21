use std::{env, path::PathBuf};

mod lib;

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
        "extract" => lib::extract::all(&path, dest.as_ref()).unwrap(),
        "package" => {
            lib::package::package_latest(&path, dest.as_ref().unwrap_or(&path.with_extension("b")))
                .unwrap()
        }
        _ => panic!("please enter 'extract' or 'package' as the first argument"),
    }
}
