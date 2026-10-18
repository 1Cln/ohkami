#![cfg(feature = "__rt_native__")]

use std::{fs::File, io};
use std::borrow::Cow;
use std::path::PathBuf;
use crate::{Ohkami, Path, Response, Route};

pub struct ServeDir {
    pub(super) dir_path: PathBuf,

    /*=== config ===*/
    pub(super) serve_dotfiles: bool,
    pub(super) omit_extensions: &'static [&'static str],
    pub(super) etag: Option<fn(&File) -> String>,
}

impl ServeDir {
    pub fn new(path: impl Into<Cow<'static, str>>) -> io::Result<Self> {
        let dir_path = Self::init_dir(&path)
            .unwrap_or_else(|_| panic!("invalid path to serve: `{}`", path.as_ref().display()));

        Self {
            dir_path,
            serve_dotfiles: false,
            omit_extensions: &[],
            etag: None,
        }
    }

    pub(crate) fn init_dir(path: &impl AsRef<std::path::Path>) -> io::Result<Self> {
        let path = path.into().canonicalize()?;

        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound, format!("{} doesn't exist", path.display())
            ));
        }

        if !path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory, format!("{} is not a directory", path.display())
            ));
        }

        Ok(path)
    }

    pub(crate) fn serve_file(&self, Path(file): Path<&str>) -> Response {
        let relative_path = self.dir_path.with_file_name(file);
        if let Ok(file) = File::open(relative_path) {
            let mime = file;
            Response::OK().with_payload(
                "image/jpeg",
                read(file)
            )
        } else {
            Response::NotFound()
        }
    }
}

impl Into<Ohkami> for ServeDir {
    fn into(self) -> Ohkami {
        Ohkami::new(
            self.dir_path.as_path().GET(self.serve_file)
        )
    }
}

fn read(mut file: File) -> io::Result<Vec<u8>> {
    let mut content = vec![0; file.metadata()?.len() as usize];
    io::Read::read_exact(&mut file, &mut content)?;
    Ok(content)
}

fn cmp_size(f: &File, g: &File) -> std::cmp::Ordering {
    u64::cmp(
        &f.metadata().map(|m| m.len()).unwrap_or(u64::MAX),
        &g.metadata().map(|m| m.len()).unwrap_or(u64::MAX),
    )
}

fn modified_unix_timestamp(file: &File) -> io::Result<u64> {
    let ts = file
        .metadata()?
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Ok(ts)
}