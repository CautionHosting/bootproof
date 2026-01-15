trait ResultExt<T> {
    type Error;

    fn with_path_and_kind(
        self,
        path: impl Into<std::path::PathBuf>,
        kind: ErrorKind,
    ) -> Result<T, Self::Error>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: std::error::Error + 'static,
{
    type Error = Error;

    fn with_path_and_kind(
        self,
        path: impl Into<std::path::PathBuf>,
        kind: ErrorKind,
    ) -> Result<T, Self::Error> {
        match self {
            Ok(o) => Ok(o),
            Err(e) => Err(Error {
                file: path.into(),
                source: Box::new(e),
                kind,
            }),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    Io,
    Deserialize,
}

#[derive(Debug, thiserror::Error)]
#[error("Could not read JSON file: {kind:?}")]
pub struct Error {
    #[source]
    pub source: Box<dyn std::error::Error>,
    pub kind: ErrorKind,
    pub file: std::path::PathBuf,
}

#[derive(Debug)]
pub struct VersionedJsonFile {
    path: std::path::PathBuf,
    modtime: std::time::SystemTime,
    data: serde_json::Value,
}

impl VersionedJsonFile {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let modtime = path
            .metadata()
            .and_then(|m| m.modified())
            .with_path_and_kind(path, ErrorKind::Io)?;
        let json = std::fs::read_to_string(path).with_path_and_kind(path, ErrorKind::Io)?;
        Ok(Self {
            path: path.to_owned(),
            modtime,
            data: serde_json::from_str(&json).with_path_and_kind(path, ErrorKind::Deserialize)?,
        })
    }

    pub fn get(&mut self) -> Result<&serde_json::Value, Error> {
        let current_modtime = self
            .path
            .metadata()
            .and_then(|m| m.modified())
            .with_path_and_kind(&self.path, ErrorKind::Io)?;

        if current_modtime > self.modtime {
            let json = std::fs::read_to_string(&self.path)
                .with_path_and_kind(&self.path, ErrorKind::Io)?;
            self.data = serde_json::from_str(&json)
                .with_path_and_kind(&self.path, ErrorKind::Deserialize)?;
            self.modtime = current_modtime;
        }

        Ok(&self.data)
    }
}
