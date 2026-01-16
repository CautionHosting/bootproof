use tracing::debug;

trait ResultExt<T> {
    type Error;

    fn with_path_and_kind(
        self,
        path: impl Into<std::path::PathBuf>,
        kind: VersionedJsonFileErrorKind,
    ) -> Result<T, Self::Error>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: std::error::Error + 'static,
{
    type Error = VersionedJsonFileError;

    fn with_path_and_kind(
        self,
        path: impl Into<std::path::PathBuf>,
        kind: VersionedJsonFileErrorKind,
    ) -> Result<T, Self::Error> {
        match self {
            Ok(o) => Ok(o),
            Err(e) => Err(VersionedJsonFileError {
                file: path.into(),
                source: Box::new(e),
                kind,
            }),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum VersionedJsonFileErrorKind {
    Io,
    Deserialize,
}

#[derive(Debug, thiserror::Error)]
#[error("could not read JSON file: {kind:?}")]
pub struct VersionedJsonFileError {
    #[source]
    pub source: Box<dyn std::error::Error>,
    pub kind: VersionedJsonFileErrorKind,
    pub file: std::path::PathBuf,
}

#[derive(Debug)]
pub struct VersionedJsonFile {
    path: std::path::PathBuf,
    modtime: std::time::SystemTime,
    data: serde_json::Value,
}

impl VersionedJsonFile {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, VersionedJsonFileError> {
        let path = path.as_ref();
        debug!(?path, "loading new versioned JSON file");
        let modtime = path
            .metadata()
            .and_then(|m| m.modified())
            .with_path_and_kind(path, VersionedJsonFileErrorKind::Io)?;
        let json = std::fs::read_to_string(path)
            .with_path_and_kind(path, VersionedJsonFileErrorKind::Io)?;
        Ok(Self {
            path: path.to_owned(),
            modtime,
            data: serde_json::from_str(&json)
                .with_path_and_kind(path, VersionedJsonFileErrorKind::Deserialize)?,
        })
    }

    pub fn get(&mut self) -> Result<&serde_json::Value, VersionedJsonFileError> {
        let current_modtime = self
            .path
            .metadata()
            .and_then(|m| m.modified())
            .with_path_and_kind(&self.path, VersionedJsonFileErrorKind::Io)?;

        if current_modtime > self.modtime {
            debug!(?self.path, "updating expired content");
            let json = std::fs::read_to_string(&self.path)
                .with_path_and_kind(&self.path, VersionedJsonFileErrorKind::Io)?;
            self.data = serde_json::from_str(&json)
                .with_path_and_kind(&self.path, VersionedJsonFileErrorKind::Deserialize)?;
            self.modtime = current_modtime;
        }

        Ok(&self.data)
    }
}
