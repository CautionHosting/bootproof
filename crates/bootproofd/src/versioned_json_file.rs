use std::panic::Location;
use tracing::debug;

trait ResultExt<T> {
    type Error;

    fn with_values(
        self,
        path: impl Into<std::path::PathBuf>,
        kind: VersionedJsonFileErrorKind,
        location: &'static Location<'static>,
    ) -> Result<T, Self::Error>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: std::error::Error + 'static,
{
    type Error = VersionedJsonFileError;

    fn with_values(
        self,
        path: impl Into<std::path::PathBuf>,
        kind: VersionedJsonFileErrorKind,
        location: &'static Location<'static>,
    ) -> Result<T, Self::Error> {
        match self {
            Ok(o) => Ok(o),
            Err(e) => Err(VersionedJsonFileError {
                file: path.into(),
                source: Box::new(e),
                kind,
                location,
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
    pub location: &'static Location<'static>,
}

#[derive(Debug)]
pub struct VersionedJsonFile {
    path: std::path::PathBuf,
    modtime: std::time::SystemTime,
    data: serde_json::Value,
}

impl VersionedJsonFile {
    #[track_caller]
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, VersionedJsonFileError> {
        let path = path.as_ref();
        debug!(?path, "loading new versioned JSON file");
        let modtime = path.metadata().and_then(|m| m.modified()).with_values(
            path,
            VersionedJsonFileErrorKind::Io,
            Location::caller(),
        )?;
        let json = std::fs::read_to_string(path).with_values(
            path,
            VersionedJsonFileErrorKind::Io,
            Location::caller(),
        )?;
        Ok(Self {
            path: path.to_owned(),
            modtime,
            data: serde_json::from_str(&json).with_values(
                path,
                VersionedJsonFileErrorKind::Deserialize,
                Location::caller(),
            )?,
        })
    }

    #[track_caller]
    pub fn get(&mut self) -> Result<&serde_json::Value, VersionedJsonFileError> {
        let current_modtime = self
            .path
            .metadata()
            .and_then(|m| m.modified())
            .with_values(
                &self.path,
                VersionedJsonFileErrorKind::Io,
                Location::caller(),
            )?;

        if current_modtime > self.modtime {
            debug!(?self.path, "updating expired content");
            let json = std::fs::read_to_string(&self.path).with_values(
                &self.path,
                VersionedJsonFileErrorKind::Io,
                Location::caller(),
            )?;
            self.data = serde_json::from_str(&json).with_values(
                &self.path,
                VersionedJsonFileErrorKind::Deserialize,
                Location::caller(),
            )?;
            self.modtime = current_modtime;
        }

        Ok(&self.data)
    }
}
