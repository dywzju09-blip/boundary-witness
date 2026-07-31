use std::{
    fmt,
    path::{Path, PathBuf},
};

use bw_model::{SemanticSiteKey, SiteId};
use sha2::{Digest, Sha256};

use crate::path_remap::stable_relative_path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteRole {
    Object,
    Callback,
    CallbackUserDataReconstruction,
    Capture,
    Drop,
    DropPrevention,
    Registration,
    RawPointerTransfer,
    ReleasePathProof,
    CallbackReleaseUseOrder,
    CallbackLifetimeBound,
    RegistrationGuard,
    ExternalCall,
    BorrowSource,
    ReturnedBorrow,
    ReturnedBorrowRelation,
    PersistedReturnedBorrow,
    ReturnedBorrowInvalidationOrder,
    ReturnedBorrowInvalidation,
    ReturnedBorrowStorage,
    ReturnedBorrowUse,
    ExternalBuffer,
    ExternalBufferBinding,
    AtomicOrdering,
    ObjectBindingGap,
    ObjectFlow,
}

impl SiteRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Callback => "callback",
            Self::CallbackUserDataReconstruction => "callback_user_data_reconstruction",
            Self::Capture => "capture",
            Self::Drop => "drop",
            Self::DropPrevention => "drop_prevention",
            Self::Registration => "registration",
            Self::RawPointerTransfer => "raw_pointer_transfer",
            Self::ReleasePathProof => "release_path_proof",
            Self::CallbackReleaseUseOrder => "callback_release_use_order",
            Self::CallbackLifetimeBound => "callback_lifetime_bound",
            Self::RegistrationGuard => "registration_guard",
            Self::ExternalCall => "external_call",
            Self::BorrowSource => "borrow_source",
            Self::ReturnedBorrow => "returned_borrow",
            Self::ReturnedBorrowRelation => "returned_borrow_relation",
            Self::PersistedReturnedBorrow => "persisted_returned_borrow",
            Self::ReturnedBorrowInvalidationOrder => "returned_borrow_invalidation_order",
            Self::ReturnedBorrowInvalidation => "returned_borrow_invalidation",
            Self::ReturnedBorrowStorage => "returned_borrow_storage",
            Self::ReturnedBorrowUse => "returned_borrow_use",
            Self::ExternalBuffer => "external_buffer",
            Self::ExternalBufferBinding => "external_buffer_binding",
            Self::AtomicOrdering => "atomic_ordering",
            Self::ObjectBindingGap => "object_binding_gap",
            Self::ObjectFlow => "object_flow",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteDescriptor {
    package: String,
    target: String,
    def_path: String,
    role: SiteRole,
    source_path: PathBuf,
    repo_root: Option<PathBuf>,
    mir_location: Option<String>,
    capture_ordinal: Option<u32>,
    span: Option<String>,
}

impl SiteDescriptor {
    #[must_use]
    pub fn new(
        package: impl Into<String>,
        target: impl Into<String>,
        def_path: impl Into<String>,
        role: SiteRole,
        source_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            package: package.into(),
            target: target.into(),
            def_path: def_path.into(),
            role,
            source_path: source_path.into(),
            repo_root: None,
            mir_location: None,
            capture_ordinal: None,
            span: None,
        }
    }

    #[must_use]
    pub fn with_repo_root(mut self, repo_root: impl Into<PathBuf>) -> Self {
        self.repo_root = Some(repo_root.into());
        self
    }

    #[must_use]
    pub fn with_mir_location(mut self, mir_location: impl Into<String>) -> Self {
        self.mir_location = Some(mir_location.into());
        self
    }

    #[must_use]
    pub fn with_capture_ordinal(mut self, capture_ordinal: u32) -> Self {
        self.capture_ordinal = Some(capture_ordinal);
        self
    }

    #[must_use]
    pub fn with_span(mut self, span: impl Into<String>) -> Self {
        self.span = Some(span.into());
        self
    }

    #[must_use]
    pub fn site_id(&self) -> SiteId {
        self.try_site_id()
            .expect("site descriptor should be valid for site_id")
    }

    pub fn try_site_id(&self) -> Result<SiteId, SiteIdentityError> {
        let relative_path = stable_relative_path(&self.source_path, self.repo_root.as_deref())?;
        reject_absolute_marker("span", self.span.as_deref())?;
        let fields = [
            ("package", self.package.as_str()),
            ("target", self.target.as_str()),
            ("def_path", self.def_path.as_str()),
            (
                "mir_location",
                self.mir_location.as_deref().unwrap_or("<none>"),
            ),
            ("role", self.role.as_str()),
            ("capture_ordinal", &ordinal_value(self.capture_ordinal)),
            ("relative_path", &relative_path),
            ("span", self.span.as_deref().unwrap_or("<none>")),
        ];
        Ok(SiteId::from(format!("site:{}", stable_digest(&fields))))
    }

    #[must_use]
    pub fn semantic_key(&self) -> SemanticSiteKey {
        let fields = [
            ("package", self.package.as_str()),
            ("target", self.target.as_str()),
            ("def_path", self.def_path.as_str()),
            ("role", self.role.as_str()),
            ("capture_ordinal", &ordinal_value(self.capture_ordinal)),
        ];
        SemanticSiteKey::from(format!("semantic:{}", stable_digest(&fields)))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SiteIdentityError {
    AbsolutePath { path: PathBuf },
    EmptyRelativePath,
    NonUtf8Path,
    AbsoluteMarker { field: &'static str, value: String },
}

impl fmt::Display for SiteIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbsolutePath { path } => {
                write!(
                    formatter,
                    "absolute path cannot enter site identity: {}",
                    path.display()
                )
            }
            Self::EmptyRelativePath => formatter.write_str("relative path is empty"),
            Self::NonUtf8Path => formatter.write_str("path is not valid UTF-8"),
            Self::AbsoluteMarker { field, value } => {
                write!(
                    formatter,
                    "{field} contains absolute path marker and cannot enter site identity: {value}"
                )
            }
        }
    }
}

impl std::error::Error for SiteIdentityError {}

fn stable_digest(fields: &[(&str, &str)]) -> String {
    let mut hasher = Sha256::new();
    for (label, value) in fields {
        hash_str(&mut hasher, label);
        hash_str(&mut hasher, value);
    }
    hex_lower(&hasher.finalize())
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn ordinal_value(value: Option<u32>) -> String {
    value
        .map(|ordinal| ordinal.to_string())
        .unwrap_or_else(|| "<none>".to_owned())
}

fn reject_absolute_marker(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), SiteIdentityError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.starts_with('/') || value.contains("://") || Path::new(value).is_absolute() {
        return Err(SiteIdentityError::AbsoluteMarker {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
