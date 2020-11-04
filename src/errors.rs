
use std::boxed::Box;
use std::fmt::Display;
use crate::exec::ExecErrorInfo;

use serde::Serialize;

use crate::log;

#[allow(dead_code)]
pub enum ImageBuildError {
    NotFound,
    Other
}

#[derive(Debug)]
pub enum MainError {
    ArgParse(&'static str),
    ListenBind(std::io::Error),
    //RepoClone(RepoError)
}

#[derive(Debug)]
pub enum RepoError {
    Exec(ExecErrorInfo),
    Git(git2::ErrorCode),
    IO(Box<dyn std::fmt::Debug>),
}

impl Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoError::Exec(_) => write!(f, "nix build exec error"),
            RepoError::Git(_) => write!(f, "git error"),
            RepoError::IO(_) => write!(f, "IO error")
        }

    }
}

#[derive(Debug, Serialize)]
pub enum DockerErrorCode {
    #[serde(rename = "BLOB_UNKNOWN")]
    BlobUnknown,
    #[serde(rename = "MANIFEST_UNKNOWN")]
    ManifestUnknown,
    #[serde(rename = "NAME_UNKNOWN")]
    NameUnknown,
    #[serde(rename = "NAME_INVALID")]
    NameInvalid,
    #[serde(rename = "SNAFU")]
    Snafu
}

#[derive(Debug, Serialize)]
pub struct DockerError {
    code: DockerErrorCode,
    message: String,
    details: String,
}

pub trait DockerErrorContext {
    fn manifest_context(self) -> DockerError;
    fn blob_context(self) -> DockerError;

}

pub trait DockerErrorDetails {
    fn to_docker_error(&self, code: DockerErrorCode) -> DockerError;
    fn docker_message(&self) -> String;
    fn docker_details(&self) -> String;
}

impl DockerErrorDetails for std::io::Error {
    fn to_docker_error(&self, code: DockerErrorCode) -> DockerError {
        DockerError {
            code,
            message: self.docker_message(),
            details: self.docker_details(),
        }
    }
    fn docker_message(&self) -> String {
        "".to_string()
    }
    fn docker_details(&self) -> String {
        "".to_string()
    }
}

impl DockerErrorDetails for RepoError {
    fn to_docker_error(&self, code: DockerErrorCode) -> DockerError {
        DockerError {
            code,
            message: self.docker_message(),
            details: self.docker_details(),
        }
    }
    fn docker_message(&self) -> String {
        match self {
            RepoError::Git(git2::ErrorCode::NotFound) => "git ref not found",
            RepoError::Git(_) => "unknown git error",
            _ => "unknown error"
        }.to_string()
    }
    fn docker_details(&self) -> String {
        "debug help".to_string()
    }
}


impl<T> DockerErrorContext for T where T: DockerErrorDetails {
    fn manifest_context(self) -> DockerError {
        self.to_docker_error(DockerErrorCode::ManifestUnknown)
    }
    fn blob_context(self) -> DockerError {
        self.to_docker_error(DockerErrorCode::BlobUnknown)
    }
}

impl DockerError {
    pub fn repository_unknown() -> Self {
        let message = "repository name not known to registry".to_string();
        DockerError {
            code: DockerErrorCode::NameUnknown,
            details: message.clone(),
            message
        }
    }
    pub fn blob_unknown(digest: &str) -> Self {
        DockerError {
            code: DockerErrorCode::BlobUnknown,
            message: "blob unknown to registry".to_string(),
            details: (json!({ "digest": digest })).to_string()
        }
    }
    pub fn snafu(text: &str) -> Self {
        DockerError {
            code: DockerErrorCode::Snafu,
            message: text.to_string(),
            details: text.to_string()
        }
    }
    pub fn unknown<E: std::fmt::Debug>(text: &str, err: E) -> Self {
        log::error(text, &err);
        DockerError {
            code: DockerErrorCode::Snafu,
            message: text.to_string(),
            details: text.to_string()
        }
    }
    pub fn repository_name_malformed() -> Self {
        let message = "repository name malformed".to_string();
        DockerError {
            code: DockerErrorCode::NameInvalid,
            details: message.clone(),
            message
        }
    }
}

impl std::convert::Into<actix_web::error::Error> for DockerError {
    fn into(self) -> actix_web::error::Error {
        use actix_web::web::HttpResponse;
        let errors = vec!(self);
        let errors = json!({ "errors": errors });
        HttpResponse::NotFound()
            .header("Docker-Distribution-API-Version", "registry/2.0")
            .json(errors)
            .into()
    }
}

impl std::convert::From<ExecErrorInfo> for RepoError {
    fn from(err: ExecErrorInfo) -> Self {
        RepoError::Exec(err)
    }
}


impl std::convert::From<RepoError> for actix_web::error::Error {
    fn from(_err: RepoError) -> Self {
        actix_web::error::ErrorInternalServerError("repo error")
    }
}

impl std::convert::From<git2::Error> for RepoError {
    fn from(err: git2::Error) -> Self {
        RepoError::Git(err.code())
    }
}
