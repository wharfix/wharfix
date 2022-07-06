
use std::boxed::Box;
use crate::exec::ExecErrorInfo;
use crate::FetchInfo;

use serde::Serialize;
use serde_json::json;
use actix_web::HttpResponse;
use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::ResponseError;

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
    Git(git2::Error),
    IndexFile(std::io::Error),
    ImageNotFound,
    BlobNotFound,
    ImageReferenceMalformed,
    IndexAttributeNotFound,
    IO(Box<dyn std::fmt::Debug>),
}

#[derive(Debug, Serialize)]
pub enum DockerErrorCode {
    #[serde(rename = "BLOB_UNKNOWN")]
    BlobUnknown,
    #[serde(rename = "MANIFEST_UNKNOWN")]
    ManifestUnknown,
    #[cfg(feature = "mysql")]
    #[serde(rename = "NAME_UNKNOWN")]
    NameUnknown,
    #[cfg(feature = "mysql")]
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
    fn manifest_context(self, info: &FetchInfo) -> DockerError;
    fn blob_context(self, info: &FetchInfo) -> DockerError;

}

pub trait DockerErrorDetails {
    fn to_docker_error(&self, info: &FetchInfo, code: DockerErrorCode) -> DockerError;
    fn docker_message(&self, info: &FetchInfo) -> String;
    fn docker_details(&self) -> String;
}

impl DockerErrorDetails for std::io::Error {
    fn to_docker_error(&self, info: &FetchInfo, code: DockerErrorCode) -> DockerError {
        DockerError {
            code,
            message: self.docker_message(&info),
            details: self.docker_details(),
        }
    }
    fn docker_message(&self, _info: &FetchInfo) -> String {
        "".to_string()
    }
    fn docker_details(&self) -> String {
        "".to_string()
    }
}

impl DockerErrorDetails for RepoError {
    fn to_docker_error(&self, info: &FetchInfo, code: DockerErrorCode) -> DockerError {
        DockerError {
            code,
            message: self.docker_message(&info),
            details: self.docker_details(),
        }
    }
    fn docker_message(&self, info: &FetchInfo) -> String {
        match self {
            RepoError::Git(e) => if e.code() == git2::ErrorCode::NotFound {
                format!("git ref: {} not found", &info.reference)
            } else {
                "unknown git error".to_string()
            }
            RepoError::IndexFile(_) => "failed to read repository index file: /default.nix".to_string(),
            RepoError::IndexAttributeNotFound => format!("attribute: {} not found in repository index: /default.nix", &info.name),
            RepoError::ImageNotFound => format!("image with name: {} and reference: {} not found", &info.reference, &info.name),
            RepoError::BlobNotFound => format!("blob: {} not found for image: {}", &info.reference, &info.name),
            _ => "unknown error".to_string()
        }
    }
    fn docker_details(&self) -> String {
        "debug help".to_string()
    }
}


impl<T> DockerErrorContext for T where T: DockerErrorDetails {
    fn manifest_context(self, info: &FetchInfo) -> DockerError {
        self.to_docker_error(info, DockerErrorCode::ManifestUnknown)
    }
    fn blob_context(self, info: &FetchInfo) -> DockerError {
        self.to_docker_error(info, DockerErrorCode::BlobUnknown)
    }
}

impl DockerError {
    #[cfg(feature = "mysql")]
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
    #[cfg(feature = "mysql")]
    pub fn repository_name_malformed() -> Self {
        let message = "repository name malformed".to_string();
        DockerError {
            code: DockerErrorCode::NameInvalid,
            details: message.clone(),
            message
        }
    }
}

impl std::fmt::Display for DockerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ResponseError for DockerError {
    fn status_code(&self) -> StatusCode {
        StatusCode::NOT_FOUND
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let errors = vec!(self);
        let errors = json!({ "errors": errors });
        HttpResponse::NotFound()
            .append_header(("Docker-Distribution-API-Version", "registry/2.0"))
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
        RepoError::Git(err)
    }
}
