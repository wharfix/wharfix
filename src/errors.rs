
use std::boxed::Box;
use crate::exec::ExecErrorInfo;

#[allow(dead_code)]
pub enum ImageBuildError {
    NotFound,
    Other
}

#[derive(Debug)]
pub enum MainError {
    ArgParse(&'static str),
    ListenBind(std::io::Error),
    RepoClone(RepoError)
}

#[derive(Debug)]
pub enum RepoError {
    Exec(ExecErrorInfo),
    Git(git2::ErrorCode),
    IO(Box<dyn std::fmt::Debug>),
}

impl std::convert::From<ExecErrorInfo> for RepoError {
    fn from(err: ExecErrorInfo) -> Self {
        RepoError::Exec(err)
    }
}
