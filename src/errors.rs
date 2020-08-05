
use std::boxed::Box;

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
    Git(Box<dyn std::fmt::Debug>),
    IO(Box<dyn std::fmt::Debug>),
}
