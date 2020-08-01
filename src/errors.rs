
#[allow(dead_code)]
pub enum ImageBuildError {
    NotFound,
    Other
}

#[derive(Debug)]
pub enum MainError {
    ArgParseError(&'static str),
    ListenBindError(std::io::Error),
}
