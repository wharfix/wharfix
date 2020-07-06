
extern crate time;
extern crate serde;
extern crate erased_serde;

use std::cell::RefCell;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::option::Option;
use std::default::Default;
use uuid::Uuid;
use std::fmt::Debug;

#[derive(Serialize, Debug)]
pub enum LogLevel {
    INFO,
    #[allow(dead_code)]
    ERROR
}

#[derive(Debug)]
pub struct Time {
    pub timestamp: time::Tm
}

#[derive(Default)]
pub struct LogEntry<'se> {
    pub level: LogLevel,
    pub timestamp: Time,
    pub message: &'se str,
    pub data: Option<&'se dyn erased_serde::Serialize>,
    pub error: Option<&'se dyn Debug>,
}

thread_local! {
    static REQ_ID: RefCell<Uuid> = RefCell::new(Uuid::nil());
}

pub fn new_request() {
    REQ_ID.with(|uuid| {
        *uuid.borrow_mut() = Uuid::new_v4();
    });
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::INFO
    }
}

impl Default for Time {
    fn default() -> Self {
        Time{
            timestamp: time::now_utc()
        }
    }
}

impl Serialize for LogEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut s = serializer.serialize_struct("LogEntry", 8)?;
        //2016-07-25T17:22:40.835692521+02:00, 2016-07-25T17:22:40.835Z
        s.serialize_field("timestamp", &self.timestamp.timestamp.rfc3339().to_string())?;
        s.serialize_field("app", "wharfix")?;
        s.serialize_field("level", &self.level)?;
        s.serialize_field("message", &self.message)?;
        s.serialize_field("requestid", &REQ_ID.with(|uuid| {
            uuid.borrow().to_string()
        }))?;
        if self.data.is_some() {
            s.serialize_field("data", &self.data.unwrap())?;
        }
        if self.error.is_some() {
            s.serialize_field("error", &format!("{:?}", self.error.unwrap()))?;
        }
        s.end()
    }
}

fn log(entry: LogEntry) {
    println!("{}", serde_json::to_string(&entry).unwrap());
}


pub fn info(message: &str) {
    log(LogEntry{
        level: LogLevel::INFO,
        message,
        ..Default::default()
    });
}

pub fn data<T>(message: &str, data: &T) where T: Serialize {
    log(LogEntry{
        level: LogLevel::INFO,
        message,
        data: Some(data),
        ..Default::default()
    });
}

#[allow(dead_code)]
pub fn error<E>(message: &str, error: &E) where E: Debug {
    log(LogEntry{
        level: LogLevel::ERROR,
        message,
        error: Some(error),
        ..Default::default()
    });
}
