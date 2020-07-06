use std::process::{Command, Child, Output};
use std::error::Error;
use serde::export::fmt::Debug;
use std::{fmt, mem};
use std::io::Write;
use std::process::Stdio;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde::de::DeserializeOwned;


#[derive(Debug)]
pub struct CommandWrapped<'l> {
    command: &'l mut Command,
    child: Option<Child>
}

#[derive(Debug)]
pub struct ExecErrorInfo {
    error: Box<dyn Error>,
    trace: String,
    output: Option<Box<Output>>,
}

#[derive(Debug)]
pub enum ExecError {
    NonZeroExitCode(i32),
    UnknownExitStatus,
    FailedToOpenStdin,
    ChildUnavailable,
    UnknownError
}

impl Serialize for ExecErrorInfo {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let mut s = serializer.serialize_struct("ExecErrorInfo", 4)?;
        s.serialize_field("error", &format!("{}", &self.error))?;
        if !self.trace.is_empty() {
            println!("Not empty");
            s.serialize_field("trace", &self.trace)?;
        }
        if self.output.is_some() {
            let o = self.output.as_ref().unwrap();
            unsafe {
                s.serialize_field("stdout", &String::from_utf8_unchecked((*o.stdout).to_vec()))?;
                s.serialize_field("stderr", &String::from_utf8_unchecked((*o.stderr).to_vec()))?;
            }
        }
        s.end()
    }
}

impl std::error::Error for ExecErrorInfo {

}

impl std::error::Error for ExecError {

}

impl fmt::Display for ExecErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: {:?}", self.error)?;
        if !self.trace.is_empty() {
            Ok(write!(f, "trace: {}", self.trace)?)
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl ExecErrorInfo {
    fn new<E, D>(err: E, trace: &D, output: Option<Box<Output>>) -> ExecErrorInfo where E: 'static + Error, D: Debug {
        ExecErrorInfo {
            error: Box::new(err),
            trace: format!("{:?}", &trace),
            output
        }
    }
}

impl CommandWrapped<'_> {
    fn new<'l>(command: &'l mut Command, child: Child) -> CommandWrapped<'l> {
        CommandWrapped {
            command,
            child: Some(child)
        }
    }
}

pub trait SpawnOk {
    fn spawn_ok<'s>(&'s mut self) -> Result<CommandWrapped<'s>, ExecErrorInfo>;
}

impl SpawnOk for Command {
    fn spawn_ok<'s>(&'s mut self) -> Result<CommandWrapped<'s>, ExecErrorInfo> {
        self.stdout(Stdio::piped()).stderr(Stdio::piped());
        match self.spawn() {
            Ok(c) => Ok(CommandWrapped::new(self, c)),
            Err(err) => Err(ExecErrorInfo::new(err, &String::new(), None))
        }
    }
}

pub trait OpenStdin {
    fn stdin_write(&mut self, content: &String) -> Result<(), ExecErrorInfo>;
}

impl OpenStdin for CommandWrapped<'_> {
    fn stdin_write(&mut self, content: &String) -> Result<(), ExecErrorInfo> {
        let child = match self.child.as_mut() {
            Some(c) => Ok(c),
            None => Err(ExecErrorInfo::new(ExecError::ChildUnavailable, &String::from("child process unavailable, perhaps already captured/closed?"), None))
        }?;
        let i = match child.stdin.as_mut() {
            Some(i) => Ok(i),
            None => Err(ExecErrorInfo::new(ExecError::FailedToOpenStdin, &content, None))
        }?;

        match i.write_all(content.as_bytes()) {
            Ok(_) =>  Ok(()),
            Err(e) => Err(ExecErrorInfo::new(e, &content, None))
        }
    }
}

pub trait Wait {
    fn wait(&mut self) -> Result<(), ExecErrorInfo>;
    fn wait_for_output(&mut self) -> Result<Output, ExecErrorInfo>;
    fn output_json<T>(&mut self) -> Result<T, ExecErrorInfo> where T: DeserializeOwned;
}

impl Wait for CommandWrapped<'_> {
    fn wait(&mut self) -> Result<(), ExecErrorInfo> {
        self.wait_for_output().and(Ok(()))
    }

    fn wait_for_output(&mut self) -> Result<Output, ExecErrorInfo> {
        // this now moves "child" out of the CommandWrapped struct, ownership is transferred to "wait_with_output" and child cannot be accessed later
        let child = match mem::replace(&mut self.child, None) {
            Some(c) => Ok(c),
            None => Err(ExecErrorInfo::new(ExecError::ChildUnavailable, &String::from("child process unavailable, perhaps already captured/closed?"), None))
        }?;
        let output = child.wait_with_output();
        match output {
            Ok(out) => match out.status.code() {
                Some(code) => if code == 0 {
                        Ok(out)
                    } else {
                        Err(ExecErrorInfo::new(ExecError::NonZeroExitCode(code), &String::new(), Some(Box::new(out))))
                    },
                None => Err(ExecErrorInfo::new(ExecError::UnknownExitStatus, &String::new(), Some(Box::new(out))))
            },
            Err(err) => Err(ExecErrorInfo::new(ExecError::UnknownError, &format!("{:?}", err), None))
        }
    }

    fn output_json<'l, T>(&mut self) -> Result<T, ExecErrorInfo> where T: DeserializeOwned {
        let out = self.wait_for_output()?;
        //yuk memcopy below, but from_utf8() needs ownership, for some reason
        let s = match String::from_utf8(out.stdout.clone()) {
            Ok(s) => Ok(s),
            Err(e) => Err(ExecErrorInfo::new(e, &out, None))
        }?;
        let res: Result<T, serde_json::Error> = serde_json::from_str(&s);
        match res {
            Ok(s) => Ok(s),
            Err(e) => Err(ExecErrorInfo::new(e, &out, None))
        }
    }
}
