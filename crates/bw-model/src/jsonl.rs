use std::{
    io::{BufRead, Read},
    marker::PhantomData,
    path::PathBuf,
};

use serde::de::DeserializeOwned;

use crate::ModelError;

/// 附带来源路径和物理行号的一条已解析记录。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Located<T> {
    pub path: PathBuf,
    pub line: usize,
    pub value: T,
}

/// 有单行上限、逐行反序列化且不读取整个文件的 JSONL reader。
pub struct JsonlReader<R, T> {
    reader: R,
    path: PathBuf,
    max_line_bytes: usize,
    physical_line: usize,
    buffer: Vec<u8>,
    finished: bool,
    marker: PhantomData<T>,
}

impl<R, T> JsonlReader<R, T>
where
    R: BufRead,
{
    #[must_use]
    pub fn new(reader: R, path: PathBuf, max_line_bytes: usize) -> Self {
        Self {
            reader,
            path,
            max_line_bytes,
            physical_line: 0,
            buffer: Vec::new(),
            finished: false,
            marker: PhantomData,
        }
    }

    fn read_physical_line(&mut self) -> Result<usize, ModelError> {
        self.buffer.clear();
        let read_limit = self.max_line_bytes.saturating_add(2) as u64;
        let mut limited = (&mut self.reader).take(read_limit);
        limited
            .read_until(b'\n', &mut self.buffer)
            .map_err(|error| ModelError::io("读取 JSONL", error))
    }

    fn strip_line_ending(&mut self) {
        if self.buffer.last() == Some(&b'\n') {
            self.buffer.pop();
            if self.buffer.last() == Some(&b'\r') {
                self.buffer.pop();
            }
        }
    }
}

impl<R, T> Iterator for JsonlReader<R, T>
where
    R: BufRead,
    T: DeserializeOwned,
{
    type Item = Result<Located<T>, ModelError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        loop {
            let next_line = self.physical_line + 1;
            let bytes_read = match self.read_physical_line() {
                Ok(bytes_read) => bytes_read,
                Err(error) => {
                    self.finished = true;
                    return Some(Err(error.at_line(self.path.clone(), next_line)));
                }
            };
            if bytes_read == 0 {
                self.finished = true;
                return None;
            }

            self.physical_line = next_line;
            self.strip_line_ending();
            if self.buffer.len() > self.max_line_bytes {
                self.finished = true;
                return Some(Err(ModelError::LineTooLong {
                    max_bytes: self.max_line_bytes,
                    observed_at_least: self.buffer.len(),
                }
                .at_line(self.path.clone(), self.physical_line)));
            }
            if self.buffer.is_empty() {
                continue;
            }

            let value = match serde_json::from_slice(&self.buffer) {
                Ok(value) => value,
                Err(error) => {
                    self.finished = true;
                    return Some(Err(ModelError::InvalidJson(error)
                        .at_line(self.path.clone(), self.physical_line)));
                }
            };
            return Some(Ok(Located {
                path: self.path.clone(),
                line: self.physical_line,
                value,
            }));
        }
    }
}
