use std::{
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapperInvocation {
    pub real_rustc: PathBuf,
    pub rustc_args: Vec<OsString>,
    pub crate_name: Option<String>,
    pub target: String,
}

impl WrapperInvocation {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, ArgsError> {
        let mut args = args.into_iter();
        let _program = args.next().ok_or(ArgsError::MissingProgram)?;
        let real_rustc = args.next().ok_or(ArgsError::MissingRealRustc)?;
        let rustc_args = args.collect::<Vec<_>>();
        let crate_name = optional_value_arg(&rustc_args, "--crate-name")?;
        let target = optional_first_value_arg(&rustc_args, "--crate-type")
            .unwrap_or_else(|| "unknown".to_owned());
        Ok(Self {
            real_rustc: PathBuf::from(real_rustc),
            rustc_args,
            crate_name,
            target,
        })
    }

    #[must_use]
    pub fn driver_args(&self) -> Vec<String> {
        let mut args = Vec::with_capacity(self.rustc_args.len() + 1);
        args.push(path_to_string(&self.real_rustc));
        args.extend(self.rustc_args.iter().map(os_to_string_lossy));
        args
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgsError {
    MissingProgram,
    MissingRealRustc,
    DuplicateArg(&'static str),
}

impl fmt::Display for ArgsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProgram => formatter.write_str("wrapper argv 缺少程序名"),
            Self::MissingRealRustc => formatter.write_str("wrapper argv 缺少真实 rustc 路径"),
            Self::DuplicateArg(name) => write!(formatter, "rustc 参数重复出现 {name}"),
        }
    }
}

impl std::error::Error for ArgsError {}

fn optional_value_arg(args: &[OsString], name: &'static str) -> Result<Option<String>, ArgsError> {
    let mut found = None;
    let prefix = format!("{name}=");
    let mut index = 0;
    while index < args.len() {
        let current = os_to_string_lossy(&args[index]);
        let value = if current == name {
            index += 1;
            args.get(index).map(os_to_string_lossy)
        } else {
            current.strip_prefix(&prefix).map(ToOwned::to_owned)
        };
        if let Some(value) = value
            && found.replace(value).is_some()
        {
            return Err(ArgsError::DuplicateArg(name));
        }
        index += 1;
    }
    Ok(found)
}

fn optional_first_value_arg(args: &[OsString], name: &'static str) -> Option<String> {
    let prefix = format!("{name}=");
    let mut index = 0;
    while index < args.len() {
        let current = os_to_string_lossy(&args[index]);
        let value = if current == name {
            index += 1;
            args.get(index).map(os_to_string_lossy)
        } else {
            current.strip_prefix(&prefix).map(ToOwned::to_owned)
        };
        if value.is_some() {
            return value;
        }
        index += 1;
    }
    None
}

fn os_to_string_lossy(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

fn path_to_string(value: &Path) -> String {
    value.to_string_lossy().into_owned()
}
