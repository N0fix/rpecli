#[macro_export]
macro_rules! color_format {
    ($fmt:expr, $val:expr, $color:expr) => {
        match $val {
            true => $color(format!("{}", $fmt).as_str()),
            false => format!("{}", $fmt).normal().clear(),
        }
    };
}

#[macro_export]
macro_rules! warn_format {
    ($fmt:expr, $val:expr) => {
        color_format!($fmt, $val, colored::Colorize::yellow)
    };
}

#[macro_export]
macro_rules! alert_format {
    ($fmt:expr, $val:expr) => {
        color_format!($fmt, $val, colored::Colorize::red)
    };
}