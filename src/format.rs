#[macro_export]
macro_rules! color_format_if {
    ($fmt:expr, $val:expr, $color:expr) => {
        match $val {
            true => $color(format!("{}", $fmt).as_str()),
            false => format!("{}", $fmt).normal().clear(),
        }
    };
}

#[macro_export]
macro_rules! warn_format_if {
    ($fmt:expr, $val:expr) => {
        color_format_if!($fmt, $val, colored::Colorize::yellow)
    };
}

#[macro_export]
macro_rules! alert_format_if {
    ($fmt:expr, $val:expr) => {
        color_format_if!($fmt, $val, colored::Colorize::red)
    };
}

#[macro_export]
macro_rules! warn_format {
    ($fmt:expr) => {
        color_format_if!($fmt, true, colored::Colorize::yellow)
    };
}

#[macro_export]
macro_rules! alert_format {
    ($fmt:expr) => {
        color_format_if!($fmt, true, colored::Colorize::red)
    };
}
