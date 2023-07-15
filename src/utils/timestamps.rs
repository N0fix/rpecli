use chrono::{DateTime, NaiveDateTime, Utc};

pub fn format_timestamp(timestamp: i64) -> String {
    let naive = NaiveDateTime::from_timestamp_opt(timestamp.into(), 0).unwrap();
    let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    format!(
        "{} (Timestamp: {} ({:#x}))",
        datetime.format("%Y-%m-%d %H:%M:%S"),
        timestamp as i64,
        timestamp as i64,
    )
}
