// some helper functions

// generic return type with boxed error
//pub type MyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// exit with notification on error
macro_rules! report_error {
    ($e:expr) => {
        if let Err(err) = $e {
            error_and_exit(
                err.to_string(),
                format!(
                    "in: {} @ {}:{}:{}",
                    stringify!($e),
                    file!(),
                    line!(),
                    column!()
                ),
            );
        } else {
        }
    };
}
pub(crate) use report_error;

// display notification and exit
pub fn error_and_exit(text1: String, text2: String) -> () {
    use winrt_notification::{Duration, Toast};
    Toast::new(Toast::POWERSHELL_APP_ID)
        .title("POE-Macro Error")
        .text1(text1.as_str())
        .text2(text2.as_str())
        .duration(Duration::Long)
        .show()
        .expect("notification failed");

    std::process::exit(-1);
}
