// some helper functions

// generic return type with boxed error
pub type MyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// exit with notification on error
macro_rules! exit_on_error {
    ($e:expr) => {
        if let Err(err) = $e {
            error_toast(
                err.to_string().as_str(),
                format!(
                    "in: {} @ {}:{}:{}",
                    stringify!($e),
                    file!(),
                    line!(),
                    column!()
                )
                .as_str(),
            );
            std::process::exit(-1);
        } else {
        }
    };
}
pub(crate) use exit_on_error;

// display notification toast
pub fn error_toast(text1: &str, text2: &str) -> () {
    use winrt_notification::{Duration, Toast};
    Toast::new(Toast::POWERSHELL_APP_ID)
        .title("POE-Macro Error")
        .text1(text1)
        .text2(text2)
        .duration(Duration::Long)
        .show()
        .expect("notification failed");
}
