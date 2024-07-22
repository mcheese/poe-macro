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

// AppUserModelId needed for notifications
//   stealing an existing one because cba to actually register as an app
//   notifications will show icon and name, so lets use something .. unassuming
const APP_ID: &'static str = "Microsoft.Windows.Shell.RunDialog";
//const APP_ID: &'static str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe";

// display error notification toast
pub fn error_toast(text1: &str, text2: &str) -> () {
    use winrt_notification::{Duration, Toast};
    Toast::new(APP_ID)
        .title("POE-Macro ERROR")
        .text1(text1)
        .text2(text2)
        .duration(Duration::Long)
        .show()
        .expect("notification failed");
}

// display error notification toast
pub fn info_toast(text1: &str, text2: &str) -> () {
    use winrt_notification::*;
    Toast::new(APP_ID)
        .title("POE-Macro")
        .text1(text1)
        .text2(text2)
        .duration(Duration::Short)
        .sound(None)
        .show()
        .expect("notification failed");
}
