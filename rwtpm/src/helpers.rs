use std::fmt::Write;
pub fn slice_to_hex_string(slice: &[u8]) -> String {
    slice.iter().fold(String::new(), |mut output, b| {
        write!(output, "{b:02x}").unwrap();
        output
    })
}
