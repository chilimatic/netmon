//! Cleaning of untrusted strings before they reach the terminal.

/// Replaces control characters and invisible Unicode format characters
/// (bidi overrides, zero-width chars) with `?`. Process names come from
/// `prctl(PR_SET_NAME)` and DNS names from the network: both are untrusted
/// and could otherwise inject terminal escapes or reorder the displayed text.
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() || is_format(c) { '?' } else { c }).collect()
}

/// Unicode general category Cf characters that change how text is shown.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn strips_escapes_and_bidi() {
        assert_eq!(sanitize("evil\x1b]0;pwn\x07"), "evil?]0;pwn?");
        assert_eq!(sanitize("abc\u{202E}gpj.exe"), "abc?gpj.exe");
        assert_eq!(sanitize("zero\u{200B}width"), "zero?width");
        assert_eq!(sanitize("firefox"), "firefox");
        assert_eq!(sanitize("münchen.de"), "münchen.de");
    }
}
