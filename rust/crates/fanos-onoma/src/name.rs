//! A validated, homograph-resistant **readable name** — a dotted sequence of labels such as
//! `mail.alice.fanos`.
//!
//! ONOMA readable names are strict ASCII **LDH** (letters/digits/hyphen, the DNS hostname rule),
//! lower-cased and Unicode-free. This is a deliberate security choice: it eliminates the entire
//! class of homograph/confusable attacks that plague internationalized names, at the cost of not
//! (yet) supporting non-Latin scripts — a policy that can be relaxed later behind a
//! confusable-resistant profile (documented, not silently unsafe).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::OnomaError;

/// Maximum labels in a name (loop/abuse guard).
pub const MAX_LABELS: usize = 32;
/// Maximum length of a single label (the DNS limit).
pub const MAX_LABEL_LEN: usize = 63;

/// Whether `label` is a valid ONOMA label: 1..=63 ASCII LDH chars, no leading/trailing hyphen.
#[must_use]
pub fn is_valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LABEL_LEN {
        return false;
    }
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return false;
    }
    label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A parsed, validated readable name, stored in DNS order (`["mail", "alice", "fanos"]`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Name {
    labels: Vec<String>,
}

impl Name {
    /// Parse and validate a dotted name. Input is lower-cased first; every label must be LDH.
    ///
    /// # Errors
    /// [`OnomaError::Empty`] if empty, [`OnomaError::BadLabel`] on an invalid or too-long label,
    /// or too many labels.
    pub fn parse(input: &str) -> Result<Self, OnomaError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(OnomaError::Empty);
        }
        let lower = trimmed.to_ascii_lowercase();
        let mut labels = Vec::new();
        for part in lower.split('.') {
            if !is_valid_label(part) {
                return Err(OnomaError::BadLabel);
            }
            labels.push(part.to_string());
            if labels.len() > MAX_LABELS {
                return Err(OnomaError::BadLabel);
            }
        }
        Ok(Self { labels })
    }

    /// The labels in DNS order (least-significant first).
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// The trailing label (the TLD), if any.
    #[must_use]
    pub fn tld(&self) -> Option<&str> {
        self.labels.last().map(String::as_str)
    }

    /// The labels below `tld` (i.e. with the trailing TLD stripped), if the name ends in `tld`.
    #[must_use]
    pub fn labels_under(&self, tld: &str) -> Option<&[String]> {
        match self.labels.split_last() {
            Some((last, rest)) if last == tld => Some(rest),
            _ => None,
        }
    }

    /// Reassemble the dotted string form.
    #[must_use]
    pub fn to_dotted(&self) -> String {
        self.labels.join(".")
    }
}

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_dotted())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_reassembles() {
        let n = Name::parse("Mail.Alice.Fanos").unwrap();
        assert_eq!(n.to_dotted(), "mail.alice.fanos"); // lower-cased
        assert_eq!(n.tld(), Some("fanos"));
        assert_eq!(
            n.labels_under("fanos"),
            Some(["mail".to_string(), "alice".to_string()].as_slice())
        );
    }

    #[test]
    fn rejects_bad_labels() {
        assert_eq!(Name::parse(""), Err(OnomaError::Empty));
        assert_eq!(Name::parse("a..b"), Err(OnomaError::BadLabel)); // empty label
        assert_eq!(Name::parse("-lead.fanos"), Err(OnomaError::BadLabel));
        assert_eq!(Name::parse("trail-.fanos"), Err(OnomaError::BadLabel));
        assert_eq!(Name::parse("bad_underscore"), Err(OnomaError::BadLabel));
        assert_eq!(Name::parse("café.fanos"), Err(OnomaError::BadLabel)); // non-ASCII
    }

    #[test]
    fn labels_under_requires_matching_tld() {
        let n = Name::parse("blog.alice.fanos").unwrap();
        assert!(n.labels_under("example").is_none());
    }
}
