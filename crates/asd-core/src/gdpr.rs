//! Configurable handling of data-subject erasure requests (GDPR Art. 17).
//!
//! The only personal data this edition holds about a person is the IP address they connected from: blocklist and flag
//! entries, and the address inside stored security events. Everything here is driven by settings so an operator can
//! pick the policy that fits their situation and change it later.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// What happens to stored security events that mention the subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureMode {
    /// Replace the address with `[erased]`, keeping the event (type, time, actor) so the security record stays whole.
    Redact,
    /// Remove every event that mentions the address.
    Delete,
    /// Record the request only and do nothing automatically; a person carries it out.
    Manual,
}

/// What happens to a block that is still in force when erasure is requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveBlockPolicy {
    /// Keep the block until it expires on its own (legitimate security interest), and say so in the answer.
    RetainUntilExpiry,
    /// Remove the block immediately, even if that lets the address back in.
    EraseNow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdprConfig {
    pub mode: ErasureMode,
    pub active_block_policy: ActiveBlockPolicy,
}

impl Default for GdprConfig {
    fn default() -> Self {
        Self {
            mode: ErasureMode::Redact,
            active_block_policy: ActiveBlockPolicy::RetainUntilExpiry,
        }
    }
}

impl ErasureMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "redact" => Some(Self::Redact),
            "delete" => Some(Self::Delete),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Redact => "redact",
            Self::Delete => "delete",
            Self::Manual => "manual",
        }
    }
}

impl ActiveBlockPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "retain_until_expiry" => Some(Self::RetainUntilExpiry),
            "erase_now" => Some(Self::EraseNow),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetainUntilExpiry => "retain_until_expiry",
            Self::EraseNow => "erase_now",
        }
    }
}

impl GdprConfig {
    /// Reads `GDPR_ERASURE_MODE` and `GDPR_ACTIVE_BLOCK_POLICY`. A value that is set but not recognised is an error
    /// rather than a silent fallback, because a typo must not quietly change what a deletion request does.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_values(
            std::env::var("GDPR_ERASURE_MODE").ok().as_deref(),
            std::env::var("GDPR_ACTIVE_BLOCK_POLICY").ok().as_deref(),
        )
    }

    pub fn from_values(mode: Option<&str>, policy: Option<&str>) -> anyhow::Result<Self> {
        let mut config = Self::default();
        if let Some(value) = mode.filter(|value| !value.trim().is_empty()) {
            config.mode = ErasureMode::parse(value).ok_or_else(|| {
                anyhow::anyhow!("GDPR_ERASURE_MODE must be one of: redact, delete, manual")
            })?;
        }
        if let Some(value) = policy.filter(|value| !value.trim().is_empty()) {
            config.active_block_policy = ActiveBlockPolicy::parse(value).ok_or_else(|| {
                anyhow::anyhow!(
                    "GDPR_ACTIVE_BLOCK_POLICY must be one of: retain_until_expiry, erase_now"
                )
            })?;
        }
        Ok(config)
    }
}

/// A stable identifier for a subject that does not reveal the address, for the request record and the report.
pub fn subject_hash(ip: &str) -> String {
    hex::encode(Sha256::digest(ip.as_bytes()))
}

/// True when `rest` continues an address, so a match ending just before it is only part of a longer address.
fn continues_address(rest: &str) -> bool {
    let mut chars = rest.chars();
    match chars.next() {
        Some(c) if c.is_ascii_hexdigit() || c == ':' => true,
        Some('.') => chars
            .next()
            .is_some_and(|next| next.is_ascii_hexdigit() || next == ':'),
        _ => false,
    }
}

/// True when `before` ends in the middle of an address.
fn continues_address_before(before: &str) -> bool {
    let mut chars = before.chars().rev();
    match chars.next() {
        Some(c) if c.is_ascii_hexdigit() || c == ':' => true,
        Some('.') => chars
            .next()
            .is_some_and(|prev| prev.is_ascii_hexdigit() || prev == ':'),
        _ => false,
    }
}

/// Replaces whole-address occurrences of `ip` in `text`: `10.0.0.1` is replaced in "blocked 10.0.0.1." but not inside
/// `10.0.0.12`, `110.0.0.1` or `::10.0.0.1`.
pub fn replace_address(text: &str, ip: &str, replacement: &str) -> (String, usize) {
    if ip.is_empty() {
        return (text.to_owned(), 0);
    }
    let mut output = String::with_capacity(text.len());
    let mut replaced = 0;
    let mut index = 0;
    while let Some(offset) = text[index..].find(ip) {
        let start = index + offset;
        let end = start + ip.len();
        output.push_str(&text[index..start]);
        if !continues_address_before(&text[..start]) && !continues_address(&text[end..]) {
            output.push_str(replacement);
            replaced += 1;
        } else {
            output.push_str(&text[start..end]);
        }
        index = end;
    }
    output.push_str(&text[index..]);
    (output, replaced)
}

/// Redacts the subject's address everywhere in a JSON value (strings, nested arrays and objects, and object keys are
/// left alone). Returns how many occurrences were replaced.
pub fn redact_subject(value: &mut Value, ip: &str) -> usize {
    match value {
        Value::String(text) => {
            let (redacted, count) = replace_address(text, ip, "[erased]");
            if count > 0 {
                *text = redacted;
            }
            count
        }
        Value::Array(items) => items.iter_mut().map(|item| redact_subject(item, ip)).sum(),
        Value::Object(map) => map.values_mut().map(|item| redact_subject(item, ip)).sum(),
        _ => 0,
    }
}

/// Whether any string in the value contains the subject's address as a whole address.
pub fn mentions_subject(value: &Value, ip: &str) -> bool {
    match value {
        Value::String(text) => replace_address(text, ip, "").1 > 0,
        Value::Array(items) => items.iter().any(|item| mentions_subject(item, ip)),
        Value::Object(map) => map.values().any(|item| mentions_subject(item, ip)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn modes_and_policies_parse_and_default_to_the_cautious_choice() {
        assert_eq!(GdprConfig::default().mode, ErasureMode::Redact);
        assert_eq!(
            GdprConfig::default().active_block_policy,
            ActiveBlockPolicy::RetainUntilExpiry
        );
        let config = GdprConfig::from_values(Some(" DELETE "), Some("erase_now")).unwrap();
        assert_eq!(config.mode, ErasureMode::Delete);
        assert_eq!(config.active_block_policy, ActiveBlockPolicy::EraseNow);
        assert_eq!(
            GdprConfig::from_values(Some("manual"), None).unwrap().mode,
            ErasureMode::Manual
        );
        assert_eq!(
            GdprConfig::from_values(Some(""), Some("  ")).unwrap(),
            GdprConfig::default()
        );
        assert!(GdprConfig::from_values(Some("reddact"), None).is_err());
        assert!(GdprConfig::from_values(None, Some("sometimes")).is_err());
        for mode in [
            ErasureMode::Redact,
            ErasureMode::Delete,
            ErasureMode::Manual,
        ] {
            assert_eq!(ErasureMode::parse(mode.as_str()), Some(mode));
        }
    }

    #[test]
    fn an_address_is_replaced_only_as_a_whole_address() {
        let ip = "10.0.0.1";
        assert_eq!(
            replace_address("blocked 10.0.0.1.", ip, "X"),
            ("blocked X.".into(), 1)
        );
        assert_eq!(replace_address("10.0.0.1", ip, "X"), ("X".into(), 1));
        assert_eq!(replace_address("ips: 10.0.0.1, 10.0.0.1;", ip, "X").1, 2);
        for not_it in [
            "10.0.0.12",
            "110.0.0.1",
            "10.0.0.1.5",
            "a10.0.0.1",
            "::10.0.0.1",
            "10.0.0.1:443",
        ] {
            assert_eq!(replace_address(not_it, ip, "X").1, 0, "{not_it}");
        }
        assert_eq!(replace_address("no address here", ip, "X").1, 0);
        assert_eq!(replace_address("anything", "", "X").1, 0);
    }

    #[test]
    fn ipv6_addresses_follow_the_same_boundary_rule() {
        let ip = "2001:db8::1";
        assert_eq!(replace_address("client 2001:db8::1 blocked", ip, "X").1, 1);
        assert_eq!(replace_address("2001:db8::10", ip, "X").1, 0);
        assert_eq!(replace_address("12001:db8::1", ip, "X").1, 0);
    }

    #[test]
    fn redaction_walks_nested_json_and_leaves_keys_and_other_values_alone() {
        let mut event = json!({
            "ip": "203.0.113.7",
            "reason": "scraper at 203.0.113.7 tripped the honeypot",
            "nested": {"peers": ["203.0.113.7", "203.0.113.70"], "count": 3},
            "203.0.113.7": "a key is not redacted",
            "ok": true
        });

        let replaced = redact_subject(&mut event, "203.0.113.7");

        assert_eq!(replaced, 3);
        assert_eq!(event["ip"], "[erased]");
        assert_eq!(event["reason"], "scraper at [erased] tripped the honeypot");
        assert_eq!(
            event["nested"]["peers"],
            json!(["[erased]", "203.0.113.70"])
        );
        assert_eq!(event["nested"]["count"], 3);
        assert_eq!(event["203.0.113.7"], "a key is not redacted");
        assert!(!mentions_subject(&event["nested"], "203.0.113.7"));
        assert!(mentions_subject(
            &json!({"a": ["x 203.0.113.7 y"]}),
            "203.0.113.7"
        ));
        assert!(!mentions_subject(
            &json!({"a": "203.0.113.70"}),
            "203.0.113.7"
        ));
    }

    #[test]
    fn the_subject_hash_is_stable_and_does_not_contain_the_address() {
        let hash = subject_hash("203.0.113.7");
        assert_eq!(hash, subject_hash("203.0.113.7"));
        assert_ne!(hash, subject_hash("203.0.113.8"));
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains("203"));
    }
}
