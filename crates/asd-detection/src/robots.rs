//! Robots policy is separate from authenticated crawler identity and sensitive-path hints.
use std::{fs, io, path::Path};

#[derive(Clone, Debug)]
struct Rule {
    pattern: Vec<u8>,
    anchored: bool,
    length: usize,
    allow: bool,
}

#[derive(Clone, Debug, Default)]
struct Group {
    agents: Vec<String>,
    rules: Vec<Rule>,
    has_rules: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RobotsPolicy {
    groups: Vec<Group>,
}

impl RobotsPolicy {
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        fs::read_to_string(path).map(|text| Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut groups: Vec<Group> = Vec::new();
        for line in text.trim_start_matches('\u{feff}').split(['\r', '\n']) {
            let line = line.split('#').next().unwrap_or("");
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if key.trim().eq_ignore_ascii_case("user-agent") {
                if value.is_empty()
                    || (value != "*"
                        && !value
                            .bytes()
                            .all(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'-'))
                {
                    continue;
                }
                if groups.last().is_none_or(|group| group.has_rules) {
                    groups.push(Group::default());
                }
                groups
                    .last_mut()
                    .unwrap()
                    .agents
                    .push(value.to_ascii_lowercase());
            } else if key.trim().eq_ignore_ascii_case("allow")
                || key.trim().eq_ignore_ascii_case("disallow")
            {
                let Some(group) = groups.last_mut() else {
                    continue;
                };
                group.has_rules = true;
                if !value.starts_with(['/', '*']) {
                    continue;
                }
                let anchored = value.ends_with('$');
                let pattern = normalize(value.strip_suffix('$').unwrap_or(value), true);
                let mut length = 0;
                let mut index = 0;
                while index < pattern.len() {
                    if pattern[index] == b'%' && index + 2 < pattern.len() {
                        index += 3;
                        length += 1;
                    } else {
                        length += usize::from(pattern[index] != b'*');
                        index += 1;
                    }
                }
                group.rules.push(Rule {
                    pattern,
                    anchored,
                    length,
                    allow: key.trim().eq_ignore_ascii_case("allow"),
                });
            }
        }
        Self { groups }
    }

    pub fn is_disallowed(&self, path: &str, user_agent: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let path = normalize(path, false);
        if path == b"/robots.txt" || path.starts_with(b"/robots.txt?") {
            return false;
        }
        let ua = user_agent.to_ascii_lowercase();
        let tokens: Vec<_> = ua
            .split(|ch: char| !ch.is_ascii_alphabetic() && ch != '_' && ch != '-')
            .collect();
        let specific: Vec<_> = self
            .groups
            .iter()
            .filter(|group| {
                group
                    .agents
                    .iter()
                    .any(|agent| agent != "*" && tokens.contains(&agent.as_str()))
            })
            .collect();
        let selected: Vec<_> = if specific.is_empty() {
            self.groups
                .iter()
                .filter(|group| group.agents.iter().any(|agent| agent == "*"))
                .collect()
        } else {
            specific
        };
        let mut best = None;
        let mut allowed = true;
        for group in selected {
            for rule in &group.rules {
                if best.is_none_or(|length| rule.length >= length) && matches(&path, rule) {
                    allowed = if best == Some(rule.length) {
                        allowed || rule.allow
                    } else {
                        rule.allow
                    };
                    best = Some(rule.length);
                }
            }
        }
        !allowed
    }
}

fn normalize(value: &str, pattern: bool) -> Vec<u8> {
    let mut result = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let mut byte = bytes[index];
        if byte == b'%' && index + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[index + 1] as char).to_digit(16),
                (bytes[index + 2] as char).to_digit(16),
            ) {
                byte = ((hi << 4) | lo) as u8;
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    result.push(byte);
                } else {
                    result.extend_from_slice(format!("%{byte:02X}").as_bytes());
                }
                index += 3;
                continue;
            }
        }
        if !byte.is_ascii() || byte <= b' ' || byte == b'$' || (byte == b'*' && !pattern) {
            result.extend_from_slice(format!("%{byte:02X}").as_bytes());
        } else {
            result.push(byte);
        }
        index += 1;
    }
    result
}

// Iterative wildcard matching avoids recursive regex backtracking.
fn matches(path: &[u8], rule: &Rule) -> bool {
    let mut pattern = rule.pattern.clone();
    if !rule.anchored {
        pattern.push(b'*');
    }
    let (mut i, mut j) = (0, 0);
    let mut star = None;
    let mut resume = 0;
    while i < path.len() {
        if pattern.get(j) == Some(&b'*') {
            star = Some(j);
            resume = i;
            j += 1;
        } else if pattern.get(j) == path.get(i) {
            i += 1;
            j += 1;
        } else if let Some(star) = star {
            resume += 1;
            i = resume;
            j = star + 1;
        } else {
            return false;
        }
    }
    while pattern.get(j) == Some(&b'*') {
        j += 1;
    }
    j == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_follow_path_comment_encoding_and_allow_semantics() {
        for (rules, path, disallowed) in [
            ("Disallow: /secret # comment", "/secret", true),
            ("Disallow: /Admin", "/Admin", true),
            ("Disallow: /Admin", "/admin", false),
            ("Disallow: /admin", "/%61dmin", true),
            ("Disallow: /%61dmin", "/admin", true),
            ("Disallow: /a%2fb", "/a%2Fb", true),
            ("Disallow: /a%2fb", "/a/b", false),
            ("Disallow: /", "/anything", true),
            ("Disallow: /", "/", true),
            ("Disallow: /", "/robots.txt", false),
            ("Disallow: /", "/robots.txt?v=1", false),
            ("Disallow: /\nAllow: /public/", "/public/page", false),
            ("Disallow: /same\nAllow: /same", "/same", false),
            ("Allow: /same\nDisallow: /same", "/same", false),
            ("Disallow: /*.gif$", "/image.gif", true),
            ("Disallow: /*.gif$", "/image.gif?v=1", false),
            ("Disallow: /literal%2A", "/literal*", true),
            ("Disallow: /literal%24", "/literal$", true),
            ("Disallow: /café", "/caf%C3%A9", true),
            ("Disallow: /caf%C3%A9", "/café", true),
            ("Disallow: /search?q=secret", "/search?q=secret", true),
            ("Disallow: /admin/", "/admin", false),
            ("Disallow:", "/anything", false),
        ] {
            let policy = RobotsPolicy::parse(&format!("User-agent: *\n{rules}"));
            assert_eq!(
                policy.is_disallowed(path, "Firefox"),
                disallowed,
                "{rules} {path}"
            );
        }
    }

    #[test]
    fn groups_are_case_insensitive_merged_and_separate_from_identity() {
        let policy = RobotsPolicy::parse("\u{feff}User-agent : *\rDisallow: /\rUser-agent: ExampleBot\rUser-agent: OtherBot\rDisallow: /one\rUser-agent: EXAMPLEBOT\rSitemap: ignored\rDisallow: /two\rUser-agent: EmptyBot\r");
        assert!(policy.is_disallowed("/one", "ExampleBot/1.0"));
        assert!(policy.is_disallowed("/two", "ExampleBot/1.0"));
        assert!(!policy.is_disallowed("/pricing", "ExampleBot/1.0"));
        assert!(policy.is_disallowed("/pricing", "FakeExampleBot"));
        assert!(!policy.is_disallowed("/one", "EmptyBot"));
        assert!(!RobotsPolicy::parse("Disallow: /").is_disallowed("/one", "Firefox"));
    }
}
