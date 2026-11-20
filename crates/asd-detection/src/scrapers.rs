//! Configured product tokens, never a bare `bot` or `crawler` substring.
use std::collections::HashSet;

pub const DEFAULT_SCRAPER_UAS: &str = "scrapy,sqlmap,nikto,masscan,nmap,zgrab,gptbot,ccbot,claudebot,claude-web,google-extended,bytespider,petalbot,ahrefsbot,semrushbot,mj12bot,dotbot";

#[derive(Clone, Debug)]
pub struct ScraperPolicy {
    blocked: Vec<String>,
    exceptions: HashSet<String>,
}

impl Default for ScraperPolicy {
    fn default() -> Self {
        Self::parse(DEFAULT_SCRAPER_UAS, "").expect("valid built-in scraper tokens")
    }
}

impl ScraperPolicy {
    pub fn parse(blocked: &str, exceptions: &str) -> Result<Self, String> {
        fn tokens(list: &str) -> Result<Vec<String>, String> {
            list.split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(|token| {
                    if !token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    {
                        return Err(format!("invalid scraper product token: {token:?}"));
                    }
                    Ok(token.to_ascii_lowercase())
                })
                .collect()
        }
        Ok(Self {
            blocked: tokens(blocked)?,
            exceptions: tokens(exceptions)?.into_iter().collect(),
        })
    }

    pub fn blocked_token(&self, user_agent: &str) -> Option<&str> {
        let ua = user_agent.to_ascii_lowercase();
        let tokens: HashSet<_> = ua
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_')
            .collect();
        self.blocked
            .iter()
            .find(|token| !self.exceptions.contains(*token) && tokens.contains(token.as_str()))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_exceptions_are_specific_and_case_insensitive() {
        let policy = ScraperPolicy::parse("GPTBot,sqlmap", "gptbot").unwrap();
        assert_eq!(policy.blocked_token("GPTBot/1.2"), None);
        assert_eq!(
            policy.blocked_token("GPTBot/1.2 sqlmap/1.7 Googlebot/2.1"),
            Some("sqlmap")
        );
        assert_eq!(policy.blocked_token("not-sqlmap sqlmapish"), None);
        assert_eq!(
            ScraperPolicy::default().blocked_token("Mozilla (compatible; GPTBOT/1.2)"),
            Some("gptbot")
        );
        for ua in [
            "Googlebot",
            "Bingbot",
            "Slackbot",
            "UptimeRobot",
            "robotics browser",
            "curl/8.5",
            "wget/1.21",
            "python-requests/2",
        ] {
            assert_eq!(ScraperPolicy::default().blocked_token(ua), None, "{ua}");
        }
        assert!(ScraperPolicy::parse("gptbot/1.2", "").is_err());
    }
}
