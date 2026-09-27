//! Optional report push (spec §4.1): the extractor is offline by default.
//! When `--push <url>` is supplied the already-written local report is sent
//! verbatim, with a bounded timeout and at most two retries. The token is
//! sourced only from `HBS_PUSH_TOKEN` or `--push-token-file`, never argv, the
//! URL, logs, the report, the audit log, or the keyslot.

use std::time::Duration;

/// Bounded network policy. Kept small and fixed so a scan never hangs.
#[derive(Clone, Debug)]
pub struct PushPolicy {
    pub connect_timeout: Duration,
    pub transfer_timeout: Duration,
    pub max_retries: u32,
    pub backoff: Duration,
}

impl Default for PushPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            transfer_timeout: Duration::from_secs(15),
            max_retries: 2,
            backoff: Duration::from_millis(500),
        }
    }
}

/// Resolve the push token from its two permitted sources. Supplying both is
/// an explicit error so provenance is never ambiguous. The token value is
/// never included in any error message.
pub fn resolve_token(
    env_token: Option<String>,
    token_file: Option<&str>,
) -> Result<String, String> {
    match (env_token, token_file) {
        (Some(_), Some(_)) => {
            Err("both HBS_PUSH_TOKEN and --push-token-file are set; provide exactly one".into())
        }
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read --push-token-file {path}: {e}"))?;
            let token = raw.trim().to_string();
            if token.is_empty() {
                return Err(format!("--push-token-file {path} is empty"));
            }
            Ok(token)
        }
        (None, None) => {
            Err("no push token: set HBS_PUSH_TOKEN or pass --push-token-file <path>".into())
        }
        (Some(token), None) => {
            let token = token.trim().to_string();
            if token.is_empty() {
                return Err("HBS_PUSH_TOKEN is empty".into());
            }
            Ok(token)
        }
    }
}

/// Push the exact sealed bytes to `url`. Retries only transient failures
/// (network errors and 5xx) up to `policy.max_retries`. 4xx is final.
/// Returns the HTTP status on success.
pub fn push_report(
    url: &str,
    envelope: &[u8],
    token: &str,
    extractor_id: &str,
    policy: &PushPolicy,
) -> Result<u16, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!("unsupported push URL scheme: {url}"));
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(policy.connect_timeout)
        .timeout(policy.transfer_timeout)
        .build();

    let auth = format!("Bearer {token}");
    let mut last_error = String::from("push did not run");

    for attempt in 0..=policy.max_retries {
        if attempt > 0 {
            let factor = 1u32 << (attempt - 1);
            std::thread::sleep(policy.backoff * factor);
        }

        let result = agent
            .post(url)
            .set("Authorization", &auth)
            .set("X-HBS-Extractor", extractor_id)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(envelope);

        match result {
            Ok(resp) => {
                let status = resp.status();
                if status >= 500 {
                    last_error = format!("server error HTTP {status}");
                    continue;
                }
                return Ok(status);
            }
            Err(ureq::Error::Status(code, _)) => {
                if code >= 500 {
                    last_error = format!("server error HTTP {code}");
                    continue;
                }
                // Client errors are definitive; retrying cannot help.
                return Err(format!("push rejected with HTTP {code}"));
            }
            Err(ureq::Error::Transport(t)) => {
                last_error = format!("transport error: {t}");
                continue;
            }
        }
    }

    Err(format!(
        "push failed after {} attempts: {last_error}",
        policy.max_retries + 1
    ))
}
