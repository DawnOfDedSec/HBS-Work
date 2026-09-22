//! Offline-by-default push policy: token sourcing, exact-bytes upload, and
//! bounded retries. A minimal in-process TCP server stands in for the
//! dashboard so no network or DNS ever leaves the machine.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;

use hbs_extractor::push::{push_report, resolve_token, PushPolicy};

#[derive(Debug)]
struct Recorded {
    method: String,
    path: String,
    authorization: Option<String>,
    extractor: Option<String>,
    body: Vec<u8>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

fn read_request(stream: &mut TcpStream) -> Recorded {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let header_end;
    loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        let n = stream.read(&mut tmp).expect("read headers");
        if n == 0 {
            return Recorded { method: String::new(), path: String::new(), authorization: None, extractor: None, body: Vec::new() };
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let headers = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
    let content_length: usize = header_value(&headers, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut tmp).expect("read body");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let request_line = headers.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    Recorded {
        method: parts.next().unwrap_or_default().to_string(),
        path: parts.next().unwrap_or_default().to_string(),
        authorization: header_value(&headers, "authorization"),
        extractor: header_value(&headers, "x-hbs-extractor"),
        body: buf[header_end..].to_vec(),
    }
}

fn spawn_server(responses: Vec<u16>) -> (String, Receiver<Recorded>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = channel();
    thread::spawn(move || {
        for status in responses {
            let Ok((mut stream, _)) = listener.accept() else { break };
            let recorded = read_request(&mut stream);
            let _ = tx.send(recorded);
            let reason = if (200..300).contains(&status) { "OK" } else { "Error" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), rx)
}

fn fast_policy() -> PushPolicy {
    PushPolicy {
        connect_timeout: Duration::from_secs(2),
        transfer_timeout: Duration::from_secs(2),
        max_retries: 2,
        backoff: Duration::from_millis(1),
    }
}

fn temp_token_file(contents: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "hbs-push-token-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn both_token_sources_is_an_error() {
    let path = temp_token_file("file-token");
    let err = resolve_token(Some("env-token".into()), Some(path.to_str().unwrap())).unwrap_err();
    assert!(err.contains("both"), "got: {err}");
    let _ = std::fs::remove_file(path);
}

#[test]
fn token_from_env_or_readonly_file() {
    assert_eq!(resolve_token(Some(" env-token \n".into()), None).unwrap(), "env-token");

    let path = temp_token_file("file-token\n");
    assert_eq!(resolve_token(None, Some(path.to_str().unwrap())).unwrap(), "file-token");
    let _ = std::fs::remove_file(path);

    let empty = temp_token_file("   \n");
    assert!(resolve_token(None, Some(empty.to_str().unwrap()))
        .unwrap_err()
        .contains("empty"));
    let _ = std::fs::remove_file(empty);
}

#[test]
fn missing_token_is_an_error() {
    let err = resolve_token(None, None).unwrap_err();
    assert!(err.contains("no push token"), "got: {err}");
}

#[test]
fn push_sends_exact_bytes_with_bearer_token() {
    let (url, rx) = spawn_server(vec![200]);
    let envelope = vec![0x48, 0x42, 0x53, 0x32, 1, 2, 3, 4, 5, 6, 7, 8];
    let status = push_report(&url, &envelope, "s3cr3t", "extractor-1", &fast_policy()).unwrap();
    assert_eq!(status, 200);

    let recorded = rx.recv_timeout(Duration::from_secs(5)).expect("one request");
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.body, envelope, "must send the exact sealed bytes");
    assert_eq!(recorded.authorization.as_deref(), Some("Bearer s3cr3t"));
    assert_eq!(recorded.extractor.as_deref(), Some("extractor-1"));
    assert!(recorded.path.starts_with('/'), "path: {}", recorded.path);
}

#[test]
fn transient_5xx_retries_then_succeeds() {
    let (url, rx) = spawn_server(vec![500, 502, 200]);
    let envelope = vec![9u8; 16];
    let status = push_report(&url, &envelope, "t", "e", &fast_policy()).unwrap();
    assert_eq!(status, 200);

    let mut attempts = 0;
    while rx.recv_timeout(Duration::from_secs(5)).is_ok() {
        attempts += 1;
    }
    assert_eq!(attempts, 3, "two retries after the initial attempt");
}

#[test]
fn persistent_5xx_is_bounded_and_reported() {
    let (url, rx) = spawn_server(vec![500, 500, 500]);
    let err = push_report(&url, &[1u8; 8], "t", "e", &fast_policy()).unwrap_err();
    assert!(err.contains("after 3 attempts"), "got: {err}");

    let mut attempts = 0;
    while rx.recv_timeout(Duration::from_secs(5)).is_ok() {
        attempts += 1;
    }
    assert_eq!(attempts, 3, "never exceeds max_retries");
}

#[test]
fn client_error_is_final_and_not_retried() {
    let (url, rx) = spawn_server(vec![403]);
    let err = push_report(&url, &[1u8; 8], "t", "e", &fast_policy()).unwrap_err();
    assert!(err.contains("HTTP 403"), "got: {err}");
    assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
}

#[test]
fn rejects_non_http_schemes() {
    let err = push_report("ftp://example.invalid", &[0u8; 4], "t", "e", &fast_policy())
        .unwrap_err();
    assert!(err.contains("scheme"), "got: {err}");
}
