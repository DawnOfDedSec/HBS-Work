//! Extractor-side secret redaction. Applied to every evidence string
//! and evidence-block line BEFORE anything enters the sealed report —
//! secrets must not exist even inside encrypted reports, because
//! reports later export to PDF/DOCX that get shared widely.

/// Mask token shape: keep first 2 + last 2 chars, report length.
fn mask(token: &str) -> String {
    let t = token.trim();
    if t.len() <= 6 {
        return format!("«masked:{len}»", len = t.len());
    }
    format!(
        "«{}…{} (masked, {} chars)»",
        &t[..2.min(t.len())],
        &t[t.len().saturating_sub(2)..],
        t.len()
    )
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || c == b'_'
        || c == b'-'
        || c == b'.'
        || c == b'$'
        || c == b'/'
        || c == b'+'
        || c == b'='
}

/// Split a line into (word, byte-range) candidates for masking.
/// A '.' only continues a word when followed by another word byte.
fn words(line: &str) -> Vec<(String, usize, usize)> {
    let bytes = line.as_bytes();
    let word_at = |i: usize| -> bool {
        if !is_word_byte(bytes[i]) {
            return false;
        }
        if bytes[i] == b'.' {
            return i + 1 < bytes.len() && is_word_byte(bytes[i + 1]);
        }
        true
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !word_at(i) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && word_at(i) {
            i += 1;
        }
        if let Some(w) = line.get(start..i) {
            out.push((w.to_string(), start, i));
        }
    }
    out
}

/// Redact one line of evidence.
pub fn redact(line: &str) -> String {
    // First pass: spaced assignments "key = value" / "key: value" with
    // secret-ish keys.
    let line = mask_spaced_assignments(line);
    let mut result = String::with_capacity(line.len());
    let mut consumed = 0usize;
    for (w, start, end) in words(&line) {
        result.push_str(line.get(consumed..start).unwrap_or(""));
        let masked = classify(&w);
        result.push_str(&masked);
        consumed = end;
    }
    result.push_str(line.get(consumed..).unwrap_or(""));
    result
}

fn is_secret_key(key: &str) -> bool {
    let kl = key.to_lowercase();
    kl.ends_with("password")
        || kl.ends_with("passwd")
        || kl.ends_with("pass")
        || kl.ends_with("secret")
        || kl.ends_with("token")
        || kl.ends_with("bindpw")
        || kl.ends_with("apikey")
        || kl.ends_with("api_key")
        || kl.ends_with("auth")
}

fn value_byte(c: u8) -> bool {
    !c.is_ascii_whitespace() && c != b'"' && c != b'\''
}

/// Mask "key = value", "key=value:", quoted variants, and "key: value".
/// Single pass — already-masked output is never rescanned.
fn mask_spaced_assignments(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() && bytes[i] != b'_' {
            out.push(line[i..].chars().next().unwrap_or_default());
            i += line[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            continue;
        }
        let kstart = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let key = line[kstart..i].to_string();
        out.push_str(&key);
        if !is_secret_key(&key) {
            continue;
        }
        let mut j = i;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        if j >= bytes.len() || (bytes[j] != b'=' && bytes[j] != b':') {
            continue;
        }
        let sep_end = j + 1;
        let mut k = sep_end;
        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
            k += 1;
        }
        if k < bytes.len() && (bytes[k] == b'"' || bytes[k] == b'\'') {
            k += 1;
        }
        let vstart = k;
        while k < bytes.len() && value_byte(bytes[k]) {
            k += 1;
        }
        out.push_str(&line[i..vstart]);
        if k > vstart {
            let value = line[vstart..k].to_string();
            out.push_str(&mask(&value));
        }
        i = k.max(sep_end);
    }
    out
}

fn classify(w: &str) -> String {
    // shadow crypt hashes: $6$..., $y$..., $5$..., $1$...
    if w.starts_with('$') && w.len() >= 8 {
        let second = w.chars().nth(1);
        if let Some(c) = second {
            if c.is_ascii_digit() || c == 'y' || c == 's' {
                return mask(w);
            }
        }
    }
    // AWS access keys
    if w.starts_with("AKIA") && w.len() >= 16 {
        return mask(w);
    }
    // GitHub / common token prefixes
    if (w.starts_with("ghp_") || w.starts_with("gho_") || w.starts_with("github_pat_"))
        && w.len() > 10
    {
        return mask(w);
    }
    // JWTs
    if w.starts_with("eyJ") && w.len() > 30 {
        return mask(w);
    }
    // private key bodies / long base64 or hex runs. Words containing
    // '/' are NOT masked — they are almost always paths.
    if w.len() >= 20 && !w.contains('/') && !w.contains('.') {
        let hexish = w.chars().all(|c| c.is_ascii_hexdigit());
        let b64ish = w
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '=' || c == '_');
        if hexish || b64ish {
            return mask(w);
        }
    }
    // key=value secrets inside a single word (password=..., bindpw=...)
    if let Some(eq) = w.find('=') {
        let (k, v) = w.split_at(eq);
        let v = &v[1..];
        let kl = k.to_lowercase();
        if v.len() >= 3
            && (kl.ends_with("password")
                || kl.ends_with("passwd")
                || kl.ends_with("pass")
                || kl.ends_with("secret")
                || kl.ends_with("token")
                || kl.ends_with("bindpw")
                || kl.ends_with("apikey")
                || kl.ends_with("api_key")
                || kl.ends_with("auth"))
        {
            return format!("{k}={}", mask(v));
        }
    }
    // quoted "PASS=..." variants are handled as separate words by words()
    // (quotes break tokens), so also treat bare quoted values after
    // secret-ish keys at line level elsewhere.
    w.to_string()
}

/// Redact a full multi-line blob.
pub fn redact_all(text: &str) -> String {
    text.lines().map(redact).collect::<Vec<_>>().join("\n")
}
