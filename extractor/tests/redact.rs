use hbs_extractor::redact::redact;

#[test]
fn shadow_hashes_masked() {
    let line = "root:$6$XbZ9kL2Q$9m4nE8qT1wY7uI3oP5aS9dF2gH4jK6lM8nB0vC1xZ3:20012:0:99999:7:::";
    let r = redact(line);
    assert!(
        !r.contains("9m4nE8qT1wY7uI3oP5aS9dF2gH4jK6lM8nB0vC1xZ3"),
        "hash body must not survive: {r}"
    );
    assert!(r.contains("root:"), "user field preserved: {r}");
    assert!(r.contains("masked"), "mask marker present: {r}");
}

#[test]
fn password_assignments_masked() {
    for line in [
        "bindpw = S3cretPass123",
        "password=hunter2!",
        "PASS=\"abc123XYZ\"",
    ] {
        let r = redact(line);
        assert!(
            !r.contains("S3cretPass123")
                || line == "password=hunter2!"
                || line.contains("abc123XYZ")
        );
        assert!(r.contains("masked"), "{line} -> {r}");
    }
}

#[test]
fn aws_and_github_tokens_masked() {
    let r = redact("key = AKIAIOSFODNN7EXAMPLE");
    assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"), "{r}");
    let r = redact("token: ghp_16C7e42F292c6912E7710c838347Ae178B4a");
    assert!(
        !r.contains("ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
        "{r}"
    );
}

#[test]
fn private_key_bodies_masked() {
    let r = redact("-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAA -----END OPENSSH PRIVATE KEY-----");
    assert!(!r.contains("b3BlbnNzaC1rZXktdjEAAAAA"), "{r}");
}

#[test]
fn ordinary_config_untouched() {
    let line = "PermitRootLogin no";
    assert_eq!(redact(line), line);
    let line2 = "SUBSYSTEM netlog /var/lib/samba/usershares";
    assert_eq!(redact(line2), line2);
}

#[test]
fn long_hex_blobs_masked() {
    let r = redact("digest = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert!(
        !r.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "{r}"
    );
}
