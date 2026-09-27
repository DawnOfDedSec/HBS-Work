//! Decrypts a real docker-harness report (if present) with the dev key
//! and sanity-checks its contents. Skips silently when no report file
//! exists so CI stays green without docker.

#[test]
fn decrypt_real_docker_report() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scripts/docker-test/out/report-ubuntu_24.04_root.hbs"
    );
    let Ok(env_bytes) = std::fs::read(path) else {
        eprintln!("no docker report present; skipping");
        return;
    };
    let priv_b: [u8; 32] = [0xab; 32];
    let pt = hbs_extractor::crypto::unseal(&env_bytes, &priv_b)
        .expect("real report must decrypt with dev key");
    let v: serde_json::Value = serde_json::from_slice(&pt).expect("report JSON parses");
    assert_eq!(v["schemaVersion"], 1);
    let results = v["results"].as_array().expect("results array");
    assert!(
        results.len() > 150,
        "expected full catalog, got {}",
        results.len()
    );
    // run context recorded on every result
    assert!(results.iter().all(|r| r["runContext"]["user"].is_string()));
    assert!(results
        .iter()
        .all(|r| r["runContext"]["elevated"].is_boolean()));
    // statuses make sense: errors listed for triage, bounded leniently
    // (slim containers lack many tools; degraded/error are honest data)
    let errors: Vec<&str> = results
        .iter()
        .filter(|r| r["status"] == "Error")
        .filter_map(|r| r["id"].as_str())
        .collect();
    eprintln!(
        "catalog={} errors={} error_ids={}",
        results.len(),
        errors.len(),
        errors.join(",")
    );
    eprintln!("summary={}", v["summary"]);
    assert!(
        errors.len() < results.len() / 5,
        "too many hard errors: {}",
        errors.len()
    );
    // metadata hardware blocks present
    assert!(v["metadata"]["network"]["interfaces"].is_array());
    assert!(v["metadata"]["cpu"]["cores"].is_number());
    eprintln!(
        "PASS: real report decrypts and validates ({} results)",
        results.len()
    );
}
