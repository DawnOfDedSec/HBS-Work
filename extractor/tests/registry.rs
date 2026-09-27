use hbs_extractor::checks::register_all;
use hbs_extractor::model::RegisteredCheck;
use std::collections::HashSet;

#[test]
fn registry_is_populated_and_ids_unique() {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    assert!(
        !reg.is_empty(),
        "registry must contain at least the seed check"
    );
    let ids: HashSet<&str> = reg.iter().map(|c| c.tc.id).collect();
    assert_eq!(ids.len(), reg.len(), "duplicate check IDs in registry");
}
