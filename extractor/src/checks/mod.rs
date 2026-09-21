//! Testcase catalog. Each module exposes `register(&mut Vec<RegisteredCheck>)`
//! and is wired into `register_all` below. Adding a testcase = one entry
//! in a module via the `check!` macro (spec §4.3).

pub mod toy;

use crate::model::RegisteredCheck;

pub fn register_all(reg: &mut Vec<RegisteredCheck>) {
    toy::register(reg);
    // Phase 2/3 modules register here as they land.
}
