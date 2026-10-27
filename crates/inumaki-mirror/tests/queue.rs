//! M5 spec §6.5 and Review Focus 3: datasets are served round-robin within
//! a priority, so a large first scan cannot starve another folder; removal
//! beats everything; a path pushed while in flight runs once more after it,
//! never twice at once (Review Focus 1 relies on it); a duplicate never
//! weakens the flags of the job it merges into.

use std::time::Duration;

use inumaki_mirror::queue::{Job, Priority, WorkQueue};

fn src(ds: &str, rel: &str) -> Job {
    Job::Source {
        dataset: ds.into(),
        rel: rel.as_bytes().to_vec(),
        force: false,
    }
}

#[test]
fn a_large_first_scan_does_not_starve_another_folder() {
    let q = WorkQueue::new();
    for i in 0..2000 {
        q.push(src("big", &format!("f{i}.txt")), Priority::Background);
    }
    q.push(src("small", "one.txt"), Priority::Background);
    let (first, _) = q.pop_timeout(Duration::ZERO).unwrap();
    q.done(&first);
    let (second, _) = q.pop_timeout(Duration::ZERO).unwrap();
    assert!(
        [first.dataset(), second.dataset()].contains(&"small"),
        "served within the first two jobs"
    );
}

#[test]
fn removal_comes_first_and_an_in_flight_path_runs_again_after_it() {
    let q = WorkQueue::new();
    q.push(src("a", "x"), Priority::Background);
    q.push(
        Job::Confirmed {
            dataset: "a".into(),
            rel: b"y".to_vec(),
        },
        Priority::Removal,
    );
    let (j, p) = q.pop_timeout(Duration::ZERO).unwrap();
    assert_eq!(p, Priority::Removal);
    q.done(&j);
    let (x, _) = q.pop_timeout(Duration::ZERO).unwrap();
    q.push(src("a", "x"), Priority::Live);
    assert!(
        q.pop_timeout(Duration::ZERO).is_none(),
        "never twice at once"
    );
    q.done(&x);
    let (again, p) = q.pop_timeout(Duration::ZERO).unwrap();
    assert_eq!((again.dataset(), p), ("a", Priority::Live));
}

#[test]
fn a_forced_push_behind_a_plain_one_still_runs_forced() {
    let q = WorkQueue::new();
    q.push(src("a", "x"), Priority::Live);
    q.push(
        Job::Source {
            dataset: "a".into(),
            rel: b"x".to_vec(),
            force: true,
        },
        Priority::Background,
    );
    let (j, _) = q.pop_timeout(Duration::ZERO).unwrap();
    assert!(matches!(j, Job::Source { force: true, .. }), "force kept");
    // Same while in flight: the re-run carries the flag.
    q.done(&j);
    q.push(src("a", "x"), Priority::Live);
    let (j, _) = q.pop_timeout(Duration::ZERO).unwrap();
    q.push(
        Job::Source {
            dataset: "a".into(),
            rel: b"x".to_vec(),
            force: true,
        },
        Priority::Live,
    );
    q.done(&j);
    let (again, _) = q.pop_timeout(Duration::ZERO).unwrap();
    assert!(
        matches!(again, Job::Source { force: true, .. }),
        "force kept across in-flight"
    );
}

#[test]
fn one_dataset_runs_one_job_at_a_time_while_others_proceed() {
    // 5c/5d carries: a whole-folder reconcile, a tripwire pass, a removal,
    // and a file of the same folder never run at once.
    let q = WorkQueue::new();
    q.push(src("a", "x"), Priority::Live);
    q.push(
        Job::Tripwire {
            dataset: "a".into(),
        },
        Priority::Tripwire,
    );
    q.push(
        Job::Confirmed {
            dataset: "a".into(),
            rel: b"y".to_vec(),
        },
        Priority::Removal,
    );
    q.push(src("b", "z"), Priority::Background);
    let (first, p) = q.pop_timeout(Duration::ZERO).unwrap();
    assert_eq!((first.dataset(), p), ("a", Priority::Removal));
    let (second, _) = q.pop_timeout(Duration::ZERO).unwrap();
    assert_eq!(second.dataset(), "b", "another dataset runs alongside");
    assert!(
        q.pop_timeout(Duration::ZERO).is_none(),
        "a's other jobs wait while one of its jobs runs"
    );
    q.done(&first);
    let (third, p) = q.pop_timeout(Duration::ZERO).unwrap();
    assert_eq!((third.dataset(), p), ("a", Priority::Live));
    assert!(q.pop_timeout(Duration::ZERO).is_none());
    q.done(&third);
    q.done(&second);
    let (last, p) = q.pop_timeout(Duration::ZERO).unwrap();
    assert_eq!((last.dataset(), p), ("a", Priority::Tripwire));
    assert!(!q.is_idle());
    q.done(&last);
    assert!(q.is_idle());
}
