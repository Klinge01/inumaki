//! System-notification text (M6 spec §6.5): what happened, at which front
//! door, how often, and which entity kinds — never a dataset, path, server
//! name, or value. macOS keeps notification history and shows it on the
//! lock screen. Records of check datasets (`check-`) never notify.

use std::collections::{BTreeMap, BTreeSet};

use inumaki_client::{ActivityRecord, Direction, FrontDoor, Verdict};

use crate::error::kind_ok;

fn what(fd: FrontDoor, dir: Direction, n: usize) -> String {
    let (one, many) = match (fd, dir) {
        (FrontDoor::Gateway, Direction::Arguments) => ("a tool call", "tool calls"),
        (FrontDoor::Gateway, _) => ("a tool result", "tool results"),
        (FrontDoor::Mirror, _) => ("a file", "files"),
        (FrontDoor::Proxy, Direction::Response) => ("a model answer", "model answers"),
        (FrontDoor::Proxy, _) => ("a chat message", "chat messages"),
        (FrontDoor::Hook, _) => ("a tool output", "tool outputs"),
        (FrontDoor::Control, _) => ("a request", "requests"),
    };
    if n == 1 {
        one.to_string()
    } else {
        format!("{n} {many}")
    }
}

fn kinds_suffix(k: &BTreeSet<String>) -> String {
    if k.is_empty() {
        return String::new();
    }
    let v: Vec<&str> = k.iter().map(String::as_str).collect();
    let shown = if v.len() > 4 {
        format!("{}, +{}", v[..4].join(", "), v.len() - 4)
    } else {
        v.join(", ")
    };
    format!(" ({shown})")
}

/// One line per (event, front door, direction) group, blocks first. Only
/// entity-kind labels of the safe shape (`kind_ok`) are shown.
pub fn render(records: &[ActivityRecord]) -> Vec<String> {
    // key: (0 = blocked, 1 = tripwire), front door, direction
    type Group = (FrontDoor, Direction, usize, BTreeSet<String>);
    let mut groups: BTreeMap<(u8, u8, u8), Group> = BTreeMap::new();
    for r in records.iter().filter(|r| !r.dataset.starts_with("check-")) {
        let event = match r.verdict {
            Verdict::Blocked | Verdict::Uncertain | Verdict::Unresolved | Verdict::Unsupported => 0,
            Verdict::Released if r.tripwire => 1,
            Verdict::Released => continue,
        };
        let key = (event, r.front_door as u8, r.direction as u8);
        let g = groups
            .entry(key)
            .or_insert((r.front_door, r.direction, 0, BTreeSet::new()));
        g.2 += 1;
        g.3.extend(
            r.kinds
                .iter()
                .map(|k| k.kind.clone())
                .filter(|k| kind_ok(k)),
        );
    }
    groups
        .into_iter()
        .map(|((event, _, _), (fd, dir, n, kinds))| match event {
            0 => format!("Blocked {}{}", what(fd, dir, n), kinds_suffix(&kinds)),
            _ => format!(
                "Stopped a known value in {}{}",
                what(fd, dir, n),
                kinds_suffix(&kinds)
            ),
        })
        .collect()
}
