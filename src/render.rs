//! Presentación del informe.

use crate::attrib::{Cache, now};
use crate::risk::{self, Risk};
use crate::store::{Decision, Entry};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;

pub fn report(entries: &[Entry], cache: &Cache, json: bool) {
    if json {
        report_json(entries, cache);
    } else {
        report_human(entries, cache);
    }
}

fn report_json(entries: &[Entry], cache: &Cache) {
    let items: Vec<_> = entries
        .iter()
        .map(|entry| {
            let info = risk::lookup(&entry.table);
            let attribution = cache.get(&entry.id).map(|record| {
                serde_json::json!({
                    "app": record.identity.label(),
                    "exe": record.identity.exe,
                    "cmdline": record.identity.cmdline,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                })
            });
            serde_json::json!({
                "table": entry.table,
                "id": entry.id,
                "risk": info.risk,
                "grants": info.grants,
                "decision": entry.decision(),
                "apps": entry.apps(),
                "unattributed": entry.unattributed(),
                "attribution": attribution,
                "issued_at": entry.issued_at,
                "data": entry.data,
            })
        })
        .collect();

    let output = serde_json::json!({
        "generated_at": now(),
        "permissions": items,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

fn report_human(entries: &[Entry], cache: &Cache) {
    if entries.is_empty() {
        println!(
            "\n  {}\n\n  No desktop-portal permission is granted on this machine.\n",
            "Nothing to audit.".bold()
        );
        return;
    }

    // Agrupar por tabla y ordenar por riesgo descendente, luego por nombre.
    let mut by_table: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    for entry in entries {
        by_table.entry(&entry.table).or_default().push(entry);
    }
    let mut tables: Vec<_> = by_table.into_iter().collect();
    tables.sort_by(|(a, _), (b, _)| {
        risk::lookup(b)
            .risk
            .cmp(&risk::lookup(a).risk)
            .then_with(|| a.cmp(b))
    });

    println!();
    for (table, mut group) in tables {
        let info = risk::lookup(table);
        let heading = format!("{}  ({table})", info.display);

        // Si en la tabla no hay nada concedido, el riesgo es teórico: anunciarlo
        // en rojo enseñaría al usuario a ignorar los rojos que sí importan.
        let any_granted = group.iter().any(|e| e.decision() == Decision::Granted);
        let badge = if any_granted {
            paint(info.risk)
        } else {
            format!("{} risk · nothing granted", info.risk.label())
                .dimmed()
                .to_string()
        };
        println!("  {}   {}", heading.bold(), badge);
        println!("  {}", info.grants.dimmed());
        println!("  {}", "─".repeat(66).dimmed());

        // Lo más reciente primero: un permiso recién concedido que no esperabas
        // es lo que más urge revisar.
        group.sort_by_key(|entry| std::cmp::Reverse(entry.issued_at.unwrap_or(0)));

        for entry in group {
            let status = match entry.decision() {
                // Un rechazo archivado protege en vez de exponer, así que se
                // enseña sin alarma.
                Decision::Denied => "denied".green().to_string(),
                Decision::Unknown => "non-standard value".dimmed().to_string(),
                Decision::Granted => match cache.get(&entry.id) {
                    Some(record) => record.identity.label().green().to_string(),
                    None if entry.unattributed() => "unattributed".yellow().to_string(),
                    None => entry.apps().join(", ").green().to_string(),
                },
            };
            println!("    {} {}   {}", "•".dimmed(), entry.id.bold(), status);

            if let Some(record) = cache.get(&entry.id)
                && let Some(exe) = &record.identity.exe
            {
                println!("      {:<11} {}", "executable", exe.dimmed());
            }
            if let Some(issued) = entry.issued_at {
                println!("      {:<11} {}", "granted", format_issued(issued));
            }
            for (label, value) in &entry.details {
                println!("      {label:<11} {value}");
            }
            println!();
        }
    }

    summarize(entries, cache);
}

fn summarize(entries: &[Entry], cache: &Cache) {
    let total = entries.len();
    let granted: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.decision() == Decision::Granted)
        .collect();
    let denied = entries
        .iter()
        .filter(|e| e.decision() == Decision::Denied)
        .count();
    // El riesgo se cuenta solo sobre lo concedido: un rechazo no expone nada.
    let high = granted
        .iter()
        .filter(|e| risk::lookup(&e.table).risk == Risk::High)
        .count();
    let unattributed = granted
        .iter()
        .filter(|e| e.unattributed() && cache.get(&e.id).is_none())
        .count();
    let tables = entries
        .iter()
        .map(|e| e.table.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();

    println!("  {}", "Summary".bold());
    print!(
        "    {} {} across {} {} · {} granted, {} high risk",
        total,
        plural(total, "permission", "permissions"),
        tables,
        plural(tables, "table", "tables"),
        granted.len(),
        high,
    );
    if denied > 0 {
        print!(" · {denied} denied");
    }
    println!(" · {unattributed} unattributed");

    if unattributed > 0 {
        println!();
        println!(
            "  {} Unattributed permissions belong to native applications. The portal",
            "!".yellow().bold()
        );
        println!("    derives the application identifier from the sandbox, so outside Flatpak");
        println!("    or Snap nothing records who asked for the permission: only a random");
        println!("    token that lets it resume access without ever asking again.");
        println!();
        println!(
            "    Run {} and use the application again to start building the",
            "wayward watch".bold()
        );
        println!("    map the system never keeps.");
    }
    println!();
}

fn paint(risk: Risk) -> String {
    let label = format!("{} risk", risk.label());
    match risk {
        Risk::High => label.red().bold().to_string(),
        Risk::Medium => label.yellow().to_string(),
        Risk::Low => label.blue().to_string(),
        Risk::Info => label.dimmed().to_string(),
    }
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        one.to_string()
    } else {
        many.to_string()
    }
}

pub fn format_issued(ts: i64) -> String {
    let when = jiff::Timestamp::from_second(ts)
        .map(|t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| ts.to_string());
    format!("{when} ({})", human_age(now() - ts))
}

fn human_age(secs: i64) -> String {
    if secs < 0 {
        return "dated in the future".to_string();
    }
    let minutes = secs / 60;
    let hours = minutes / 60;
    let days = hours / 24;

    if days >= 2 {
        format!("{days} days ago")
    } else if days == 1 {
        "1 day ago".to_string()
    } else if hours >= 2 {
        format!("{hours} hours ago")
    } else if hours == 1 {
        "1 hour ago".to_string()
    } else if minutes >= 2 {
        format!("{minutes} minutes ago")
    } else {
        "just now".to_string()
    }
}
