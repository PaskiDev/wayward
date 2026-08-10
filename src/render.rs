//! Presentación del informe.

use crate::attrib::{Cache, now};
use crate::journal::{Confidence, Resolution};
use crate::risk::{self, Risk};
use crate::sessions::Session;
use crate::store::{Decision, Entry};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;

/// Informe de `wayward resolve`.
pub fn report_resolution(results: &[Resolution], written: usize, min: Confidence, json: bool) {
    if json {
        let output = serde_json::json!({
            "generated_at": now(),
            "written": written,
            "min_confidence": min,
            "resolutions": results,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        return;
    }

    if results.is_empty() {
        println!(
            "\n  {}\n\n  Every granted permission already has a name.\n",
            "Nothing left to resolve.".bold()
        );
        return;
    }

    println!();
    for resolution in results {
        let when = match resolution.issued_at {
            Some(ts) => format_issued(ts),
            None => "no timestamp recorded".to_string(),
        };
        println!(
            "  {}   {} · {}",
            resolution.token.bold(),
            resolution.table,
            when.dimmed()
        );

        if resolution.issued_at.is_none() {
            println!(
                "    {}\n",
                "This table stores no grant time, so there is nothing to correlate against."
                    .dimmed()
            );
            continue;
        }
        if resolution.candidates.is_empty() {
            println!(
                "    {}\n",
                "No process logged anything in that window. The journal may not reach back \
                 that far."
                    .dimmed()
            );
            continue;
        }

        // Tres candidatos bastan: por debajo del tercero la señal es ruido.
        for candidate in resolution.candidates.iter().take(3) {
            let sign = if candidate.offset >= 0 { "+" } else { "-" };
            println!(
                "    {} {} {:>4}   {}",
                format!("{:<16}", truncate(&candidate.label, 16)).bold(),
                paint_confidence(candidate.confidence),
                format!("{}{}s", sign, candidate.offset.abs()),
                candidate.exe.as_deref().unwrap_or("").dimmed(),
            );
            if !candidate.evidence.is_empty() {
                let evidence = truncate(&candidate.evidence, 84);
                println!("    {:<16} {}", "", evidence.dimmed());
            }
        }
        println!();
    }

    if written > 0 {
        println!(
            "  {} {} {} written to the attribution map ({} confidence or better).",
            "✓".green(),
            written,
            plural(written, "attribution", "attributions"),
            min.label()
        );
    } else {
        println!(
            "  {}",
            "Nothing written. Re-run with --write to persist the attributions above.".dimmed()
        );
    }
    println!(
        "  {}\n",
        "These are correlations, not proof: a match means the process was logging at the \
         moment the permission was filed."
            .dimmed()
    );
}

/// El relleno va dentro del color, no fuera: `{:<8}` cuenta bytes, y los
/// códigos de escape ANSI cuentan como tales, así que colorear primero y
/// alinear después descuadra la columna entera.
/// Informe de `wayward sessions`.
pub fn report_sessions(sessions: &[Session], json: bool) {
    if json {
        let output = serde_json::json!({
            "generated_at": now(),
            "sessions": sessions,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        return;
    }

    if sessions.is_empty() {
        println!(
            "\n  {}\n\n  No application currently holds an open desktop-portal session.\n",
            "Nothing open.".bold()
        );
        return;
    }

    println!(
        "\n  {}   {}\n",
        "Open portal sessions".bold(),
        format!(
            "{} {}",
            sessions.len(),
            plural(sessions.len(), "session", "sessions")
        )
        .dimmed()
    );

    for session in sessions {
        let who = match &session.owner {
            Some(identity) => identity.label().green().bold().to_string(),
            // La conexión se fue entre listar y preguntar, o el bus no quiso
            // decirlo. La sesión existe igual y hay que enseñarla.
            None => "owner unresolved".yellow().to_string(),
        };
        println!("    {} {}", "●".red(), who);

        if let Some(identity) = &session.owner {
            if let Some(exe) = &identity.exe {
                println!("      {:<9} {}", "exe", exe.dimmed());
            }
            if let Some(cmdline) = &identity.cmdline {
                println!("      {:<9} {}", "cmdline", truncate(cmdline, 78).dimmed());
            }
            if let Some(pid) = identity.pid {
                println!(
                    "      {:<9} {}",
                    "pid",
                    format!("{pid} · {}", session.unique_name).dimmed()
                );
            }
        }
        println!("      {:<9} {}", "session", session.path.dimmed());
        println!();
    }

    println!(
        "  {} An open session is what capture runs on top of, not proof that capture is",
        "!".yellow().bold()
    );
    println!("    happening this instant. It does mean the application can resume without");
    println!("    any further prompt.\n");
}

fn paint_confidence(confidence: Confidence) -> String {
    let padded = format!("{:<7}", confidence.label());
    match confidence {
        Confidence::High => padded.green().bold().to_string(),
        Confidence::Medium => padded.yellow().to_string(),
        Confidence::Low => padded.dimmed().to_string(),
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

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
