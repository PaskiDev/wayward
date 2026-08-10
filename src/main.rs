//! wayward — audita los permisos persistentes de portal en un escritorio Wayland.

mod attrib;
mod history;
mod journal;
mod notify;
mod render;
mod risk;
mod service;
mod sessions;
mod store;
mod tui;
mod watch;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use std::io::Write;

use attrib::Cache;
use store::PermissionStoreProxy;

#[derive(Parser)]
#[command(
    name = "wayward",
    version,
    about = "Audit which applications hold desktop-portal permissions on Wayland",
    long_about = "Desktop portals grant persistent permissions —screen capture, camera, \
                  location— that outlive the application that asked for them. Outside \
                  Flatpak those permissions are filed under an anonymous token and no tool \
                  shows them. wayward lists them, attributes them and revokes them."
)]
struct Cli {
    /// Sin subcomando se abre la interfaz de terminal.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the terminal interface, with the bus monitor running inside
    Tui,

    /// List the desktop-portal permissions granted on this machine
    List {
        /// JSON output, for composing with other tools
        #[arg(long)]
        json: bool,
        /// Restrict the report to a single table
        #[arg(long, value_name = "TABLE")]
        table: Option<String>,
    },

    /// Watch the bus and work out which application asks for each permission
    Watch {
        /// One JSON line per event
        #[arg(long)]
        json: bool,
        /// Quiet mode for running under systemd: log grants only, never calls
        #[arg(long)]
        daemon: bool,
        /// Do not raise a desktop notification when a grant appears
        #[arg(long)]
        no_notify: bool,
    },

    /// Install the monitor as a systemd user service, so attribution happens
    /// without you having to remember to watch
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Show which applications hold an open portal session right now, and who
    /// they are — no monitor or history required
    Sessions {
        /// JSON output
        #[arg(long)]
        json: bool,
    },

    /// Recover the identity of permissions granted before wayward was watching,
    /// by correlating their grant time against the journal
    Resolve {
        /// Seconds to search either side of the grant time
        #[arg(long, default_value_t = 10)]
        window: i64,
        /// Persist the winning candidates to the attribution map
        #[arg(long)]
        write: bool,
        /// Confidence a candidate needs before --write will record it
        #[arg(long, value_enum, default_value_t = journal::Confidence::High)]
        min_confidence: journal::Confidence,
        /// JSON output
        #[arg(long)]
        json: bool,
    },

    /// Revoke a granted permission
    Revoke {
        /// Permission token, as shown by `wayward list`
        #[arg(value_name = "TOKEN")]
        token: Option<String>,
        /// Revoke every permission in a table
        #[arg(long, value_name = "TABLE", conflicts_with = "token")]
        table: Option<String>,
        /// Show what would be deleted without touching anything
        #[arg(long)]
        dry_run: bool,
        /// Do not ask for confirmation
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Write the unit, enable it, and start watching
    Install {
        /// Enable only; start with the next graphical session instead of now
        #[arg(long)]
        later: bool,
    },
    /// Stop the service and remove the unit
    Uninstall,
    /// Show whether the monitor is running
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Command::Tui) => tui::run().await,
        Some(Command::List { json, table }) => list(json, table).await,
        Some(Command::Watch {
            json,
            daemon,
            no_notify,
        }) => {
            watch::run(watch::Options {
                json,
                daemon,
                notify: !no_notify,
            })
            .await
        }
        Some(Command::Service { action }) => match action {
            ServiceAction::Install { later } => service::install(!later),
            ServiceAction::Uninstall => service::uninstall(),
            ServiceAction::Status => service::status(),
        },
        Some(Command::Sessions { json }) => list_sessions(json).await,
        Some(Command::Resolve {
            window,
            write,
            min_confidence,
            json,
        }) => resolve(window, write, min_confidence, json).await,
        Some(Command::Revoke {
            token,
            table,
            dry_run,
            yes,
        }) => revoke(token, table, dry_run, yes).await,
    }
}

/// Abre el proxy del permission store con un error legible si no está.
async fn connect() -> Result<PermissionStoreProxy<'static>> {
    let connection = zbus::Connection::session()
        .await
        .context("could not connect to the session bus")?;

    PermissionStoreProxy::new(&connection).await.context(
        "could not reach the permission store; \
         is xdg-desktop-portal running in this session?",
    )
}

async fn collect(proxy: &PermissionStoreProxy<'_>, only: Option<&str>) -> Result<Vec<store::Entry>> {
    let tables = match only {
        Some(table) => vec![table.to_string()],
        None => store::discover_tables()?,
    };

    let mut entries = Vec::new();
    for table in tables {
        entries.extend(store::read_table(proxy, &table).await?);
    }
    Ok(entries)
}

async fn list(json: bool, table: Option<String>) -> Result<()> {
    let proxy = connect().await?;
    let entries = collect(&proxy, table.as_deref()).await?;
    let cache = Cache::load()?;
    render::report(&entries, &cache, json);
    Ok(())
}

/// Quién tiene una sesión de portal abierta en este instante.
async fn list_sessions(json: bool) -> Result<()> {
    let connection = zbus::Connection::session()
        .await
        .context("could not connect to the session bus")?;
    let sessions = sessions::live(&connection).await?;
    render::report_sessions(&sessions, json);
    Ok(())
}

/// Reconstruye la autoría de los permisos que nadie vio conceder.
async fn resolve(
    window: i64,
    write: bool,
    min_confidence: journal::Confidence,
    json: bool,
) -> Result<()> {
    let proxy = connect().await?;
    let entries = collect(&proxy, None).await?;
    let mut cache = Cache::load()?;

    // Solo tiene sentido sobre lo concedido y sin atribuir: un rechazo no
    // necesita dueño, y lo ya atribuido no se toca.
    let pending: Vec<_> = entries
        .iter()
        .filter(|e| e.decision() == store::Decision::Granted)
        .filter(|e| e.unattributed() && cache.get(&e.id).is_none())
        .collect();

    let mut results = Vec::new();
    for entry in pending {
        let candidates = match entry.issued_at {
            Some(issued) => journal::resolve(&entry.table, issued, window)?,
            None => Vec::new(),
        };
        results.push(journal::Resolution {
            token: entry.id.clone(),
            table: entry.table.clone(),
            issued_at: entry.issued_at,
            candidates,
        });
    }

    let mut written = 0;
    if write {
        for resolution in &results {
            let Some(candidate) = resolution.best(min_confidence) else {
                continue;
            };
            cache.observe(
                &resolution.token,
                attrib::Identity {
                    pid: candidate.pid,
                    exe: candidate.exe.clone(),
                    cmdline: None,
                    comm: Some(candidate.label.clone()),
                },
                &resolution.table,
                attrib::now(),
            );
            written += 1;
        }
        if written > 0 {
            cache.save()?;
        }
    }

    render::report_resolution(&results, written, min_confidence, json);
    Ok(())
}

async fn revoke(
    token: Option<String>,
    table: Option<String>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let proxy = connect().await?;

    let targets: Vec<store::Entry> = match (&token, &table) {
        (Some(token), _) => {
            let all = collect(&proxy, None).await?;
            let found: Vec<_> = all.into_iter().filter(|e| &e.id == token).collect();
            if found.is_empty() {
                bail!("no permission found with token \"{token}\"");
            }
            found
        }
        (None, Some(table)) => {
            let found = collect(&proxy, Some(table)).await?;
            if found.is_empty() {
                bail!("table \"{table}\" has no permissions to revoke");
            }
            found
        }
        (None, None) => bail!("give a token, or a table with --table"),
    };

    let cache = Cache::load()?;
    println!(
        "\n  {} {} will be revoked:\n",
        targets.len(),
        render::plural(targets.len(), "permission", "permissions")
    );
    for entry in &targets {
        let who = match cache.get(&entry.id) {
            Some(record) => record.identity.label(),
            None => "unattributed".to_string(),
        };
        println!("    {}  {}  ({})", entry.table.bold(), entry.id, who);
    }
    println!();

    if dry_run {
        println!("  {} nothing was touched.\n", "--dry-run:".dimmed());
        return Ok(());
    }

    if !yes && !confirm()? {
        println!("  Cancelled.\n");
        return Ok(());
    }

    // La foto se toma antes de borrar: después el permiso no existe en ninguna
    // parte y no hay forma de reconstruir a quién pertenecía.
    let mut log = history::History::load()?;
    for entry in &targets {
        log.record(history::Revocation::of(entry, &cache, attrib::now()));
        proxy
            .delete(&entry.table, &entry.id)
            .await
            .with_context(|| format!("could not delete \"{}\" from \"{}\"", entry.id, entry.table))?;
    }
    log.save()?;

    println!(
        "  {} {} {} revoked.\n",
        "✓".green(),
        targets.len(),
        render::plural(targets.len(), "permission", "permissions")
    );
    println!(
        "  {}\n",
        "The application will ask for permission again next time it needs it.".dimmed()
    );
    Ok(())
}

fn confirm() -> Result<bool> {
    print!("  Confirm? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(is_affirmative(&answer))
}

/// «sí» cuenta igual que «yes»: la interfaz está en inglés, quien la usa no
/// necesariamente, y una revocación perdida por eso es un fallo de diseño.
fn is_affirmative(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Al traducir la interfaz al inglés la confirmación pasó de `s` a `y`, y
    /// pulsar «s» de sí cancelaba en silencio. Este test existe para que no
    /// vuelva a pasar.
    #[test]
    fn el_si_en_castellano_confirma_igual_que_el_yes() {
        for afirmativo in ["y", "Y", "yes", "s", "S", "si", "sí", "SÍ", " s "] {
            assert!(is_affirmative(afirmativo), "«{afirmativo}» debería confirmar");
        }
    }

    #[test]
    fn lo_demas_cancela() {
        for negativo in ["", "n", "no", "nope", "x", "yy", "quiza"] {
            assert!(!is_affirmative(negativo), "«{negativo}» no debería confirmar");
        }
    }
}
