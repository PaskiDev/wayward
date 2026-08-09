//! wayward — audita los permisos persistentes de portal en un escritorio Wayland.

mod attrib;
mod render;
mod risk;
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Command::Tui) => tui::run().await,
        Some(Command::List { json, table }) => list(json, table).await,
        Some(Command::Watch { json }) => watch::run(json).await,
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

    for entry in &targets {
        proxy
            .delete(&entry.table, &entry.id)
            .await
            .with_context(|| format!("could not delete \"{}\" from \"{}\"", entry.id, entry.table))?;
    }

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
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}
