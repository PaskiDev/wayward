//! Instalación del monitor como unidad de usuario de systemd.
//!
//! La atribución en vivo solo funciona si alguien está escuchando en el momento
//! exacto en que la aplicación pide el permiso, lo que en la práctica significa
//! nunca. Esto convierte esa función de teórica en real: el monitor arranca con
//! la sesión gráfica y se para con ella.
//!
//! Va a `graphical-session.target` y no a `default.target` porque el monitor no
//! tiene sentido sin sesión: sin portal no hay permisos que observar.

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::process::Command;

const UNIT: &str = "wayward.service";

pub fn unit_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/"));
            home.join(".config")
        });
    base.join("systemd").join("user").join(UNIT)
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .context("no se pudo ejecutar systemctl; ¿hay systemd en esta sesión?")?;
    if !status.success() {
        anyhow::bail!("systemctl --user {} falló", args.join(" "));
    }
    Ok(())
}

pub fn install(start_now: bool) -> Result<()> {
    // La unidad apunta al binario que la instala, no a un nombre en el PATH:
    // así no hay ambigüedad sobre qué copia va a correr durante meses.
    let exe = std::env::current_exe().context("no se pudo determinar el binario actual")?;
    let exe = exe.canonicalize().unwrap_or(exe);

    let unit = format!(
        "[Unit]\n\
         Description=wayward — watch desktop-portal permission grants\n\
         Documentation=https://github.com/PaskiDev/wayward\n\
         PartOf=graphical-session.target\n\
         After=graphical-session.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} watch --daemon\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=graphical-session.target\n",
        exe.display()
    );

    let path = unit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("no se pudo crear {}", parent.display()))?;
    }
    std::fs::write(&path, unit).with_context(|| format!("no se pudo escribir {}", path.display()))?;

    systemctl(&["daemon-reload"])?;

    println!("\n  {} {}", "✓".green(), path.display());
    println!("    {} {}", "runs".dimmed(), exe.display().to_string().dimmed());

    if start_now {
        systemctl(&["enable", "--now", UNIT])?;
        println!("  {} enabled and started", "✓".green());
    } else {
        systemctl(&["enable", UNIT])?;
        println!("  {} enabled; starts with your next graphical session", "✓".green());
        println!(
            "    {}\n",
            "Start it now with: systemctl --user start wayward.service".dimmed()
        );
        return Ok(());
    }

    println!(
        "\n  {}\n",
        "Every persistent grant from now on gets attributed and announced."
            .dimmed()
    );
    Ok(())
}

pub fn uninstall() -> Result<()> {
    // Se ignoran los fallos al parar: la unidad puede estar ya detenida o no
    // haber llegado nunca a habilitarse, y eso no es un error aquí.
    let _ = systemctl(&["disable", "--now", UNIT]);

    let path = unit_path();
    match std::fs::remove_file(&path) {
        Ok(()) => println!("\n  {} removed {}\n", "✓".green(), path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("\n  {} was not installed\n", UNIT.dimmed());
            return Ok(());
        }
        Err(e) => return Err(e).context(format!("no se pudo borrar {}", path.display())),
    }

    systemctl(&["daemon-reload"])?;
    println!(
        "  {}\n",
        "The attribution map is kept; delete it by hand if you want it gone.".dimmed()
    );
    Ok(())
}

pub fn status() -> Result<()> {
    let path = unit_path();
    if !path.exists() {
        println!(
            "\n  {} install it with: wayward service install\n",
            "Not installed.".bold()
        );
        return Ok(());
    }
    // `status` devuelve un código distinto de cero cuando la unidad está parada,
    // que aquí es información y no un fallo, así que no se comprueba.
    let _ = Command::new("systemctl")
        .args(["--user", "status", "--no-pager", UNIT])
        .status();
    Ok(())
}
