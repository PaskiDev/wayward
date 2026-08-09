//! El mapa token → aplicación que el sistema no guarda.
//!
//! Cuando una aplicación nativa pide un permiso de portal, el permission store
//! lo archiva bajo un token aleatorio y con el app ID vacío, porque ese
//! identificador se deriva del sandbox y una aplicación nativa no tiene. El
//! resultado es un permiso permanente que no se puede atribuir a nadie.
//!
//! Aquí se guarda lo que `wayward watch` observa en el bus: qué proceso pidió
//! qué token. Es la pieza que convierte un listado de tokens opacos en un
//! informe legible, y solo cubre lo ocurrido desde la primera ejecución.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Identidad de un proceso, reconstruida desde `/proc`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Identity {
    pub pid: Option<u32>,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub comm: Option<String>,
}

impl Identity {
    pub fn from_pid(pid: u32) -> Self {
        let base = PathBuf::from("/proc").join(pid.to_string());

        let exe = std::fs::read_link(base.join("exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // `cmdline` viene separado por nul y termina en nul.
        let cmdline = std::fs::read(base.join("cmdline")).ok().map(|raw| {
            String::from_utf8_lossy(&raw)
                .split('\0')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        });

        let comm = std::fs::read_to_string(base.join("comm"))
            .ok()
            .map(|s| s.trim().to_string());

        Self {
            pid: Some(pid),
            exe,
            cmdline: cmdline.filter(|s| !s.is_empty()),
            comm: comm.filter(|s| !s.is_empty()),
        }
    }

    /// Nombre corto para mostrar en el informe.
    pub fn label(&self) -> String {
        if let Some(exe) = &self.exe {
            // El kernel añade " (deleted)" si el binario se reemplazó estando
            // el proceso vivo, lo cual pasa a menudo tras actualizar paquetes.
            let exe = exe.trim_end_matches(" (deleted)");
            if let Some(name) = exe.rsplit('/').next().filter(|n| !n.is_empty()) {
                return name.to_string();
            }
        }
        if let Some(comm) = &self.comm {
            return comm.clone();
        }
        if let Some(cmdline) = &self.cmdline
            && let Some(first) = cmdline.split_whitespace().next()
        {
            return first.to_string();
        }
        match self.pid {
            Some(pid) => format!("pid {pid}"),
            None => "unknown".to_string(),
        }
    }
}

/// Una atribución observada.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    #[serde(flatten)]
    pub identity: Identity,
    /// Tabla del permiso, por si un mismo proceso pide varios tipos.
    pub table: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// Persistencia del mapa, en JSON para que sea inspeccionable a mano.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Cache {
    #[serde(default)]
    pub tokens: HashMap<String, Record>,
}

impl Cache {
    pub fn load() -> Result<Self> {
        let path = cache_path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw)
                .with_context(|| format!("{} is corrupt", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).context(format!("could not read {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = cache_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let raw = serde_json::to_string_pretty(self)?;
        // Escritura atómica: si wayward muere a media escritura, el mapa previo
        // sigue intacto en vez de quedar truncado.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, raw).with_context(|| format!("could not write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("could not move into place at {}", path.display()))?;
        Ok(())
    }

    pub fn get(&self, token: &str) -> Option<&Record> {
        self.tokens.get(token)
    }

    /// Registra que `identity` pidió `token`. Conserva el primer avistamiento.
    pub fn observe(&mut self, token: &str, identity: Identity, table: &str, now: i64) {
        self.tokens
            .entry(token.to_string())
            .and_modify(|record| {
                record.identity = identity.clone();
                record.last_seen = now;
            })
            .or_insert(Record {
                identity,
                table: table.to_string(),
                first_seen: now,
                last_seen: now,
            });
    }
}

pub fn cache_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/"));
            home.join(".local").join("state")
        });
    base.join("wayward").join("attribution.json")
}

/// Segundos Unix actuales.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
