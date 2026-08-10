//! Registro de lo revocado.
//!
//! Al borrar una entrada del permission store desaparece por completo: ni el
//! portal ni el sistema guardan que existió. Si dentro de un mes te preguntas
//! qué le quitaste a qué aplicación, no hay dónde mirarlo.
//!
//! Esto lo conserva. Es lo único de wayward que sobrevive a su propio objeto,
//! así que guarda todo lo que se sabía en el momento del borrado —la atribución
//! y los detalles decodificados— porque después ya no hay forma de recuperarlo.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::attrib::Cache;
use crate::store::Entry;

/// Un permiso que estuvo y ya no está.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub token: String,
    pub table: String,
    /// A quién estaba atribuido, si se sabía. No se puede reconstruir después.
    pub app: Option<String>,
    pub exe: Option<String>,
    /// Cuándo se concedió, si la tabla lo guardaba.
    pub issued_at: Option<i64>,
    pub revoked_at: i64,
    /// Los pares ya legibles que tenía la entrada: salida, cursor, backend.
    #[serde(default)]
    pub details: Vec<(String, String)>,
}

impl Revocation {
    /// Toma la foto de una entrada antes de que se borre.
    pub fn of(entry: &Entry, cache: &Cache, at: i64) -> Self {
        let record = cache.get(&entry.id);
        Self {
            token: entry.id.clone(),
            table: entry.table.clone(),
            app: record
                .map(|r| r.identity.label())
                .or_else(|| entry.apps().first().map(|a| a.to_string())),
            exe: record.and_then(|r| r.identity.exe.clone()),
            issued_at: entry.issued_at,
            revoked_at: at,
            details: entry.details.clone(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct History {
    #[serde(default)]
    pub revocations: Vec<Revocation>,
}

impl History {
    pub fn load() -> Result<Self> {
        let path = history_path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                serde_json::from_str(&raw).with_context(|| format!("{} is corrupt", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).context(format!("could not read {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = history_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let raw = serde_json::to_string_pretty(self)?;
        // Escritura atómica, igual que el mapa de atribuciones: este fichero es
        // la única copia de algo que ya no existe en ningún otro sitio.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, raw).with_context(|| format!("could not write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("could not move into place at {}", path.display()))?;
        Ok(())
    }

    pub fn record(&mut self, revocation: Revocation) {
        self.revocations.push(revocation);
    }

    /// Lo más reciente primero, que es como se quiere leer un histórico.
    pub fn newest_first(&self) -> Vec<&Revocation> {
        let mut all: Vec<&Revocation> = self.revocations.iter().collect();
        all.sort_by_key(|r| std::cmp::Reverse(r.revoked_at));
        all
    }
}

pub fn history_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/"));
            home.join(".local").join("state")
        });
    base.join("wayward").join("revocations.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrib::Identity;
    use std::collections::HashMap;

    fn entry(id: &str) -> Entry {
        Entry {
            table: "screencast".to_string(),
            id: id.to_string(),
            permissions: HashMap::from([(String::new(), vec!["yes".to_string()])]),
            data: serde_json::Value::Null,
            details: vec![("output".to_string(), "DP-1".to_string())],
            issued_at: Some(1_786_207_593),
        }
    }

    /// Lo que se sabía en el momento del borrado tiene que quedar congelado:
    /// después de borrar no hay forma de volver a averiguarlo.
    #[test]
    fn la_foto_conserva_la_atribucion_y_los_detalles() {
        let mut cache = Cache::default();
        cache.observe(
            "tok",
            Identity {
                pid: Some(1),
                exe: Some("/usr/bin/obs".to_string()),
                cmdline: None,
                comm: Some("obs".to_string()),
            },
            "screencast",
            0,
        );

        let revocation = Revocation::of(&entry("tok"), &cache, 1_786_300_000);
        assert_eq!(revocation.app.as_deref(), Some("obs"));
        assert_eq!(revocation.exe.as_deref(), Some("/usr/bin/obs"));
        assert_eq!(revocation.issued_at, Some(1_786_207_593));
        assert_eq!(revocation.details.len(), 1);
    }

    #[test]
    fn sin_atribucion_la_foto_sigue_siendo_util() {
        let revocation = Revocation::of(&entry("tok"), &Cache::default(), 10);
        assert!(revocation.app.is_none(), "no había a quién atribuirlo");
        assert_eq!(revocation.token, "tok");
        assert_eq!(revocation.revoked_at, 10);
    }

    #[test]
    fn el_historico_se_lee_del_mas_reciente_al_mas_viejo() {
        let mut history = History::default();
        for (token, at) in [("viejo", 100), ("nuevo", 300), ("medio", 200)] {
            let mut revocation = Revocation::of(&entry(token), &Cache::default(), at);
            revocation.token = token.to_string();
            history.record(revocation);
        }
        let orden: Vec<&str> = history
            .newest_first()
            .iter()
            .map(|r| r.token.as_str())
            .collect();
        assert_eq!(orden, vec!["nuevo", "medio", "viejo"]);
    }
}
