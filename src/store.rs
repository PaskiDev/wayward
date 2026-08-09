//! Cliente del permission store de `xdg-desktop-portal`.
//!
//! La base de datos vive en `$XDG_DATA_HOME/flatpak/db`, un fichero GVDB por
//! tabla. Ese directorio existe aunque Flatpak no esté instalado: la ruta viene
//! del componente `xdg-desktop-permission-store`, que la heredó de Flatpak y la
//! usa igual para aplicaciones nativas. Por eso wayward nunca asume Flatpak.
//!
//! Se lee por D-Bus en vez de parsear el GVDB a mano para no competir con el
//! demonio, que mantiene el fichero abierto y lo reescribe entero al cambiarlo.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use zbus::zvariant::{OwnedValue, Value};

#[zbus::proxy(
    interface = "org.freedesktop.impl.portal.PermissionStore",
    default_service = "org.freedesktop.impl.portal.PermissionStore",
    default_path = "/org/freedesktop/impl/portal/PermissionStore"
)]
pub trait PermissionStore {
    fn list(&self, table: &str) -> zbus::Result<Vec<String>>;

    fn lookup(
        &self,
        table: &str,
        id: &str,
    ) -> zbus::Result<(HashMap<String, Vec<String>>, OwnedValue)>;

    fn delete(&self, table: &str, id: &str) -> zbus::Result<()>;
}

/// Un permiso concedido: una fila de una tabla.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub table: String,
    pub id: String,
    /// App ID → permisos concedidos. La clave vacía significa "aplicación sin
    /// identificar", que es lo normal fuera de un sandbox: el portal deriva el
    /// app ID del cgroup del solicitante y una aplicación nativa no tiene.
    pub permissions: HashMap<String, Vec<String>>,
    /// Los datos asociados, tal cual, para `--json` y para tablas que wayward
    /// todavía no sabe interpretar.
    pub data: serde_json::Value,
    /// Pares etiqueta/valor ya legibles, cuando la tabla se sabe interpretar.
    pub details: Vec<(String, String)>,
    /// Momento de concesión en segundos Unix, si la tabla lo guarda.
    pub issued_at: Option<i64>,
}

/// Qué decidió el usuario sobre este permiso.
///
/// El permission store guarda tanto las concesiones como los rechazos, y
/// confundirlos sería el peor fallo posible en una herramienta como esta: un
/// rechazo archivado no es una exposición, es exactamente lo contrario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Granted,
    Denied,
    /// Valores que no son ni «yes» ni «no»: los inventa cada portal y hay que
    /// mirarlos a mano en vez de suponer.
    Unknown,
}

impl Entry {
    /// Cierto si ninguna aplicación identificable figura en el permiso.
    pub fn unattributed(&self) -> bool {
        self.permissions.keys().all(|app| app.is_empty())
    }

    pub fn decision(&self) -> Decision {
        let values: Vec<&str> = self
            .permissions
            .values()
            .flatten()
            .map(String::as_str)
            .collect();

        if values.is_empty() {
            Decision::Unknown
        } else if values.iter().any(|v| v.eq_ignore_ascii_case("yes")) {
            Decision::Granted
        } else if values.iter().all(|v| v.eq_ignore_ascii_case("no")) {
            Decision::Denied
        } else {
            Decision::Unknown
        }
    }

    /// Los app IDs reales que constan en el permiso, sin la clave vacía.
    pub fn apps(&self) -> Vec<&str> {
        let mut apps: Vec<&str> = self
            .permissions
            .keys()
            .filter(|app| !app.is_empty())
            .map(String::as_str)
            .collect();
        apps.sort_unstable();
        apps
    }
}

/// Directorio donde el permission store guarda una tabla por fichero.
pub fn db_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/"));
            home.join(".local").join("share")
        });
    base.join("flatpak").join("db")
}

/// Enumera las tablas existentes.
///
/// No hay método D-Bus para listarlas, así que hay que mirar el directorio. Se
/// descartan los ficheros temporales que GLib deja al reescribir de forma
/// atómica.
pub fn discover_tables() -> Result<Vec<String>> {
    let dir = db_dir();
    let read = match std::fs::read_dir(&dir) {
        Ok(read) => read,
        // Sin permisos concedidos nunca, el directorio puede no existir.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context(format!("could not read {}", dir.display())),
    };

    let mut tables = Vec::new();
    for entry in read {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        tables.push(name);
    }
    tables.sort();
    Ok(tables)
}

/// Lee todas las entradas de una tabla.
pub async fn read_table(proxy: &PermissionStoreProxy<'_>, table: &str) -> Result<Vec<Entry>> {
    let ids = proxy
        .list(table)
        .await
        .with_context(|| format!("List on table \"{table}\""))?;

    let mut entries = Vec::with_capacity(ids.len());
    for id in ids {
        let (permissions, data) = proxy
            .lookup(table, &id)
            .await
            .with_context(|| format!("Lookup of \"{id}\" in \"{table}\""))?;

        let json = value_to_json(&data);
        let (details, issued_at) = interpret(table, &json);

        entries.push(Entry {
            table: table.to_string(),
            id,
            permissions,
            data: json,
            details,
            issued_at,
        });
    }
    Ok(entries)
}

/// Convierte un valor de D-Bus en JSON para poder mostrarlo o serializarlo sin
/// conocer su tipo de antemano.
pub fn value_to_json(value: &Value<'_>) -> serde_json::Value {
    use serde_json::Value as J;

    match value {
        Value::U8(n) => J::from(*n),
        Value::Bool(b) => J::from(*b),
        Value::I16(n) => J::from(*n),
        Value::U16(n) => J::from(*n),
        Value::I32(n) => J::from(*n),
        Value::U32(n) => J::from(*n),
        Value::I64(n) => J::from(*n),
        Value::U64(n) => J::from(*n),
        Value::F64(n) => J::from(*n),
        Value::Str(s) => J::from(s.as_str()),
        Value::Signature(s) => J::from(s.to_string()),
        Value::ObjectPath(p) => J::from(p.as_str()),
        // Un variant anidado: se desenvuelve y ya está.
        Value::Value(inner) => value_to_json(inner),
        Value::Array(array) => J::Array(array.iter().map(value_to_json).collect()),
        Value::Dict(dict) => {
            let mut map = serde_json::Map::new();
            for (k, v) in dict.iter() {
                // Las claves de D-Bus pueden no ser cadenas; JSON exige que lo
                // sean, así que se representan por su forma textual.
                let key = match value_to_json(k) {
                    J::String(s) => s,
                    other => other.to_string(),
                };
                map.insert(key, value_to_json(v));
            }
            J::Object(map)
        }
        Value::Structure(s) => J::Array(s.fields().iter().map(value_to_json).collect()),
        other => J::String(format!("{other:?}")),
    }
}

/// Traduce los datos de una tabla conocida a pares legibles.
///
/// Devuelve además el instante de concesión si la tabla lo guarda, que es lo
/// único que permite ordenar los permisos por antigüedad.
fn interpret(table: &str, data: &serde_json::Value) -> (Vec<(String, String)>, Option<i64>) {
    match table {
        "screencast" => interpret_screencast(data),
        _ => (Vec::new(), None),
    }
}

/// Los datos de `screencast` son `(suv)`: vendor del backend, versión del
/// formato y un diccionario que rellena cada backend a su gusto. Lo que sigue
/// está verificado contra xdg-desktop-portal-hyprland 1.4.0; otros backends
/// pueden guardar claves distintas, así que todo se lee de forma tolerante.
fn interpret_screencast(data: &serde_json::Value) -> (Vec<(String, String)>, Option<i64>) {
    let Some(fields) = data.as_array() else {
        return (Vec::new(), None);
    };

    let vendor = fields.first().and_then(|v| v.as_str());
    let version = fields.get(1).and_then(serde_json::Value::as_u64);
    let payload = fields.get(2).and_then(|v| v.as_object());

    let mut details = Vec::new();
    let mut issued_at = None;

    if let Some(payload) = payload {
        if let Some(output) = payload.get("output").and_then(|v| v.as_str()) {
            details.push(("output".to_string(), output.to_string()));
        }
        if let Some(cursor) = payload.get("withCursor").and_then(serde_json::Value::as_u64) {
            details.push(("cursor".to_string(), cursor_mode(cursor).to_string()));
        }
        issued_at = payload
            .get("timeIssued")
            .and_then(serde_json::Value::as_i64);
    }

    if let Some(vendor) = vendor {
        let backend = match version {
            Some(v) => format!("{vendor} (format v{v})"),
            None => vendor.to_string(),
        };
        details.push(("backend".to_string(), backend));
    }

    (details, issued_at)
}

/// Modos de cursor del portal ScreenCast: máscara de bits con oculto, incrustado
/// en la imagen y enviado aparte como metadatos.
fn cursor_mode(bits: u64) -> &'static str {
    match bits {
        1 => "hidden",
        2 => "embedded in the image",
        4 => "as metadata",
        _ => "non-standard mode",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(permissions: HashMap<String, Vec<String>>) -> Entry {
        Entry {
            table: "devices".to_string(),
            id: "camera".to_string(),
            permissions,
            data: serde_json::Value::Null,
            details: Vec::new(),
            issued_at: None,
        }
    }

    /// Forma real de un permiso concedido a una aplicación nativa, con el app ID
    /// vacío, tal como lo devuelve xdg-desktop-portal 1.22.1.
    #[test]
    fn un_yes_es_una_concesion() {
        let permissions = HashMap::from([(String::new(), vec!["yes".to_string()])]);
        assert_eq!(entry(permissions).decision(), Decision::Granted);
    }

    /// Confundir esto con una concesión sería el peor falso positivo posible:
    /// el rechazo protege, y avisarlo como riesgo entrena al usuario a ignorar
    /// la herramienta.
    #[test]
    fn un_no_es_un_rechazo() {
        let permissions = HashMap::from([(String::new(), vec!["no".to_string()])]);
        assert_eq!(entry(permissions).decision(), Decision::Denied);
    }

    #[test]
    fn basta_un_yes_de_cualquier_app_para_que_este_concedido() {
        let permissions = HashMap::from([
            ("org.ejemplo.Uno".to_string(), vec!["no".to_string()]),
            ("org.ejemplo.Dos".to_string(), vec!["yes".to_string()]),
        ]);
        assert_eq!(entry(permissions).decision(), Decision::Granted);
    }

    #[test]
    fn lo_que_no_se_reconoce_no_se_supone() {
        let vacio = entry(HashMap::new());
        assert_eq!(vacio.decision(), Decision::Unknown);

        let raro = HashMap::from([(String::new(), vec!["ask".to_string()])]);
        assert_eq!(entry(raro).decision(), Decision::Unknown);
    }

    #[test]
    fn el_app_id_vacio_marca_lo_no_atribuible() {
        let anonimo = HashMap::from([(String::new(), vec!["yes".to_string()])]);
        assert!(entry(anonimo).unattributed());

        let con_sandbox =
            HashMap::from([("com.obsproject.Studio".to_string(), vec!["yes".to_string()])]);
        let entry = entry(con_sandbox);
        assert!(!entry.unattributed());
        assert_eq!(entry.apps(), vec!["com.obsproject.Studio"]);
    }
}
