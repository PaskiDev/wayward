//! Sesiones de portal abiertas ahora mismo.
//!
//! `list` enseña permisos, que es una capacidad latente: quién *podría*. Esto
//! enseña quién tiene una sesión abierta *en este momento*, que es otra pregunta
//! y normalmente la que de verdad preocupa.
//!
//! El portal publica un objeto por sesión viva bajo
//! `/org/freedesktop/portal/desktop/session/<REMITENTE>/<token>`, con el mismo
//! fragmento de conexión que ya se usa para correlacionar Requests. La
//! diferencia es que aquí la transformación se recorre al revés: del fragmento
//! se reconstruye el nombre único (`1_181` → `:1.181`), se pregunta al bus por
//! su PID y de ahí se llega al ejecutable.
//!
//! Ventaja sobre el monitor: esto no necesita haber estado escuchando. Funciona
//! en una máquina donde wayward se acaba de instalar, y ve también las sesiones
//! reanudadas con un restore token, que no generan ningún evento nuevo.

use anyhow::{Context, Result};
use serde::Serialize;
use zbus::names::BusName;
use zbus::{Connection, fdo};

use crate::attrib::Identity;

const ROOT: &str = "/org/freedesktop/portal/desktop/session";

/// Una sesión de portal abierta.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub path: String,
    /// Nombre único de la conexión que la abrió, reconstruido del fragmento.
    pub unique_name: String,
    /// Token elegido por la propia aplicación al crear la sesión.
    pub token: String,
    /// Quién está detrás, si la conexión sigue viva.
    pub owner: Option<Identity>,
}

/// Reconstruye el nombre único a partir del fragmento de la ruta.
///
/// Es la inversa exacta de lo que hace el portal al construirla: los nombres
/// únicos son siempre `:N.M`, así que devolver los dos puntos y los puntos
/// intermedios recupera el original sin ambigüedad.
fn unique_name_from(fragment: &str) -> String {
    format!(":{}", fragment.replace('_', "."))
}

/// Extrae los nodos hijos de un documento de introspección.
///
/// Los hijos aparecen como `<node name="1_181"/>`; el elemento raíz lleva una
/// ruta absoluta o no lleva nombre, y por eso se descartan los que tienen
/// barras. Es un análisis deliberadamente mínimo: el formato lo fija la
/// especificación de D-Bus y no merece arrastrar un parser de XML entero.
fn child_nodes(xml: &str) -> Vec<String> {
    let mut children = Vec::new();
    for chunk in xml.split("<node name=\"").skip(1) {
        let Some(end) = chunk.find('"') else { continue };
        let name = &chunk[..end];
        if name.is_empty() || name.contains('/') {
            continue;
        }
        children.push(name.to_string());
    }
    children
}

async fn introspect(connection: &Connection, path: &str) -> Result<String> {
    let proxy = fdo::IntrospectableProxy::builder(connection)
        .destination("org.freedesktop.portal.Desktop")?
        .path(path.to_string())?
        .build()
        .await?;
    Ok(proxy.introspect().await?)
}

/// Enumera las sesiones abiertas y resuelve a quién pertenecen.
pub async fn live(connection: &Connection) -> Result<Vec<Session>> {
    let root = introspect(connection, ROOT)
        .await
        .context("no se pudo listar el árbol de sesiones del portal")?;

    let dbus = fdo::DBusProxy::new(connection).await?;
    let mut sessions = Vec::new();

    for fragment in child_nodes(&root) {
        let branch = format!("{ROOT}/{fragment}");
        // Una conexión puede haber cerrado entre listar y consultar; no es un
        // error, solo una sesión que ya no está.
        let Ok(xml) = introspect(connection, &branch).await else {
            continue;
        };

        for token in child_nodes(&xml) {
            let unique_name = unique_name_from(&fragment);
            let owner = match BusName::try_from(unique_name.clone()) {
                Ok(name) => match dbus.get_connection_unix_process_id(name).await {
                    Ok(pid) => Some(Identity::from_pid(pid)),
                    Err(_) => None,
                },
                Err(_) => None,
            };

            sessions.push(Session {
                path: format!("{branch}/{token}"),
                unique_name,
                token,
                owner,
            });
        }
    }

    sessions.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_fragmento_recupera_el_nombre_unico() {
        // Caso capturado en vivo durante el desarrollo: la conexión :1.181
        // produjo la ruta .../session/1_181/holdses1.
        assert_eq!(unique_name_from("1_181"), ":1.181");
        assert_eq!(unique_name_from("1_1066"), ":1.1066");
    }

    /// El viaje de ida y vuelta con la transformación que aplica el portal.
    #[test]
    fn la_conversion_es_reversible() {
        for original in [":1.5", ":1.181", ":1.99999"] {
            let fragment = original.trim_start_matches(':').replace('.', "_");
            assert_eq!(unique_name_from(&fragment), original);
        }
    }

    #[test]
    fn se_leen_los_nodos_hijos_y_no_la_raiz() {
        let xml = r#"<!DOCTYPE node PUBLIC "..." "...">
<node name="/org/freedesktop/portal/desktop/session">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect"><arg name="xml" type="s" direction="out"/></method>
  </interface>
  <node name="1_181"/>
  <node name="1_66"/>
</node>"#;
        // La raíz lleva ruta absoluta y no debe colarse como sesión.
        assert_eq!(child_nodes(xml), vec!["1_181", "1_66"]);
    }

    #[test]
    fn un_arbol_vacio_no_da_sesiones() {
        let xml = r#"<node name="/org/freedesktop/portal/desktop/session"></node>"#;
        assert!(child_nodes(xml).is_empty());
    }
}
