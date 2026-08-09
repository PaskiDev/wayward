//! Observador del bus: construye la atribución que el sistema no guarda.
//!
//! La idea: el permission store archiva el permiso *después*, ya anonimizado,
//! pero la petición viaja por D-Bus y ahí el remitente sí es identificable. Un
//! monitor del bus ve la llamada, resuelve la conexión a PID y de ahí a un
//! ejecutable en `/proc`.
//!
//! La correlación con el token se apoya en cómo el portal construye la ruta del
//! objeto Request:
//!
//! ```text
//! /org/freedesktop/portal/desktop/request/<REMITENTE>/<handle_token>
//! ```
//!
//! donde `<REMITENTE>` es el nombre único del solicitante sin los dos puntos
//! iniciales y con los puntos convertidos en guiones bajos. Esa ruta aparece en
//! la señal `Response`, así que basta con deshacer la transformación para saber
//! quién estaba detrás del `restore_token` que devuelve el portal.
//!
//! El monitor no imprime ni persiste nada: emite eventos por un canal. Así lo
//! consumen igual el comando `watch`, que los escribe por pantalla, y el TUI,
//! que además refresca la lista en vivo.

use anyhow::{Context, Result};
use futures_util::StreamExt;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use tokio::sync::mpsc::Sender;
use zbus::message::Type as MessageType;
use zbus::names::BusName;
use zbus::zvariant::OwnedValue;
use zbus::{Connection, MatchRule, MessageStream, fdo};

use crate::attrib::{Cache, Identity, now};
use crate::store::value_to_json;

/// Lo que el monitor observa en el bus.
#[derive(Debug, Clone)]
pub enum Event {
    /// Una aplicación ha llamado a un portal sensible.
    Call {
        identity: Identity,
        interface: String,
        member: String,
    },
    /// El portal ha concedido un permiso persistente, ya atribuido.
    Grant {
        identity: Identity,
        token: String,
        table: &'static str,
    },
    /// El monitor no pudo arrancar o se cayó.
    Error(String),
}

/// Interfaces cuyo uso merece registrarse, con la tabla del permission store a
/// la que acaban escribiendo.
const WATCHED: &[(&str, &str)] = &[
    ("org.freedesktop.portal.ScreenCast", "screencast"),
    ("org.freedesktop.portal.Screenshot", "screenshot"),
    ("org.freedesktop.portal.RemoteDesktop", "remote-desktop"),
    ("org.freedesktop.portal.Camera", "camera"),
    ("org.freedesktop.portal.Location", "location"),
    ("org.freedesktop.portal.GlobalShortcuts", "global-shortcuts"),
    ("org.freedesktop.portal.InputCapture", "input-capture"),
    ("org.freedesktop.portal.Background", "background"),
    ("org.freedesktop.portal.Device", "devices"),
];

fn table_for(interface: &str) -> Option<&'static str> {
    WATCHED
        .iter()
        .find(|(name, _)| *name == interface)
        .map(|(_, table)| *table)
}

/// Traduce un nombre único de conexión (`:1.42`) al fragmento que el portal usa
/// en la ruta del Request (`1_42`).
fn sender_token(unique: &str) -> String {
    unique.trim_start_matches(':').replace('.', "_")
}

/// Extrae el fragmento del remitente de una ruta de Request.
fn sender_from_request_path(path: &str) -> Option<&str> {
    path.strip_prefix("/org/freedesktop/portal/desktop/request/")?
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
}

/// Escucha el bus y emite un evento por cada cosa relevante que ocurre.
///
/// Termina cuando el receptor se cierra o el bus corta la conexión.
pub async fn monitor(tx: Sender<Event>) -> Result<()> {
    // Hacen falta dos conexiones: una vez que se activa el modo monitor, esa
    // conexión ya no puede emitir llamadas, y resolver el PID del remitente es
    // precisamente una llamada.
    let monitor_conn = Connection::session()
        .await
        .context("could not open the monitoring connection")?;
    let query_conn = Connection::session()
        .await
        .context("could not open the query connection")?;

    let dbus = fdo::DBusProxy::new(&query_conn).await?;

    // El filtro va por ruta de objeto y no por destino: en una match rule el
    // campo `destination` solo admite nombres únicos de conexión (`:1.66`),
    // nunca uno bien conocido como org.freedesktop.portal.Desktop.
    let rules = [
        MatchRule::builder()
            .msg_type(MessageType::MethodCall)
            .path_namespace("/org/freedesktop/portal/desktop")?
            .build(),
        MatchRule::builder()
            .msg_type(MessageType::Signal)
            .interface("org.freedesktop.portal.Request")?
            .build(),
    ];

    fdo::MonitoringProxy::new(&monitor_conn)
        .await?
        .become_monitor(&rules, 0)
        .await
        .context("the bus refused to enable monitor mode")?;

    // Fragmento del remitente → identidad del proceso que hay detrás.
    let mut senders: HashMap<String, Identity> = HashMap::new();
    // Fragmento del remitente → última interfaz de portal que usó, para saber a
    // qué tabla atribuir el token cuando llegue la respuesta.
    let mut last_interface: HashMap<String, &'static str> = HashMap::new();

    let mut stream = MessageStream::from(monitor_conn);

    while let Some(message) = stream.next().await {
        let message = match message {
            Ok(message) => message,
            Err(_) => continue,
        };
        let header = message.header();

        match message.message_type() {
            MessageType::MethodCall => {
                let Some(interface) = header.interface().map(|i| i.to_string()) else {
                    continue;
                };
                let Some(table) = table_for(&interface) else {
                    continue;
                };
                let Some(sender) = header.sender() else {
                    continue;
                };
                let member = header.member().map(|m| m.to_string()).unwrap_or_default();

                let token = sender_token(sender.as_str());
                last_interface.insert(token.clone(), table);

                // Resolver el PID una sola vez por conexión: es una ida y vuelta
                // por el bus y una aplicación activa llama muchas veces.
                if !senders.contains_key(&token) {
                    let identity = match dbus
                        .get_connection_unix_process_id(BusName::Unique(sender.to_owned()))
                        .await
                    {
                        Ok(pid) => Identity::from_pid(pid),
                        // La conexión puede haber muerto ya; se registra igual
                        // para no reintentar en cada mensaje.
                        Err(_) => Identity::default(),
                    };
                    senders.insert(token.clone(), identity);
                }

                let event = Event::Call {
                    identity: senders[&token].clone(),
                    interface,
                    member,
                };
                if tx.send(event).await.is_err() {
                    break;
                }
            }

            MessageType::Signal => {
                if header.interface().map(|i| i.as_str()) != Some("org.freedesktop.portal.Request")
                    || header.member().map(|m| m.as_str()) != Some("Response")
                {
                    continue;
                }
                let Some(path) = header.path().map(|p| p.to_string()) else {
                    continue;
                };
                let Some(sender_frag) = sender_from_request_path(&path) else {
                    continue;
                };

                // El cuerpo es `(u response, a{sv} results)`. Un código distinto
                // de cero significa cancelado o fallido: no se concedió nada.
                let Ok((code, results)) = message
                    .body()
                    .deserialize::<(u32, HashMap<String, OwnedValue>)>()
                else {
                    continue;
                };
                if code != 0 {
                    continue;
                }

                let Some(token) = results
                    .get("restore_token")
                    .and_then(|v| value_to_json(v).as_str().map(str::to_owned))
                else {
                    continue;
                };

                // Sin la llamada previa no hay a quién atribuir el token: pasa
                // cuando el monitor arranca con un flujo ya empezado. Emitirlo
                // vacío solo ensuciaría el mapa, así que se descarta.
                let (Some(identity), Some(table)) = (
                    senders.get(sender_frag),
                    last_interface.get(sender_frag).copied(),
                ) else {
                    continue;
                };

                let event = Event::Grant {
                    identity: identity.clone(),
                    token,
                    table,
                };
                if tx.send(event).await.is_err() {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(())
}

/// Lanza el monitor en una tarea y reenvía los errores de arranque por el canal.
pub fn spawn(tx: Sender<Event>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = monitor(tx.clone()).await {
            let _ = tx.send(Event::Error(format!("{e:#}"))).await;
        }
    })
}

/// El comando `wayward watch`: imprime lo que ve y persiste las atribuciones.
pub async fn run(json: bool) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    spawn(tx);

    let mut cache = Cache::load()?;
    let mut dirty = false;

    if !json {
        println!(
            "{} listening to the portal. Ctrl-C to stop and save.\n",
            "wayward".bold()
        );
    }

    loop {
        let event = tokio::select! {
            event = rx.recv() => match event {
                Some(event) => event,
                None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        };

        match event {
            Event::Call {
                identity,
                interface,
                member,
            } => report_call(json, &identity, &interface, &member),

            Event::Grant {
                identity,
                token,
                table,
            } => {
                cache.observe(&token, identity.clone(), table, now());
                dirty = true;
                report_grant(json, &identity, &token, table);
            }

            Event::Error(message) => {
                anyhow::bail!(message);
            }
        }
    }

    if dirty {
        cache.save()?;
    }
    if !json {
        println!(
            "\n{} {} attributions saved to {}",
            "✓".green(),
            cache.tokens.len(),
            crate::attrib::cache_path().display()
        );
    }
    Ok(())
}

fn report_call(json: bool, identity: &Identity, interface: &str, member: &str) {
    let short = interface.rsplit('.').next().unwrap_or(interface);
    if json {
        let line = serde_json::json!({
            "event": "call",
            "time": now(),
            "app": identity.label(),
            "pid": identity.pid,
            "exe": identity.exe,
            "interface": short,
            "member": member,
        });
        println!("{line}");
    } else {
        println!(
            "  {}  {:<22} {}.{}",
            clock().dimmed(),
            identity.label().bold(),
            short.cyan(),
            member
        );
    }
}

fn report_grant(json: bool, identity: &Identity, token: &str, table: &str) {
    if json {
        let line = serde_json::json!({
            "event": "grant",
            "time": now(),
            "app": identity.label(),
            "pid": identity.pid,
            "exe": identity.exe,
            "table": table,
            "restore_token": token,
        });
        println!("{line}");
    } else {
        println!(
            "  {}  {} {} was granted persistent {} access → token {}",
            clock().dimmed(),
            "⚑".yellow(),
            identity.label().bold(),
            table.yellow(),
            token.dimmed()
        );
    }
}

fn clock() -> String {
    jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::system())
        .strftime("%H:%M:%S")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rutas reales capturadas de xdg-desktop-portal 1.22.1 durante el
    /// desarrollo: la conexión `:1.72` produce el fragmento `1_72`.
    #[test]
    fn el_fragmento_del_remitente_sale_del_nombre_unico() {
        assert_eq!(sender_token(":1.72"), "1_72");
        assert_eq!(sender_token(":1.1066"), "1_1066");
    }

    #[test]
    fn la_ruta_de_request_devuelve_el_fragmento() {
        assert_eq!(
            sender_from_request_path("/org/freedesktop/portal/desktop/request/1_72/wayward1"),
            Some("1_72")
        );
    }

    /// El viaje de ida y vuelta es lo que sostiene la correlación: el token que
    /// se guarda al ver la llamada tiene que ser el mismo que se extrae de la
    /// ruta cuando llega la respuesta.
    #[test]
    fn la_correlacion_cierra_el_circulo() {
        let unique = ":1.72";
        let path = format!(
            "/org/freedesktop/portal/desktop/request/{}/handle",
            sender_token(unique)
        );
        assert_eq!(sender_from_request_path(&path), Some("1_72"));
    }

    #[test]
    fn las_rutas_ajenas_no_correlacionan() {
        assert_eq!(
            sender_from_request_path("/org/freedesktop/portal/desktop"),
            None
        );
        assert_eq!(sender_from_request_path("/algo/completamente/otro"), None);
        // Una ruta de sesión no es una de request, aunque se le parezca.
        assert_eq!(
            sender_from_request_path("/org/freedesktop/portal/desktop/session/1_72/ses"),
            None
        );
    }

    #[test]
    fn solo_se_vigilan_las_interfaces_del_catalogo() {
        assert_eq!(
            table_for("org.freedesktop.portal.ScreenCast"),
            Some("screencast")
        );
        assert_eq!(table_for("org.freedesktop.portal.Settings"), None);
    }
}
