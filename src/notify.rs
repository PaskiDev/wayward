//! Avisos de escritorio cuando algo se lleva un permiso permanente.
//!
//! Es lo que separa a un auditor de un vigilante: de nada sirve descubrir tres
//! semanas después que algo obtuvo acceso perpetuo a tu pantalla. El aviso llega
//! por `org.freedesktop.Notifications`, el mismo bus que ya usa el resto de la
//! herramienta, así que no hace falta ninguna dependencia más.

use anyhow::Result;
use std::collections::HashMap;
use zbus::zvariant::Value;

use crate::attrib::Identity;
use crate::risk::{self, Risk};

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
pub trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

/// Avisa de una concesión recién observada.
///
/// Los fallos no se propagan hacia arriba: que no haya servidor de
/// notificaciones no puede tumbar al monitor, que es lo que de verdad importa.
pub async fn grant(connection: &zbus::Connection, identity: &Identity, table: &str, token: &str) {
    if let Err(e) = try_grant(connection, identity, table, token).await {
        eprintln!("could not send the notification: {e}");
    }
}

async fn try_grant(
    connection: &zbus::Connection,
    identity: &Identity,
    table: &str,
    token: &str,
) -> Result<()> {
    let info = risk::lookup(table);
    let proxy = NotificationsProxy::new(connection).await?;

    let summary = format!("{} gained persistent access", identity.label());
    let body = format!(
        "{}\n<i>{}</i>\n\nToken {}\nRevoke with: wayward revoke {}",
        info.grants,
        identity.exe.as_deref().unwrap_or("unknown executable"),
        token,
        token,
    );

    let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
    // Un permiso permanente de captura de pantalla merece quedarse en la
    // pantalla hasta que lo mires; el resto puede caducar solo.
    let urgency: u8 = if info.risk == Risk::High { 2 } else { 1 };
    hints.insert("urgency", Value::U8(urgency));
    hints.insert("category", Value::from("device"));

    // -1 deja el tiempo al servidor; 0 lo deja fijo hasta que se cierre. Las
    // críticas se quedan, las demás se van solas.
    let timeout = if urgency == 2 { 0 } else { -1 };

    proxy
        .notify(
            "wayward",
            0,
            "camera-web",
            &summary,
            &body,
            &[],
            hints,
            timeout,
        )
        .await?;
    Ok(())
}
