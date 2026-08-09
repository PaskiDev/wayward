//! Catálogo de tablas del permission store y su sensibilidad.
//!
//! El permission store de `xdg-desktop-portal` guarda una tabla por tipo de
//! permiso, cada una en un fichero GVDB bajo `$XDG_DATA_HOME/flatpak/db`. Los
//! nombres no están documentados en un sitio único: salen de las distintas
//! implementaciones de portal, así que el catálogo se mantiene a mano y
//! cualquier tabla desconocida se trata como sospechosa en vez de ignorarla.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Info,
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::High => "HIGH",
            Risk::Medium => "MEDIUM",
            Risk::Low => "LOW",
            Risk::Info => "INFO",
        }
    }
}

/// Descripción de una tabla del permission store.
pub struct TableInfo {
    /// Nombre bonito para mostrar.
    pub display: &'static str,
    pub risk: Risk,
    /// Qué concede el permiso, en una línea.
    pub grants: &'static str,
}

/// Tablas conocidas. El orden de esta lista no importa; el informe ordena por
/// riesgo descendente.
const CATALOG: &[(&str, TableInfo)] = &[
    (
        "screencast",
        TableInfo {
            display: "ScreenCast",
            risk: Risk::High,
            grants: "continuous screen capture, resumable without asking again",
        },
    ),
    (
        "screenshot",
        TableInfo {
            display: "Screenshot",
            risk: Risk::High,
            grants: "one-off screenshots, potentially with no visible prompt",
        },
    ),
    (
        "camera",
        TableInfo {
            display: "Camera",
            risk: Risk::High,
            grants: "access to the camera",
        },
    ),
    (
        "devices",
        TableInfo {
            display: "Devices",
            risk: Risk::High,
            grants: "access to input devices, camera and microphone",
        },
    ),
    (
        "location",
        TableInfo {
            display: "Location",
            risk: Risk::High,
            grants: "the machine's geographic location",
        },
    ),
    (
        "remote-desktop",
        TableInfo {
            display: "RemoteDesktop",
            risk: Risk::High,
            grants: "remote control of keyboard and pointer",
        },
    ),
    (
        "background",
        TableInfo {
            display: "Background",
            risk: Risk::Medium,
            grants: "running in the background and starting at login",
        },
    ),
    (
        "notifications",
        TableInfo {
            display: "Notifications",
            risk: Risk::Low,
            grants: "sending desktop notifications",
        },
    ),
    (
        "wallpaper",
        TableInfo {
            display: "Wallpaper",
            risk: Risk::Low,
            grants: "changing the desktop wallpaper",
        },
    ),
    (
        "inhibit",
        TableInfo {
            display: "Inhibit",
            risk: Risk::Low,
            grants: "blocking the screensaver and suspend",
        },
    ),
    (
        "desktop-used-apps",
        TableInfo {
            display: "Used apps",
            risk: Risk::Info,
            grants: "history of which application opens each file type",
        },
    ),
    (
        "gnome",
        TableInfo {
            display: "GNOME",
            risk: Risk::Info,
            grants: "internal settings of the GNOME backend",
        },
    ),
];

/// Devuelve la ficha de una tabla. Las desconocidas se marcan como riesgo medio
/// a propósito: una tabla que no está en el catálogo es una que nadie ha
/// revisado, no una que sea inofensiva.
pub fn lookup(table: &str) -> TableInfo {
    for (name, info) in CATALOG {
        if *name == table {
            return TableInfo {
                display: info.display,
                risk: info.risk,
                grants: info.grants,
            };
        }
    }
    TableInfo {
        display: "unknown",
        risk: Risk::Medium,
        grants: "table missing from wayward's catalogue; review it by hand",
    }
}
