//! Atribución retroactiva a partir del journal.
//!
//! Un permiso concedido antes de que wayward existiera no tiene atribución
//! posible por el bus, porque nadie estaba escuchando. Pero la tabla guarda un
//! `timeIssued`, y las aplicaciones dejan rastro en journald al hacer lo que
//! acaban de pedir permiso para hacer. Cruzando ambas cosas se recupera lo que
//! el permission store no guardó.
//!
//! El método no depende de ninguna aplicación concreta: journald adjunta
//! `_COMM`, `_EXE` y `_PID` a cada línea, así que basta con mirar quién estaba
//! escribiendo en el instante de la concesión y puntuar a los candidatos.
//!
//! Esto produce **candidatos con un nivel de confianza**, nunca certezas. Una
//! coincidencia al segundo con una línea que menciona screencast es prueba
//! fuerte; un proceso que casualmente logueó algo en ese momento no lo es, y
//! presentarlos igual sería mentir en la dirección más peligrosa.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// Una aplicación que pudo pedir el permiso.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub label: String,
    pub exe: Option<String>,
    pub pid: Option<u32>,
    pub confidence: Confidence,
    /// Segundos entre la línea más significativa y el `timeIssued`.
    pub offset: i64,
    /// La línea del journal que sostiene la atribución.
    pub evidence: String,
    /// Cuántas líneas escribió el proceso en la ventana.
    pub lines: usize,
}

/// Lo averiguado sobre un permiso concreto.
#[derive(Debug, Clone, Serialize)]
pub struct Resolution {
    pub token: String,
    pub table: String,
    pub issued_at: Option<i64>,
    pub candidates: Vec<Candidate>,
}

impl Resolution {
    /// El candidato que se usaría para atribuir, si alguno llega al listón.
    pub fn best(&self, min: Confidence) -> Option<&Candidate> {
        self.candidates.first().filter(|c| c.confidence >= min)
    }
}

/// Procesos de infraestructura, que aparecen alrededor de casi cualquier evento
/// y nunca son quien pide el permiso.
///
/// Se comparan por prefijo a propósito: el kernel trunca `_COMM` a 15
/// caracteres, así que `xdg-desktop-portal` llega como `xdg-desktop-por`.
const INFRASTRUCTURE: &[&str] = &[
    "systemd",
    "dbus-daemon",
    "dbus-broker",
    "pipewire",
    "wireplumber",
    "polkitd",
    "gnome-keyring",
    "xdg-desktop-por",
    "xdg-document-po",
    "xdg-permission",
    "kernel",
    "audit",
    "rtkit-daemon",
    "wayward",
];

fn is_infrastructure(comm: &str) -> bool {
    INFRASTRUCTURE
        .iter()
        .any(|prefix| comm.starts_with(prefix))
}

/// Palabras que, dichas por el propio proceso, convierten una coincidencia
/// temporal en una prueba: significa que estaba haciendo justo aquello para lo
/// que pidió permiso.
fn keywords(table: &str) -> &'static [&'static str] {
    match table {
        "screencast" => &["screencast", "screen capture", "screen-cast", "screencopy", "pipewire"],
        "screenshot" => &["screenshot", "screen shot", "capture"],
        "camera" => &["camera", "webcam", "v4l"],
        "devices" => &["camera", "microphone", "device"],
        "location" => &["location", "geoclue", "gps"],
        "remote-desktop" => &["remote desktop", "remotedesktop", "input capture"],
        "background" => &["background", "autostart"],
        _ => &["portal"],
    }
}

/// Acumulador por proceso mientras se recorre la ventana.
#[derive(Default)]
struct Tally {
    exe: Option<String>,
    pid: Option<u32>,
    lines: usize,
    /// Menor distancia absoluta al `timeIssued`, con su línea.
    nearest: Option<(i64, String)>,
    /// Mejor coincidencia de palabra clave: prioridad, distancia y línea. La
    /// prioridad es el índice en la lista de palabras, que va de más específica
    /// a más genérica — «screencast» pesa más que «pipewire», porque la primera
    /// describe la acción y la segunda solo nombra la tecnología.
    keyword: Option<(usize, i64, String)>,
}

/// Busca candidatos alrededor del instante de concesión.
///
/// `window` son los segundos a cada lado. El valor por defecto de la CLI es
/// generoso porque entre que el usuario elige la fuente en el diálogo y el
/// portal archiva el permiso pueden pasar varios segundos.
pub fn resolve(table: &str, issued_at: i64, window: i64) -> Result<Vec<Candidate>> {
    let output = Command::new("journalctl")
        .args([
            "--user",
            "--no-pager",
            "-o",
            "json",
            "--since",
            &format!("@{}", issued_at - window),
            "--until",
            &format!("@{}", issued_at + window),
        ])
        .output()
        .context("no se pudo ejecutar journalctl; ¿está systemd-journald disponible?")?;

    if !output.status.success() {
        anyhow::bail!(
            "journalctl falló: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let keywords = keywords(table);
    let mut tallies: HashMap<String, Tally> = HashMap::new();

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        let comm = entry.get("_COMM").and_then(|v| v.as_str()).unwrap_or("");
        if comm.is_empty() || is_infrastructure(comm) {
            continue;
        }

        // journald da el instante en microsegundos y como cadena.
        let Some(stamp) = entry
            .get("__REALTIME_TIMESTAMP")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
        else {
            continue;
        };
        let offset = stamp / 1_000_000 - issued_at;

        let message = message_of(&entry);
        let tally = tallies.entry(comm.to_string()).or_default();
        tally.lines += 1;
        if tally.exe.is_none() {
            tally.exe = entry
                .get("_EXE")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
        }
        if tally.pid.is_none() {
            tally.pid = entry
                .get("_PID")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok());
        }

        if tally
            .nearest
            .as_ref()
            .is_none_or(|(best, _)| offset.abs() < best.abs())
        {
            tally.nearest = Some((offset, message.clone()));
        }

        let lowered = message.to_lowercase();
        if let Some(priority) = keywords.iter().position(|k| lowered.contains(k))
            && beats_keyword(tally.keyword.as_ref(), priority, offset)
        {
            tally.keyword = Some((priority, offset, message));
        }
    }

    let mut candidates: Vec<Candidate> = tallies
        .into_iter()
        .map(|(label, tally)| {
            // La palabra clave manda: si el proceso dijo que estaba capturando
            // pantalla en ese instante, es la prueba más fuerte disponible.
            let (offset, evidence, confidence) = match (&tally.keyword, &tally.nearest) {
                (Some((_, offset, line)), _) if offset.abs() <= 3 => {
                    (*offset, line.clone(), Confidence::High)
                }
                (Some((_, offset, line)), _) => (*offset, line.clone(), Confidence::Medium),
                (None, Some((offset, line))) if offset.abs() <= 3 => {
                    (*offset, line.clone(), Confidence::Medium)
                }
                (None, Some((offset, line))) => (*offset, line.clone(), Confidence::Low),
                (None, None) => (window, String::new(), Confidence::Low),
            };

            Candidate {
                label,
                exe: tally.exe,
                pid: tally.pid,
                confidence,
                offset,
                evidence,
                lines: tally.lines,
            }
        })
        .collect();

    // Mejor confianza primero; a igual confianza, lo más cercano en el tiempo.
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.offset.abs().cmp(&b.offset.abs()))
            .then_with(|| b.lines.cmp(&a.lines))
    });

    Ok(candidates)
}

/// ¿Sustituye la coincidencia nueva a la que ya teníamos?
///
/// Manda la especificidad de la palabra y solo se desempata por cercanía. Al
/// revés, un proceso que nombra «pipewire» en el mismo segundo desplazaría a la
/// línea que dice «setting up screencast» un segundo después, que es mucho mejor
/// prueba.
fn beats_keyword(current: Option<&(usize, i64, String)>, priority: usize, offset: i64) -> bool {
    match current {
        None => true,
        Some((best_priority, best_offset, _)) => {
            priority < *best_priority
                || (priority == *best_priority && offset.abs() < best_offset.abs())
        }
    }
}

/// `MESSAGE` normalmente es texto, pero journald lo entrega como lista de bytes
/// cuando no es UTF-8 válido.
fn message_of(entry: &serde_json::Value) -> String {
    match entry.get("MESSAGE") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(bytes)) => {
            let raw: Vec<u8> = bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|n| n as u8))
                .collect();
            String::from_utf8_lossy(&raw).into_owned()
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_infraestructura_se_descarta_por_prefijo() {
        // El kernel trunca _COMM a 15 caracteres: si se comparase por igualdad
        // el portal se colaría como candidato en todas las atribuciones.
        assert!(is_infrastructure("xdg-desktop-por"));
        assert!(is_infrastructure("systemd-logind"));
        assert!(is_infrastructure("pipewire-pulse"));
        assert!(is_infrastructure("wayward"));
        assert!(!is_infrastructure("obs"));
        assert!(!is_infrastructure("vesktop"));
    }

    #[test]
    fn cada_tabla_busca_sus_propias_palabras() {
        assert!(keywords("screencast").contains(&"screencast"));
        assert!(keywords("camera").contains(&"camera"));
        // Una tabla sin catalogar no se queda sin criterio.
        assert!(!keywords("inventada").is_empty());
    }

    /// Caso real que motivó la prioridad: OBS carga `linux-pipewire.so` y un
    /// instante después escribe «setting up screencast». Sin prioridad ganaba la
    /// primera por llegar antes, y la evidencia mostrada era mucho peor.
    #[test]
    fn la_palabra_mas_especifica_gana_a_la_mas_cercana() {
        let palabras = keywords("screencast");
        let screencast = palabras.iter().position(|w| *w == "screencast").unwrap();
        let pipewire = palabras.iter().position(|w| *w == "pipewire").unwrap();
        assert!(screencast < pipewire, "la lista debe ir de específica a genérica");

        let flojo = (pipewire, 0i64, "loading linux-pipewire.so".to_string());
        assert!(
            beats_keyword(Some(&flojo), screencast, 1),
            "«screencast» a 1s debe desplazar a «pipewire» a 0s"
        );
    }

    #[test]
    fn a_igual_palabra_gana_la_mas_cercana() {
        let lejos = (0usize, 5i64, "screencast".to_string());
        assert!(beats_keyword(Some(&lejos), 0, 1));
        assert!(!beats_keyword(Some(&lejos), 0, 9));
        assert!(beats_keyword(None, 3, 100), "sin nada previo, cualquiera vale");
    }

    #[test]
    fn el_mensaje_admite_texto_y_bytes() {
        let texto = serde_json::json!({ "MESSAGE": "setting up screencast" });
        assert_eq!(message_of(&texto), "setting up screencast");

        // journald entrega bytes cuando el mensaje no es UTF-8 válido.
        let bytes = serde_json::json!({ "MESSAGE": [104, 111, 108, 97] });
        assert_eq!(message_of(&bytes), "hola");

        assert_eq!(message_of(&serde_json::json!({})), "");
    }
}
