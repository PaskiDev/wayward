//! Interfaz de terminal.
//!
//! Lo que aporta sobre el CLI es tener el monitor del bus corriendo dentro:
//! mientras miras la lista de permisos, un token que estaba «sin atribuir»
//! pasa a tener nombre en el instante en que la aplicación vuelve a pedirlo.
//! Esa transición es justo lo que el sistema no te deja ver.

mod ui;

use anyhow::Result;
use std::collections::{HashSet, VecDeque};

use ratatui::crossterm::event::{
    Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use tokio::sync::mpsc;

use crate::attrib::{Cache, now};
use crate::history::{History, Revocation};
use crate::store::{Entry, PermissionStoreProxy};
use crate::watch;

/// Cuántas líneas de actividad se conservan antes de tirar las viejas.
const ACTIVITY_LIMIT: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Permisos,
    Actividad,
    Revocados,
}

/// Una línea del registro de actividad.
pub struct Activity {
    pub time: String,
    pub app: String,
    pub detail: String,
    /// Las concesiones se pintan distinto: son lo único que deja rastro.
    pub grant: bool,
}

/// Revocación pendiente de confirmar.
pub struct Confirm {
    pub token: String,
    pub table: String,
}

pub struct App {
    pub entries: Vec<Entry>,
    pub cache: Cache,
    /// Lo revocado, que ya no existe en el permission store y solo vive aquí.
    pub history: History,
    pub selected: usize,
    pub tab: Tab,
    pub activity: VecDeque<Activity>,
    pub confirm: Option<Confirm>,
    pub status: Option<String>,
    pub monitor_error: Option<String>,
    /// Cierto solo cuando el bus ha confirmado el modo monitor. Hasta entonces
    /// la cabecera no puede anunciar que se está vigilando.
    pub monitoring: bool,
    /// Tokens atribuidos durante esta sesión, para resaltar el hallazgo.
    pub fresh: HashSet<String>,
    pub quit: bool,
}

impl App {
    fn new(entries: Vec<Entry>, cache: Cache, history: History) -> Self {
        Self {
            entries,
            cache,
            history,
            selected: 0,
            tab: Tab::Permisos,
            activity: VecDeque::new(),
            confirm: None,
            status: None,
            monitor_error: None,
            monitoring: false,
            fresh: HashSet::new(),
            quit: false,
        }
    }

    pub fn current(&self) -> Option<&Entry> {
        self.entries.get(self.selected)
    }

    fn move_by(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        let last = self.entries.len() - 1;
        self.selected = match delta {
            d if d < 0 => self.selected.saturating_sub(d.unsigned_abs()),
            d => (self.selected + d as usize).min(last),
        };
    }

    fn push_activity(&mut self, activity: Activity) {
        if self.activity.len() >= ACTIVITY_LIMIT {
            self.activity.pop_front();
        }
        self.activity.push_back(activity);
    }

    /// Aplica un evento del monitor. Devuelve `true` si conviene releer el
    /// permission store, porque acaba de aparecer un permiso nuevo.
    fn on_monitor(&mut self, event: watch::Event) -> bool {
        match event {
            watch::Event::Ready => {
                self.monitoring = true;
                false
            }

            watch::Event::Call {
                identity,
                interface,
                member,
            } => {
                let short = interface.rsplit('.').next().unwrap_or(&interface).to_string();
                self.push_activity(Activity {
                    time: clock(),
                    app: identity.label(),
                    detail: format!("{short}.{member}"),
                    grant: false,
                });
                false
            }
            watch::Event::Grant {
                identity,
                token,
                table,
            } => {
                // Solo estado en memoria: persistir es efecto de borde y lo hace
                // el bucle de eventos. Si no, los tests que ejercitan esta
                // transición escribirían en el estado real del usuario.
                self.cache.observe(&token, identity.clone(), table, now());
                self.fresh.insert(token.clone());
                self.push_activity(Activity {
                    time: clock(),
                    app: identity.label(),
                    detail: format!("was granted persistent {table} access"),
                    grant: true,
                });
                true
            }
            watch::Event::Error(message) => {
                self.monitor_error = Some(message);
                false
            }
        }
    }
}

pub async fn run() -> Result<()> {
    let proxy = crate::connect().await?;
    let entries = crate::collect(&proxy, None).await?;
    let mut app = App::new(entries, Cache::load()?, History::load()?);

    let (monitor_tx, mut monitor_rx) = mpsc::channel(256);
    watch::spawn(monitor_tx);
    let mut keys = spawn_input();

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app, &proxy, &mut keys, &mut monitor_rx).await;
    ratatui::restore();
    result
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    proxy: &PermissionStoreProxy<'_>,
    keys: &mut mpsc::Receiver<TermEvent>,
    monitor: &mut mpsc::Receiver<watch::Event>,
) -> Result<()> {
    while !app.quit {
        terminal.draw(|frame| ui::draw(frame, app))?;

        tokio::select! {
            Some(event) = keys.recv() => {
                if let TermEvent::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    handle_key(app, key, proxy).await?;
                }
            }
            Some(event) = monitor.recv() => {
                if app.on_monitor(event) {
                    if let Err(e) = app.cache.save() {
                        app.status = Some(format!("could not save the attribution: {e}"));
                    }
                    reload(app, proxy).await;
                }
            }
            else => break,
        }
    }
    Ok(())
}

async fn handle_key(
    app: &mut App,
    key: KeyEvent,
    proxy: &PermissionStoreProxy<'_>,
) -> Result<()> {
    // En modo raw la terminal no genera SIGINT: Ctrl-C llega como una tecla más
    // y hay que atenderla a mano o no habría forma de salir con ella.
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.quit = true;
        return Ok(());
    }

    // Con el diálogo abierto solo se responde a él.
    if let Some(confirm) = &app.confirm {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let (token, table) = (confirm.token.clone(), confirm.table.clone());
                app.confirm = None;

                // Se fotografía antes de borrar: después el permiso no existe
                // en ninguna parte y la atribución sería irrecuperable.
                let snapshot = app
                    .entries
                    .iter()
                    .find(|e| e.id == token && e.table == table)
                    .map(|entry| Revocation::of(entry, &app.cache, now()));

                match proxy.delete(&table, &token).await {
                    Ok(()) => {
                        let mut logged = Ok(());
                        if let Some(revocation) = snapshot {
                            app.history.record(revocation);
                            logged = app.history.save();
                        }
                        app.status = Some(match logged {
                            Ok(()) => format!("revoked {token}"),
                            Err(e) => format!("revoked {token}, but the log failed: {e}"),
                        });
                        reload(app, proxy).await;
                    }
                    Err(e) => app.status = Some(format!("could not revoke: {e}")),
                }
            }
            _ => {
                app.confirm = None;
                app.status = Some("revocation cancelled".to_string());
            }
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
        KeyCode::Char('j') | KeyCode::Down => app.move_by(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_by(-1),
        KeyCode::Home => app.selected = 0,
        KeyCode::End => app.selected = app.entries.len().saturating_sub(1),
        KeyCode::Tab => {
            app.tab = match app.tab {
                Tab::Permisos => Tab::Actividad,
                Tab::Actividad => Tab::Revocados,
                Tab::Revocados => Tab::Permisos,
            }
        }
        KeyCode::Char('1') => app.tab = Tab::Permisos,
        KeyCode::Char('2') => app.tab = Tab::Actividad,
        KeyCode::Char('3') => app.tab = Tab::Revocados,
        KeyCode::Char('R') => {
            reload(app, proxy).await;
            app.status = Some("list reloaded".to_string());
        }
        KeyCode::Char('r') => {
            if let Some(entry) = app.current() {
                app.confirm = Some(Confirm {
                    token: entry.id.clone(),
                    table: entry.table.clone(),
                });
            }
        }
        _ => {}
    }
    Ok(())
}

async fn reload(app: &mut App, proxy: &PermissionStoreProxy<'_>) {
    match crate::collect(proxy, None).await {
        Ok(entries) => {
            app.entries = entries;
            app.selected = app.selected.min(app.entries.len().saturating_sub(1));
        }
        Err(e) => app.status = Some(format!("could not re-read the store: {e}")),
    }
}

/// Lee el teclado en un hilo propio: `read()` bloquea, y bloquear el runtime
/// pararía también al monitor del bus.
fn spawn_input() -> mpsc::Receiver<TermEvent> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::spawn(move || {
        while let Ok(event) = ratatui::crossterm::event::read() {
            if tx.blocking_send(event).is_err() {
                break;
            }
        }
    });
    rx
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
    use crate::attrib::Identity;
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};
    use std::collections::HashMap;

    fn entry(id: &str) -> Entry {
        // El app ID vacío es el caso que motiva la herramienta: así es como
        // queda un permiso pedido por una aplicación nativa.
        let permissions = HashMap::from([(String::new(), vec!["yes".to_string()])]);
        Entry {
            table: "screencast".to_string(),
            id: id.to_string(),
            permissions,
            data: serde_json::json!([]),
            details: vec![("salida".to_string(), "DP-1".to_string())],
            issued_at: Some(1_786_207_593),
        }
    }

    fn render(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| ui::draw(frame, app)).unwrap();
        flatten(terminal.backend().buffer())
    }

    fn flatten(buffer: &Buffer) -> String {
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn un_permiso_sin_atribuir_se_ve_como_tal() {
        let app = App::new(vec![entry("4fuEEh6prRn88cBf79d3jw")], Cache::default(), History::default());
        let screen = render(&app);
        assert!(screen.contains("ScreenCast"), "falta la tabla:\n{screen}");
        assert!(screen.contains("unattributed"), "falta el aviso:\n{screen}");
    }

    /// La cabecera no puede decir que se está vigilando hasta que el bus lo
    /// confirme: anunciarlo antes de tiempo es la única mentira que una
    /// herramienta de vigilancia no se puede permitir.
    #[test]
    fn no_se_anuncia_la_vigilancia_antes_de_confirmarla() {
        let mut app = App::new(vec![entry("tok")], Cache::default(), History::default());
        let antes = render(&app);
        assert!(antes.contains("connecting"), "debería estar conectando:\n{antes}");
        assert!(!antes.contains("listening"), "no puede afirmarlo aún:\n{antes}");

        app.on_monitor(watch::Event::Ready);
        let despues = render(&app);
        assert!(despues.contains("listening"), "ya confirmado:\n{despues}");
    }

    #[test]
    fn la_atribucion_sustituye_al_aviso() {
        let mut cache = Cache::default();
        cache.observe(
            "4fuEEh6prRn88cBf79d3jw",
            Identity {
                pid: Some(1234),
                exe: Some("/usr/bin/obs".to_string()),
                cmdline: Some("obs".to_string()),
                comm: Some("obs".to_string()),
            },
            "screencast",
            0,
        );

        let app = App::new(vec![entry("4fuEEh6prRn88cBf79d3jw")], cache, History::default());
        let screen = render(&app);
        assert!(screen.contains("obs"), "falta el nombre atribuido:\n{screen}");
        assert!(!screen.contains("unattributed"), "no debería avisar ya:\n{screen}");
    }

    #[test]
    fn el_monitor_caido_se_anuncia() {
        let mut app = App::new(vec![entry("tok")], Cache::default(), History::default());
        app.monitor_error = Some("el bus rechazó activar el modo monitor".to_string());
        let screen = render(&app);
        assert!(screen.contains("monitor down"), "falta el aviso:\n{screen}");
    }

    #[test]
    fn la_vista_de_actividad_se_pinta_sin_datos() {
        let mut app = App::new(Vec::new(), Cache::default(), History::default());
        app.tab = Tab::Actividad;
        let screen = render(&app);
        assert!(screen.contains("Listening"), "falta la pista:\n{screen}");
    }

    #[test]
    fn una_concesion_marca_el_token_como_reciente() {
        let mut app = App::new(vec![entry("tok")], Cache::default(), History::default());
        let reload = app.on_monitor(watch::Event::Grant {
            identity: Identity::default(),
            token: "tok".to_string(),
            table: "screencast",
        });
        assert!(reload, "una concesión debe forzar la relectura del store");
        assert!(app.fresh.contains("tok"));
        assert_eq!(app.activity.len(), 1);
    }

    /// «3 revoked» se leía como «tres revocados» cuando el 3 era la tecla. La
    /// tecla va entre corchetes y la cantidad entre paréntesis, que es lo único
    /// que hace la cabecera legible de un vistazo.
    #[test]
    fn la_cabecera_separa_la_tecla_de_la_cantidad() {
        let vacia = App::new(Vec::new(), Cache::default(), History::default());
        let screen = render(&vacia);
        assert!(screen.contains("[3] revoked (0)"), "cabecera ambigua:\n{screen}");
        assert!(screen.contains("[1] permissions (0)"), "cabecera ambigua:\n{screen}");

        let mut history = History::default();
        history.record(Revocation::of(&entry("tok"), &Cache::default(), 1));
        history.record(Revocation::of(&entry("otro"), &Cache::default(), 2));
        let con_datos = App::new(vec![entry("a")], Cache::default(), history);
        let screen = render(&con_datos);
        assert!(screen.contains("[3] revoked (2)"), "falta la cuenta:\n{screen}");
        assert!(screen.contains("[1] permissions (1)"), "falta la cuenta:\n{screen}");
    }

    #[test]
    fn la_pestana_de_revocados_explica_para_que_sirve() {
        let mut app = App::new(Vec::new(), Cache::default(), History::default());
        app.tab = Tab::Revocados;
        let screen = render(&app);
        assert!(screen.contains("Nothing revoked yet"), "falta la pista:\n{screen}");
    }

    /// La razón de ser de la pestaña: el permiso ya no está en el store y la
    /// caché de atribuciones tampoco lo tiene, y aun así hay que poder decir a
    /// quién pertenecía. Por eso la app se construye aquí vacía salvo el
    /// histórico.
    #[test]
    fn lo_revocado_sobrevive_al_permiso_y_a_la_cache() {
        let mut cache = Cache::default();
        cache.observe(
            "4fuEEh6prRn88cBf79d3jw",
            Identity {
                pid: Some(1),
                exe: Some("/usr/bin/obs".to_string()),
                cmdline: None,
                comm: Some("obs".to_string()),
            },
            "screencast",
            0,
        );
        let mut history = History::default();
        history.record(Revocation::of(
            &entry("4fuEEh6prRn88cBf79d3jw"),
            &cache,
            1_786_300_000,
        ));

        let mut app = App::new(Vec::new(), Cache::default(), history);
        app.tab = Tab::Revocados;
        let screen = render(&app);

        assert!(screen.contains("obs"), "falta el dueño:\n{screen}");
        assert!(screen.contains("screencast"), "falta la tabla:\n{screen}");
        assert!(screen.contains("/usr/bin/obs"), "falta el ejecutable:\n{screen}");
    }

    #[test]
    fn el_cursor_no_se_sale_de_la_lista() {
        let mut app = App::new(vec![entry("a"), entry("b")], Cache::default(), History::default());
        app.move_by(-1);
        assert_eq!(app.selected, 0, "no debe pasar del principio");
        app.move_by(50);
        assert_eq!(app.selected, 1, "no debe pasar del final");
    }

    #[test]
    fn el_registro_de_actividad_no_crece_sin_limite() {
        let mut app = App::new(Vec::new(), Cache::default(), History::default());
        for i in 0..ACTIVITY_LIMIT + 25 {
            app.push_activity(Activity {
                time: "00:00:00".to_string(),
                app: format!("app{i}"),
                detail: "ScreenCast.Start".to_string(),
                grant: false,
            });
        }
        assert_eq!(app.activity.len(), ACTIVITY_LIMIT);
        // Se tiran las viejas, no las nuevas.
        assert_eq!(app.activity.back().unwrap().app, format!("app{}", ACTIVITY_LIMIT + 24));
    }
}
