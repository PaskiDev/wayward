//! Pintado de la interfaz de terminal.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

use super::{App, Confirm, Tab};
use crate::render::format_issued;
use crate::risk::{self, Risk};
use crate::store::Decision;

pub fn draw(frame: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, header, app);
    match app.tab {
        Tab::Permisos => draw_permisos(frame, body, app),
        Tab::Actividad => draw_actividad(frame, body, app),
        Tab::Revocados => draw_revocados(frame, body, app),
    }
    draw_footer(frame, footer, app);

    if let Some(confirm) = &app.confirm {
        draw_confirm(frame, confirm);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let [left, right] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(20)]).areas(area);

    let tab_style = |tab: Tab| {
        if app.tab == tab {
            Style::new().fg(Color::Black).bg(Color::Cyan).bold()
        } else {
            Style::new().dim()
        }
    };

    // Los corchetes marcan la tecla y los paréntesis la cantidad. Sin esa
    // distinción «3 revoked» se lee como «tres revocados», que es justo lo que
    // el número no significa.
    let title = Line::from(vec![
        Span::styled(" wayward ", Style::new().bold()),
        Span::styled(
            format!(" [1] permissions ({}) ", app.entries.len()),
            tab_style(Tab::Permisos),
        ),
        Span::raw(" "),
        Span::styled(" [2] activity ", tab_style(Tab::Actividad)),
        Span::raw(" "),
        Span::styled(
            format!(" [3] revoked ({}) ", app.history.revocations.len()),
            tab_style(Tab::Revocados),
        ),
    ]);
    frame.render_widget(Paragraph::new(title), left);

    // El estado del monitor importa: si no arrancó, la atribución en vivo no
    // va a ocurrir y conviene que se vea sin tener que buscarlo.
    let status = match (&app.monitor_error, app.monitoring) {
        (Some(_), _) => Span::styled("monitor down ", Style::new().fg(Color::Red).bold()),
        (None, true) => Span::styled("● listening ", Style::new().fg(Color::Green)),
        // Todavía no ha confirmado el bus: no se anuncia lo que no consta.
        (None, false) => Span::styled("connecting… ", Style::new().dim()),
    };
    frame.render_widget(Paragraph::new(Line::from(status)).right_aligned(), right);
}

fn draw_permisos(frame: &mut Frame, area: Rect, app: &App) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).areas(area);

    if app.entries.is_empty() {
        let empty = Paragraph::new("\n  No desktop-portal permission is granted.")
            .block(bordered(" permissions "))
            .dim();
        frame.render_widget(empty, list_area);
    } else {
        let items: Vec<ListItem> = app.entries.iter().map(|entry| item_for(app, entry)).collect();
        let list = List::new(items)
            .block(bordered(" permissions "))
            .highlight_style(Style::new().bold().bg(Color::DarkGray))
            .highlight_symbol("▌");
        let mut state = ListState::default().with_selected(Some(app.selected));
        frame.render_stateful_widget(list, list_area, &mut state);
    }

    frame.render_widget(
        Paragraph::new(detail_lines(app))
            .block(bordered(" details "))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn item_for<'a>(app: &'a App, entry: &'a crate::store::Entry) -> ListItem<'a> {
    let info = risk::lookup(&entry.table);
    let attributed = app.cache.get(&entry.id);

    let decision = entry.decision();
    let who = match decision {
        // Un rechazo archivado protege en vez de exponer: ni alarma ni
        // atribución pendiente.
        Decision::Denied => Span::styled("denied", Style::new().fg(Color::Green).dim()),
        Decision::Unknown => Span::styled("non-standard value", Style::new().dim()),
        Decision::Granted => match attributed {
            Some(record) => Span::styled(record.identity.label(), Style::new().fg(Color::Green)),
            None if entry.unattributed() => {
                Span::styled("unattributed", Style::new().fg(Color::Yellow))
            }
            None => Span::styled(entry.apps().join(", "), Style::new().fg(Color::Green)),
        },
    };

    // El punto de riesgo solo se enciende sobre lo que está concedido.
    let dot = match decision {
        Decision::Granted => Style::new().fg(risk_color(info.risk)),
        _ => Style::new().dim(),
    };

    // Marca lo atribuido durante esta sesión: es el momento en que la
    // herramienta enseña algo que el sistema no guardaba.
    let fresh = if app.fresh.contains(&entry.id) {
        Span::styled("✦ ", Style::new().fg(Color::Cyan).bold())
    } else {
        Span::raw("  ")
    };

    ListItem::new(Line::from(vec![
        Span::styled("● ", dot),
        Span::styled(format!("{:<11}", info.display), Style::new().bold()),
        Span::styled(
            format!("{:<14} ", truncate(&entry.id, 13)),
            Style::new().dim(),
        ),
        fresh,
        who,
    ]))
}

fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let Some(entry) = app.current() else {
        return vec![Line::from("")];
    };
    let info = risk::lookup(&entry.table);
    let mut lines = vec![
        Line::from(Span::styled(entry.id.clone(), Style::new().bold())),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("{} ", info.display), Style::new().bold()),
            Span::styled(
                format!("{} risk", info.risk.label()),
                Style::new().fg(risk_color(info.risk)).bold(),
            ),
        ]),
        Line::from(Span::styled(info.grants.to_string(), Style::new().dim())),
        Line::from(""),
    ];

    if let Some(issued) = entry.issued_at {
        lines.push(field("granted", &format_issued(issued)));
    }
    for (label, value) in &entry.details {
        lines.push(field(label, value));
    }

    lines.push(Line::from(""));

    if entry.decision() == Decision::Denied {
        lines.push(Line::from(Span::styled(
            "Denied",
            Style::new().fg(Color::Green).bold(),
        )));
        lines.push(Line::from(Span::styled(
            "The permission store files rejections too. This one exposes nothing: \
             while it stays here the request is denied without asking again. \
             Revoking it makes the prompt come back."
                .to_string(),
            Style::new().dim(),
        )));
        return lines;
    }

    match app.cache.get(&entry.id) {
        Some(record) => {
            lines.push(Line::from(Span::styled("Attributed to", Style::new().bold())));
            lines.push(Line::from(Span::styled(
                record.identity.label(),
                Style::new().fg(Color::Green).bold(),
            )));
            if let Some(exe) = &record.identity.exe {
                lines.push(Line::from(Span::styled(exe.clone(), Style::new().dim())));
            }
            if let Some(cmdline) = &record.identity.cmdline {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(cmdline.clone(), Style::new().dim())));
            }
        }
        None if entry.unattributed() => {
            lines.push(Line::from(Span::styled(
                "Unattributed",
                Style::new().fg(Color::Yellow).bold(),
            )));
            lines.push(Line::from(Span::styled(
                "The portal derives the application identifier from the sandbox. \
                 Outside Flatpak or Snap nothing records who asked for the \
                 permission: only this token, which lets it resume access without \
                 ever asking again."
                    .to_string(),
                Style::new().dim(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Leave wayward open and use the application again: the moment it \
                 asks for the permission it will show up here with a name."
                    .to_string(),
                Style::new().dim(),
            )));
        }
        None => {
            lines.push(Line::from(Span::styled("Applications", Style::new().bold())));
            lines.push(Line::from(entry.apps().join(", ")));
        }
    }

    lines
}

fn draw_actividad(frame: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" portal activity ");

    if let Some(error) = &app.monitor_error {
        let text = vec![
            Line::from(Span::styled(
                "The bus monitor failed to start",
                Style::new().fg(Color::Red).bold(),
            )),
            Line::from(""),
            Line::from(error.clone()),
        ];
        frame.render_widget(
            Paragraph::new(text).block(block).wrap(Wrap { trim: false }),
            area,
        );
        return;
    }

    if app.activity.is_empty() {
        let hint = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Listening. Nothing has happened yet.",
                Style::new().dim(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Share your screen in any application and it will show up here,",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  along with the name of the process that asked for it.",
                Style::new().dim(),
            )),
        ];
        frame.render_widget(Paragraph::new(hint).block(block), area);
        return;
    }

    // Solo caben `height - 2` líneas por los bordes; se enseñan las últimas,
    // que es el comportamiento que se espera de un registro en vivo.
    let visible = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = app
        .activity
        .iter()
        .skip(app.activity.len().saturating_sub(visible))
        .map(|activity| {
            let (marker, style) = if activity.grant {
                ("⚑ ", Style::new().fg(Color::Yellow).bold())
            } else {
                ("  ", Style::new())
            };
            Line::from(vec![
                Span::styled(format!("{} ", activity.time), Style::new().dim()),
                Span::styled(marker, style),
                Span::styled(
                    format!("{:<20}", truncate(&activity.app, 19)),
                    Style::new().bold(),
                ),
                Span::styled(activity.detail.clone(), style),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Lo revocado. Es la única vista que enseña algo que ya no existe: en cuanto
/// se borra del permission store, este registro es la única constancia.
fn draw_revocados(frame: &mut Frame, area: Rect, app: &App) {
    let block = bordered(" revoked ");
    let revocations = app.history.newest_first();

    if revocations.is_empty() {
        let hint = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Nothing revoked yet.",
                Style::new().dim(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Revoking a permission deletes it from the store for good — neither",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  the portal nor the system remembers it existed. Whatever you revoke",
                Style::new().dim(),
            )),
            Line::from(Span::styled(
                "  from here is kept in this list, with whoever it belonged to.",
                Style::new().dim(),
            )),
        ];
        frame.render_widget(Paragraph::new(hint).block(block), area);
        return;
    }

    let mut lines = Vec::new();
    for revocation in revocations {
        let who = match &revocation.app {
            Some(app) => Span::styled(app.clone(), Style::new().fg(Color::Green).bold()),
            None => Span::styled("unattributed", Style::new().fg(Color::Yellow)),
        };
        lines.push(Line::from(vec![
            Span::styled(short_stamp(revocation.revoked_at), Style::new().dim()),
            Span::raw("  "),
            who,
            Span::raw("  "),
            Span::styled(revocation.table.clone(), Style::new().dim()),
        ]));
        lines.push(Line::from(vec![
            Span::raw("               "),
            Span::styled(revocation.token.clone(), Style::new().dim()),
        ]));
        if let Some(exe) = &revocation.exe {
            lines.push(Line::from(vec![
                Span::raw("               "),
                Span::styled(exe.clone(), Style::new().dim()),
            ]));
        }
        // Los detalles decodificados se guardan porque tras el borrado no hay
        // de dónde volver a sacarlos.
        if !revocation.details.is_empty() {
            let summary = revocation
                .details
                .iter()
                .map(|(label, value)| format!("{label} {value}"))
                .collect::<Vec<_>>()
                .join(" · ");
            lines.push(Line::from(vec![
                Span::raw("               "),
                Span::styled(truncate(&summary, 60), Style::new().dim()),
            ]));
        }
        lines.push(Line::from(""));
    }

    let visible = area.height.saturating_sub(2) as usize;
    let shown: Vec<Line> = lines.into_iter().take(visible).collect();
    frame.render_widget(Paragraph::new(shown).block(block), area);
}

/// Fecha corta para el listado: día, mes y hora bastan para situarlo.
fn short_stamp(ts: i64) -> String {
    jiff::Timestamp::from_second(ts)
        .map(|t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%d %b %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| ts.to_string())
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let line = match &app.status {
        Some(status) => Line::from(Span::styled(
            format!(" {status}"),
            Style::new().fg(Color::Cyan),
        )),
        None => Line::from(Span::styled(
            " j/k move · r revoke · R reload · tab switch view · q quit",
            Style::new().dim(),
        )),
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_confirm(frame: &mut Frame, confirm: &Confirm) {
    let area = centered(frame.area(), 60, 9);
    frame.render_widget(Clear, area);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  Revoke the {} permission", confirm.table),
            Style::new().bold(),
        )),
        Line::from(Span::styled(
            format!("  {}", confirm.token),
            Style::new().dim(),
        )),
        Line::from(""),
        Line::from("  The application will ask for it again next time it"),
        Line::from("  needs it."),
        Line::from(""),
        Line::from(Span::styled(
            "  y confirm · any other key cancels",
            Style::new().fg(Color::Yellow),
        )),
    ];

    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(Color::Yellow))
                .title(" confirm "),
        ),
        area,
    );
}

fn bordered(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().dim())
        .title(title)
}

fn field(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<11} "), Style::new().dim()),
        Span::raw(value.to_string()),
    ])
}

fn risk_color(risk: Risk) -> Color {
    match risk {
        Risk::High => Color::Red,
        Risk::Medium => Color::Yellow,
        Risk::Low => Color::Blue,
        Risk::Info => Color::DarkGray,
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [_, middle, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height),
        Constraint::Fill(1),
    ])
    .areas(area);
    let [_, center, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(width),
        Constraint::Fill(1),
    ])
    .areas(middle);
    center
}
