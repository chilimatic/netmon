//! Rendering with ratatui.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::Marker,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Clear, Dataset, GraphType, Paragraph, Row, Sparkline, Table, TableState, Tabs,
        canvas::{Canvas, Line as CanvasLine, Points},
    },
};

use netmon_common::{ACTION_DENY, DIR_IN};

use crate::{
    ask::{ASK_TIMEOUT, Prompt},
    rules::{Action, Dir, Rules, proto_name},
    app::{App, ConnRow, RowId, Sort, Tab, human},
    capture::Capture,
    decode::hexdump,
    collector::{Collector, HISTORY, addr},
    graph::{self, Kind, Verdict},
    ifaces::Names,
};

fn rate(v: f64) -> String {
    format!("{}/s", human(v))
}

/// Rows the traffic graph takes. Hidden when the terminal is too short.
const GRAPH_HEIGHT: u16 = 10;

pub fn draw(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, cap: Option<&Capture>, rules: &Rules) {
    // The Graph tab needs the height more than the traffic chart.
    let chart = app.show_graph && app.tab != Tab::Graph;
    let graph_height = if chart && f.area().height >= GRAPH_HEIGHT + 10 { GRAPH_HEIGHT } else { 0 };
    let [header, graph, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(graph_height),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(f.area());

    // Loopback is excluded from the totals because both ends of each
    // packet are local.
    let (tx, rx) = c.total_history.back().copied().unwrap_or_default();
    if graph_height > 0 {
        draw_graph(f, app, c, graph);
    }
    let paused = if app.paused { "  [PAUSED]" } else { "" };
    let profile = if rules.profile.is_empty() { String::new() } else { format!("  PROFILE {}", rules.profile) };
    let capturing = match cap {
        Some(k) if k.running => format!("  ● capturing {}", k.target.label()),
        Some(k) => format!("  ■ stopped {}", k.target.label()),
        None => String::new(),
    };
    f.render_widget(
        Paragraph::new(format!(
            " netmon   ↑ {}  ↓ {}   flows {}{}{}{}   {}",
            rate(tx),
            rate(rx),
            c.flows.len(),
            match (rules.rules.len(), rules.default) {
                (0, Action::Allow) => String::new(),
                (n, Action::Allow) => format!("  RULES {n}"),
                (n, Action::Deny) => format!("  RULES {n}  DEFAULT DENY"),
                (n, Action::Ask) => format!("  RULES {n}  ASK"),
            },
            match &app.ask {
                Some((_, more)) if app.ask_hidden => format!("  {} QUESTIONS WAITING (? shows)", more + 1),
                _ => String::new(),
            } + &profile
                + paused,
            capturing,
            app.status
        ))
        .style(Style::new().add_modifier(Modifier::BOLD)),
        header,
    );

    let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    f.render_widget(
        Tabs::new(Tab::ALL.iter().enumerate().map(|(i, t)| format!("{} {}", i + 1, t.title())))
            .select(idx)
            .highlight_style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        tabs,
    );

    match app.tab {
        Tab::Connections => draw_conns(f, app, c, names, rules, body),
        Tab::Rules => draw_rules(f, app, rules, body),
        Tab::Processes => draw_procs(f, app, c, names, rules, body),
        Tab::Interfaces => draw_ifaces(f, app, c, names, body),
        Tab::Capture => draw_capture(f, cap, names, body),
        Tab::Graph => draw_conn_graph(f, app, c, names, body),
        Tab::Hosts => draw_hosts(f, app, rules, body),
        Tab::Log => draw_log(f, app, body),
        Tab::Usage => draw_usage(f, app, body),
    }

    let sort = match app.sort {
        Sort::Rate => "rate",
        Sort::Total => "total",
        Sort::Process => "name",
    };
    let footer_text = if app.editing_host {
        format!(" block host (name or *.domain): {}█   (Enter block, Esc cancel)", app.host_input)
    } else if app.editing_capture_filter {
        format!(
            " capture filter (tcp, udp, port 443, host 1.1.1.1, net 10.0.0.0/8, dns, tls, not, and, or): {}█   (Enter apply, empty clears, Esc cancel)",
            app.capture_filter_input
        )
    } else if app.editing_filter {
        format!(" filter: {}█   (Enter keep, Esc clear)", app.filter)
    } else if app.tab == Tab::Capture {
        " q quit  ←→/1-9 view  ↑↓ PgUp/PgDn Home select  End/f follow  / filter  s save shown as .pcap  c clear  x stop  g graph".to_string()
    } else if app.tab == Tab::Hosts {
        " q quit  ←→/1-9 view  ↑↓ select  a block a host  d remove  r reload lists  s save to rules file".to_string()
    } else if app.tab == Tab::Graph {
        format!(
            " q quit  ←→/1-9 view  ↑↓ select node  Enter its connections  b block it  z level [{}]  p pause  h names  v veth/bridge [{}]",
            app.graph_level.label(),
            if app.show_virtual { "on" } else { "off" }
        )
    } else if app.tab == Tab::Usage {
        format!(" q quit  ←→/1-9 view  ↑↓ select  / filter [{}]   local days; netmond writes every 60 s", app.filter)
    } else if app.tab == Tab::Log {
        format!(" q quit  ←→/1-9 view  ↑↓ select  / filter [{}]   newest first, read every 2 s", app.filter)
    } else if app.tab == Tab::Rules {
        " q quit  ←→/1-9 view  ↑↓ select  d remove rule  t end time 1h/1d/never  P profile  s save to rules file   tmp rules end when the monitor stops".to_string()
    } else {
        let block = match app.tab {
            Tab::Connections => "  b/B/H block ip/port/host",
            Tab::Processes => "  b block exe  Q QUIC off",
            _ => "",
        };
        format!(
            " q quit  ←→/1-9 view  Enter capture{block}  r/t/n sort [{sort}]  / filter [{}]  h names  v veth/bridge [{}]  p pause  g graph",
            app.filter,
            if app.show_virtual { "on" } else { "off" }
        )
    };
    f.render_widget(Paragraph::new(footer_text).style(Style::new().fg(Color::DarkGray)), footer);
    if app.picking_profile {
        draw_profiles(f, app, rules);
    }
    if let Some((p, more)) = &app.ask
        && !app.ask_hidden
    {
        draw_ask(f, p, *more, &app.status);
    }
}

/// The profile picker over the Rules tab.
fn draw_profiles(f: &mut Frame, app: &App, rules: &Rules) {
    let active = if rules.profile.is_empty() { "default" } else { rules.profile.as_str() };
    let a = f.area();
    let h = (app.profiles.len() as u16 + 4).min(a.height.saturating_sub(2));
    let w = 50.min(a.width.saturating_sub(4));
    let r = Rect { x: a.x + (a.width - w) / 2, y: a.y + (a.height - h) / 2, width: w, height: h };
    let mut lines: Vec<Line> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mark = if p == active { " (active)" } else { "" };
            let style = if i == app.profile_sel { Style::new().fg(Color::Black).bg(Color::Cyan) } else { Style::new() };
            Line::from(Span::styled(format!(" {p}{mark} "), style))
        })
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("↑↓ select  Enter load  Esc cancel", Style::new().fg(Color::Yellow))));
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" rule profile ").border_style(Style::new().fg(Color::Cyan))),
        r,
    );
}

/// Color of an edge by the kernel's verdict. Idle edges are gray.
fn verdict_color(v: Verdict, rate: f64) -> Color {
    match v {
        Verdict::Deny => Color::Red,
        Verdict::Ask => Color::Yellow,
        _ if rate < 1.0 => Color::DarkGray,
        Verdict::Allow => Color::Green,
        Verdict::None => Color::Blue,
    }
}

/// The Graph tab: processes around this host, their remote ends outside.
/// Dots run along each line: outward for upload, inward for download.
fn draw_conn_graph(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, area: Rect) {
    let g = graph::build(c, names, app.show_virtual, app.show_hosts, app.graph_level);
    app.graph_labels = g.nodes.iter().map(|n| n.label.clone()).collect();
    app.graph_targets = g.nodes.iter().map(|n| n.target.clone()).collect();
    // Advance each edge's dots by the time since the last frame.
    let dt = (app.anim - app.anim_drawn).clamp(0.0, 1.0);
    app.anim_drawn = app.anim;
    let edge_key = |e: &graph::Edge| (g.nodes[e.from].label.clone(), g.nodes[e.to].label.clone());
    let live: std::collections::HashSet<_> = g.edges.iter().map(edge_key).collect();
    app.graph_motion.retain(|k, _| live.contains(k));
    for e in &g.edges {
        app.graph_motion.entry(edge_key(e)).or_default().step(dt, e.traffic.tx, e.traffic.rx);
    }
    let motion = &app.graph_motion;
    app.graph_sel = app.graph_sel.min(g.nodes.len().saturating_sub(1));
    let [canvas_area, info] = Layout::vertical([Constraint::Min(5), Constraint::Length(1)]).areas(area);
    let sel = app.graph_sel;
    let canvas = Canvas::default()
        .block(Block::default().borders(Borders::ALL).title(format!(" connections by {} ", app.graph_level.label())))
        .marker(Marker::Braille)
        .x_bounds([-1.3, 1.3])
        .y_bounds([-1.15, 1.15])
        .paint(|ctx| {
            for e in &g.edges {
                let (a, b) = (&g.nodes[e.from], &g.nodes[e.to]);
                let color = verdict_color(e.traffic.verdict, e.traffic.tx + e.traffic.rx);
                ctx.draw(&CanvasLine { x1: a.x, y1: a.y, x2: b.x, y2: b.y, color });
                // Process to host, thin: every process belongs to this host.
                ctx.draw(&CanvasLine { x1: 0.0, y1: 0.0, x2: a.x, y2: a.y, color: Color::DarkGray });
            }
            ctx.layer();
            for e in &g.edges {
                let (a, b) = (&g.nodes[e.from], &g.nodes[e.to]);
                let at = |s: f64| (a.x + (b.x - a.x) * s, a.y + (b.y - a.y) * s);
                let m = motion.get(&edge_key(e)).copied().unwrap_or_default();
                let up: Vec<(f64, f64)> =
                    graph::dots_at(m.phase_up, graph::dot_count(m.up)).into_iter().map(at).collect();
                let down: Vec<(f64, f64)> =
                    graph::dots_at(m.phase_down, graph::dot_count(m.down)).into_iter().map(|s| at(1.0 - s)).collect();
                ctx.draw(&Points { coords: &up, color: Color::LightMagenta });
                ctx.draw(&Points { coords: &down, color: Color::LightCyan });
            }
            ctx.layer();
            for (i, n) in g.nodes.iter().enumerate() {
                let mut label: String = n.label.chars().take(22).collect();
                if n.label.chars().count() > 22 {
                    label.push('…');
                }
                let style = match n.kind {
                    _ if i == sel => Style::new().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD),
                    Kind::Host => Style::new().add_modifier(Modifier::BOLD),
                    Kind::Process => Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
                    Kind::Remote => Style::new().fg(Color::Gray),
                    Kind::More => Style::new().fg(Color::DarkGray),
                };
                // Centered on the node; labels on the left half end at it.
                let w = label.chars().count() as f64 * 2.6 / f64::from(canvas_area.width.max(1));
                let x = if n.x < -0.05 { n.x - w } else if n.x > 0.05 { n.x } else { n.x - w / 2.0 };
                ctx.print(x, n.y, Line::styled(label, style));
            }
        });
    f.render_widget(canvas, canvas_area);
    let text = match g.nodes.get(sel) {
        Some(n) => {
            let a = &n.traffic;
            let hidden = if g.hidden > 0 { format!("   {} quiet processes not shown", g.hidden) } else { String::new() };
            format!(" {}   ↑ {}  ↓ {}   {} connections{hidden}", n.label, rate(a.tx), rate(a.rx), a.conns)
        }
        None => " no connections".into(),
    };
    f.render_widget(Paragraph::new(text).style(Style::new().add_modifier(Modifier::BOLD)), info);
}

/// The oldest unanswered question, over everything.
fn draw_ask(f: &mut Frame, p: &Prompt, more: usize, status: &str) {
    const LIST: usize = 6;
    let area = f.area();
    let shown = p.dests.len().min(LIST);
    let w = area.width.saturating_sub(4).min(110);
    let h = (shown as u16 + 10).min(area.height);
    let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h };
    let who = if p.pid == 0 {
        "unknown process (no local socket: forwarded, container or VM traffic)".to_string()
    } else {
        format!("{} (pid {}, user {})   exe {}", p.comm, p.pid, or_dash(&p.user), or_dash(&p.exe))
    };
    let mut text = vec![
        Line::from(Span::styled(who, Style::new().add_modifier(Modifier::BOLD))),
        Line::from(format!("wants {} connections to {} destinations:", p.conns(), p.dests.len())),
    ];
    // A window of LIST destinations that keeps the selected one visible.
    let start = p.selected.saturating_sub(LIST - 1).min(p.dests.len().saturating_sub(LIST));
    for (i, d) in p.dests.iter().enumerate().skip(start).take(LIST) {
        let ip = d.remote.to_string();
        let target = match &d.host {
            Some(h) => format!("{h} ({ip})"),
            None => ip,
        };
        let line = format!("{} {target}  {} {}  ×{}", if i == p.selected { ">" } else { " " }, proto_name(d.proto), d.port, d.conns.len());
        let style = if i == p.selected { Style::new().bg(Color::DarkGray) } else { Style::new() };
        text.push(Line::from(Span::styled(line, style)));
    }
    let rule = match p.rule_match() {
        Some(m) if p.exe.is_empty() => format!("rule: {m} (any process)"),
        Some(m) => format!("rule: {m}"),
        None => "process unknown: no program rule, pick port or destination".into(),
    };
    let left = ASK_TIMEOUT.saturating_sub(p.since.elapsed()).as_secs();
    let more = if more > 0 { format!("   {more} more waiting") } else { String::new() };
    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::raw("scope ←→ "),
        Span::styled(p.scope.label(), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(format!("   {rule}")),
    ]));
    text.push(Line::from(Span::styled(
        "a allow  A allow always  h/H allow/deny 1 h  d deny  D deny always   o/x allow/deny selected once   ↑↓ select   Esc later",
        Style::new().fg(Color::Yellow),
    )));
    text.push(Line::from(format!("no answer in {left} s: deny once{more}")));
    text.push(Line::from(Span::styled(status.to_string(), Style::new().fg(Color::Cyan))));
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(text).block(
            Block::new().borders(Borders::ALL).title(" netmon asks ").border_style(Style::new().fg(Color::Yellow)),
        ),
        r,
    );
}

/// Mirrored histogram of total traffic: download above the zero line,
/// upload below. Each half has its own scale, shown on the y axis, so a
/// small upload stays visible next to a large download.
/// The newest sample is on the right.
fn draw_graph(f: &mut Frame, app: &App, c: &Collector, area: Rect) {
    let hist = &c.total_history;
    let peak_down = hist.iter().map(|h| h.1).fold(0.0, f64::max).max(1.0);
    let peak_up = hist.iter().map(|h| h.0).fold(0.0, f64::max).max(1.0);
    let start = HISTORY - hist.len();
    // Each sample becomes 4 points across its slot, so Braille bars have no
    // gaps on terminals wider than the history length.
    const SUB: usize = 4;
    let bars = |value: &dyn Fn(&(f64, f64)) -> f64| -> Vec<(f64, f64)> {
        hist.iter()
            .enumerate()
            .flat_map(|(i, h)| {
                let v = value(h);
                (0..SUB).map(move |j| ((start + i) as f64 + j as f64 / SUB as f64, v))
            })
            .collect()
    };
    let down = bars(&|h| h.1 / peak_down);
    let up = bars(&|h| -h.0 / peak_up);
    let (now_up, now_down) = hist.back().copied().unwrap_or_default();

    let down_style = Style::new().fg(Color::Green);
    let up_style = Style::new().fg(Color::Magenta);
    let title = Line::from(vec![
        Span::raw(" traffic (excl. lo)  "),
        Span::styled(format!("↓ {}", rate(now_down)), down_style.add_modifier(Modifier::BOLD)),
        Span::raw(format!(" peak {}   ", rate(peak_down))),
        Span::styled(format!("↑ {}", rate(now_up)), up_style.add_modifier(Modifier::BOLD)),
        Span::raw(format!(" peak {} ", rate(peak_up))),
    ]);
    let span_secs = (HISTORY as f64 * app.interval_secs).round();
    let chart = Chart::new(vec![
        Dataset::default().marker(Marker::Braille).graph_type(GraphType::Bar).style(down_style).data(&down),
        Dataset::default().marker(Marker::Braille).graph_type(GraphType::Bar).style(up_style).data(&up),
    ])
    .block(Block::bordered().title(title))
    .x_axis(
        Axis::default()
            .bounds([0.0, HISTORY as f64])
            .labels([format!("-{span_secs}s"), "now".to_string()])
            .style(Style::new().fg(Color::DarkGray)),
    )
    .y_axis(
        Axis::default()
            .bounds([-1.0, 1.0])
            .labels([
                Span::styled(format!("↑{}", rate(peak_up)), up_style),
                Span::raw("0"),
                Span::styled(format!("↓{}", rate(peak_down)), down_style),
            ])
            .style(Style::new().fg(Color::DarkGray)),
    );
    f.render_widget(chart, area);
}

fn draw_capture(f: &mut Frame, cap: Option<&Capture>, names: &Names, area: Rect) {
    let Some(cap) = cap else {
        f.render_widget(
            Paragraph::new(
                "\n  No capture running.\n\n  Select a row in Connections, Processes or Interfaces and press Enter.\n  \
                 Process and connection captures start with the flows known at that moment;\n  \
                 new flows of a process join within about a second.",
            )
            .block(Block::new().borders(Borders::TOP)),
            area,
        );
        return;
    };
    let [info, list, detail] =
        Layout::vertical([Constraint::Length(1), Constraint::Percentage(55), Constraint::Min(5)]).areas(area);
    let shown = cap.shown();
    let follow = match (cap.running, cap.follow) {
        (false, _) => "STOPPED (Enter on a row in tabs 1-3 starts a new capture)",
        (true, true) => "following",
        (true, false) => "paused view (End to follow)",
    };
    f.render_widget(
        Paragraph::new(format!(
            " {}   kept {}  received {}  ring drops {}   {follow}{}",
            cap.target.label(),
            cap.packets.len(),
            cap.received,
            cap.dropped,
            match &cap.filter {
                Some(flt) => format!("   filter [{}] shows {}", flt.text(), shown.len()),
                None => String::new(),
            }
        ))
        .style(Style::new().fg(Color::Yellow)),
        info,
    );

    // Only build rows for the visible window: a capture can hold 20k packets.
    let visible = list.height.saturating_sub(2).max(1) as usize;
    let pos = shown.partition_point(|i| *i <= cap.selected).saturating_sub(1);
    let start = pos.saturating_sub(visible - 1);
    let first_no = cap.received - cap.packets.len() as u64 + 1;
    let rows = shown.iter().skip(start).take(visible).filter_map(|&i| cap.packets.get(i).map(|p| (i, p))).map(|(i, p)| {
        let t = p.time.duration_since(cap.started).unwrap_or_default().as_secs_f64();
        let s = &p.decoded.summary;
        let dir = if p.egress {
            Cell::from("↑").style(Style::new().fg(Color::Magenta))
        } else {
            Cell::from("↓").style(Style::new().fg(Color::Green))
        };
        Row::new(vec![
            Cell::from(Line::from((first_no + i as u64).to_string()).right_aligned()),
            Cell::from(format!("{t:.3}")),
            dir,
            Cell::from(names.get(p.ifindex)),
            Cell::from(s.src.clone()),
            Cell::from(s.dst.clone()),
            Cell::from(s.proto.clone()),
            Cell::from(Line::from(p.orig_len.to_string()).right_aligned()),
            Cell::from(s.info.clone()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(1),
            Constraint::Length(10),
            Constraint::Length(24),
            Constraint::Length(24),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Fill(1),
        ],
    )
    .header(header_row(&["No.", "Time", "", "Iface", "Source", "Destination", "Proto", "Len", "Info"]))
    .block(Block::new().borders(Borders::TOP))
    .row_highlight_style(Style::new().bg(Color::DarkGray));
    let mut state = TableState::default().with_selected((!shown.is_empty()).then_some(pos - start));
    f.render_stateful_widget(table, list, &mut state);

    let Some(p) = shown.get(pos).and_then(|i| cap.packets.get(*i)) else { return };
    let [fields, hex] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(76)]).areas(detail);
    let mut lines: Vec<Line> = vec![Line::from(format!(
        "{}  {}  {} bytes on wire, {} captured",
        if p.egress { "egress" } else { "ingress" },
        names.get(p.ifindex),
        p.orig_len,
        p.data.len()
    ))];
    lines.extend(p.decoded.lines.iter().map(|l| Line::from(l.clone())));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(ratatui::widgets::Wrap { trim: false })
            .block(Block::bordered().title(" decoded ")),
        fields,
    );
    let dump: Vec<Line> = hexdump(&p.data).into_iter().map(Line::from).collect();
    f.render_widget(Paragraph::new(dump).block(Block::bordered().title(" bytes ")), hex);
}

fn header_row(cols: &[&'static str]) -> Row<'static> {
    Row::new(cols.iter().copied()).style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
}

fn render_table(f: &mut Frame, app: &mut App, table: Table, ids: &[RowId], area: Rect) {
    let selected = app.sync_selection(ids);
    let mut state = TableState::default().with_selected(Some(selected));
    f.render_stateful_widget(
        table
            .block(Block::new().borders(Borders::TOP))
            .row_highlight_style(Style::new().bg(Color::DarkGray)),
        area,
        &mut state,
    );
}

fn draw_conns(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, rules: &Rules, area: Rect) {
    let rows = app.conn_rows(c, names);
    let ids: Vec<RowId> = rows.iter().map(|r| r.id()).collect();
    let [area, detail] = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(area);
    let geo_col = app.geo.loaded();
    let line = match app.selected_in(&ids).map(|i| &rows[i]) {
        Some(r) if !r.source.is_empty() => format!(
            " {}{}{}   exe {}   user {}   unit {}   owner from {}{}",
            r.remote_addr,
            name_source(r),
            if r.geo.is_empty() { String::new() } else { format!("   {}", r.geo) },
            or_dash(&r.exe),
            or_dash(&r.user),
            or_dash(&r.unit),
            r.source,
            verdict(r)
        ),
        Some(r) => format!(" {}{}   owner unknown{}", r.remote_addr, name_source(r), verdict(r)),
        None => String::new(),
    };
    f.render_widget(Paragraph::new(line).style(Style::new().fg(Color::Cyan)), detail);
    let table = Table::new(
        rows.into_iter().map(|r| {
            let remote = addr(r.key.family, &r.key.remote_addr, r.key.remote_port);
            // The kernel's verdict when it has one; else what the rules say
            // for a new outbound connection.
            let blocked = match r.conn {
                Some(c) => c.action == ACTION_DENY,
                None => rules.denies(r.key.proto, remote, &r.exe, Dir::Out),
            };
            let style = if blocked { Style::new().fg(Color::Red) } else { Style::new() };
            let mut cells = vec![
                Cell::from(r.process),
                Cell::from(r.pid),
                Cell::from(r.proto),
                Cell::from(r.local),
                Cell::from(r.remote),
            ];
            if geo_col {
                cells.push(Cell::from(r.geo));
            }
            cells.extend([
                Cell::from(r.iface),
                Cell::from(r.state),
                Cell::from(Line::from(rate(r.tx_rate)).right_aligned()),
                Cell::from(Line::from(rate(r.rx_rate)).right_aligned()),
                Cell::from(Line::from(human(r.total as f64)).right_aligned()),
            ]);
            Row::new(cells).style(style)
        }),
        conn_columns(geo_col),
    )
    .header(header_row(&conn_headers(geo_col)));
    render_table(f, app, table, &ids, area);
}

fn draw_rules(f: &mut Frame, app: &mut App, rules: &Rules, area: Rect) {
    if rules.rules.is_empty() {
        f.render_widget(
            Paragraph::new(
                "\n  No rules.\n\n  In Connections, b blocks the selected row's remote address and B its\n  \
                 remote port; in Processes, b blocks the process's exe. Blocks end when the monitor stops, unless saved with s.\n  \
                 Rules that load at start go in /etc/netmon/rules.toml (see README). Loopback, this SSH\n  \
                 session and DNS to the resolvers in /etc/resolv.conf are never blocked.",
            )
            .block(Block::new().borders(Borders::TOP)),
            area,
        );
        return;
    }
    let ids: Vec<RowId> = rules.rules.iter().map(|r| RowId::Rule(r.id)).collect();
    let now = crate::rules::unix_now();
    let table = Table::new(
        rules.rules.iter().enumerate().map(|(i, r)| {
            let color = if r.action == Action::Deny { Color::Red } else { Color::Green };
            Row::new(vec![
                Cell::from((i + 1).to_string()),
                Cell::from(action_label(r, now)),
                Cell::from(r.m.to_string()),
                Cell::from(r.comment.clone()),
                Cell::from(Line::from(r.hits.to_string()).right_aligned()),
            ])
            .style(Style::new().fg(color))
        }),
        [Constraint::Length(4), Constraint::Length(14), Constraint::Fill(2), Constraint::Fill(1), Constraint::Length(12)],
    )
    .header(header_row(&["#", "Action", "Match", "Comment", "Hits"]));
    render_table(f, app, table, &ids, area);
}

/// The Action cell of a rule: "allow", "deny tmp", "allow 59m".
fn action_label(r: &crate::rules::Rule, now: u64) -> String {
    let mut s = r.action.to_string();
    if r.temporary {
        s.push_str(" tmp");
    }
    if let Some(u) = r.until {
        s.push(' ');
        s.push_str(&crate::rules::time_left(u, now));
    }
    s
}

/// The Usage tab: traffic per program for today, yesterday, 7 and 30 days.
fn draw_usage(f: &mut Frame, app: &mut App, area: Rect) {
    if app.usage.is_empty() {
        let why = if app.usage_error.is_empty() { "No traffic counted yet.".to_string() } else { app.usage_error.clone() };
        f.render_widget(
            Paragraph::new(format!(
                "\n  {why}\n\n  netmond adds up the traffic of each program per day in {} and writes it every\n  \
                 60 s (see README).",
                crate::usage::DEFAULT_PATH
            ))
            .block(Block::new().borders(Borders::TOP)),
            area,
        );
        return;
    }
    let rows = app.usage_rows();
    let ids: Vec<RowId> = rows.iter().map(|r| RowId::Usage(r.program.clone())).collect();
    let bytes = |n: u64| Cell::from(Line::from(human(n as f64)).right_aligned());
    let sum = |w: [u64; 2]| w[0] + w[1];
    let lines: Vec<Row> = rows
        .iter()
        .map(|r| {
            Row::new(vec![
                Cell::from(r.program.clone()),
                bytes(r.today[1]),
                bytes(r.today[0]),
                bytes(sum(r.yesterday)),
                bytes(sum(r.week)),
                bytes(sum(r.month)),
            ])
        })
        .collect();
    let table = Table::new(
        lines,
        [
            Constraint::Fill(1),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(11),
        ],
    )
    .header(header_row(&["Program", "Today ↓", "Today ↑", "Yesterday", "7 days", "30 days"]));
    render_table(f, app, table, &ids, area);
}

/// The Log tab: the newest lines of the connection log.
fn draw_log(f: &mut Frame, app: &mut App, area: Rect) {
    if app.log.is_empty() {
        let why = if app.log_error.is_empty() { "The log is empty.".to_string() } else { app.log_error.clone() };
        f.render_widget(
            Paragraph::new(format!(
                "\n  {why}\n\n  netmond writes one line per new connection of a program to a destination, and per\n  \
                 denied outbound connection, to {} (see README).",
                crate::connlog::DEFAULT_PATH
            ))
            .block(Block::new().borders(Borders::TOP)),
            area,
        );
        return;
    }
    let rows = app.log_rows();
    let ids: Vec<RowId> = rows.iter().map(|(_, id)| id.clone()).collect();
    let lines: Vec<Row> = rows
        .iter()
        .map(|(e, _)| {
            let color = if e.event == "denied" { Color::Red } else { Color::Reset };
            let program = if e.exe.is_empty() { e.comm.clone() } else { format!("{} ({})", e.comm, e.exe) };
            let host = if e.host.is_empty() { String::new() } else { e.host.clone() };
            Row::new(vec![
                Cell::from(e.time.replace('T', " ").trim_end_matches('Z').to_string()),
                Cell::from(e.event.clone()),
                Cell::from(e.dir.clone()),
                Cell::from(e.proto.clone()),
                Cell::from(std::net::SocketAddr::new(e.remote, e.port).to_string()),
                Cell::from(host),
                Cell::from(if e.pid == 0 { "?".to_string() } else { e.pid.to_string() }),
                Cell::from(program),
            ])
            .style(Style::new().fg(color))
        })
        .collect();
    let table = Table::new(
        lines,
        [
            Constraint::Length(19),
            Constraint::Length(6),
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(30),
            Constraint::Fill(1),
            Constraint::Length(8),
            Constraint::Fill(2),
        ],
    )
    .header(header_row(&["Time (UTC)", "Event", "Dir", "Proto", "Remote", "Host", "PID", "Program"]));
    render_table(f, app, table, &ids, area);
}

/// The Hosts tab: blocked hostnames, the addresses learned for them and
/// the connections they denied.
fn draw_hosts(f: &mut Frame, app: &mut App, rules: &Rules, area: Rect) {
    if rules.hosts.is_empty() && rules.blocklists.is_empty() {
        f.render_widget(
            Paragraph::new(
                "\n  No blocked hosts.\n\n  a blocks a hostname: ads.example.com blocks that name, *.example.com also every\n  \
                 name below it. In Connections, H blocks the hostname of the selected row.\n\n  \
                 netmon learns the addresses from DNS answers and TLS server names and blocks them in\n  \
                 the kernel, also on open connections. s saves the list with the rules.\n\n  \
                 Lists of many names (hosts files, adblock lists) go in the rules file as [[blocklist]]\n  \
                 sections (see README). r reads them again.",
            )
            .block(Block::new().borders(Borders::TOP)),
            area,
        );
        return;
    }
    let ids = host_row_ids(rules);
    let lists = rules.blocklists.iter().map(|l| {
        let what = if l.error.is_empty() {
            format!("{} names{}", l.count, if l.skipped > 0 { format!(", {} lines skipped", l.skipped) } else { String::new() })
        } else {
            format!("not read: {}", l.error)
        };
        Row::new(vec![
            Cell::from(format!("list {}", l.path)),
            Cell::from(Line::from(l.addrs.to_string()).right_aligned()),
            Cell::from(what),
            Cell::from(l.comment.clone()),
            Cell::from(Line::from(l.hits.to_string()).right_aligned()),
        ])
        .style(Style::new().fg(if l.error.is_empty() { Color::Red } else { Color::Yellow }))
    });
    let table = Table::new(
        rules.hosts.iter().map(|h| {
            let mut addrs: Vec<String> = h.addrs.iter().take(4).map(|a| a.to_string()).collect();
            if h.addrs.len() > 4 {
                addrs.push(format!("+{} more", h.addrs.len() - 4));
            }
            let addrs = if addrs.is_empty() { "none seen yet".to_string() } else { addrs.join(", ") };
            Row::new(vec![
                Cell::from(h.pattern.clone()),
                Cell::from(Line::from(h.addrs.len().to_string()).right_aligned()),
                Cell::from(addrs),
                Cell::from(h.comment.clone()),
                Cell::from(Line::from(h.hits.to_string()).right_aligned()),
            ])
            .style(Style::new().fg(Color::Red))
        })
        .chain(lists),
        [Constraint::Fill(1), Constraint::Length(6), Constraint::Fill(2), Constraint::Fill(1), Constraint::Length(10)],
    )
    .header(header_row(&["Host", "Addrs", "Addresses", "Comment", "Hits"]));
    render_table(f, app, table, &ids, area);
}

/// Column widths of the Connections tab, with the Geo column or without.
fn conn_columns(geo: bool) -> Vec<Constraint> {
    let mut c = vec![Constraint::Length(16), Constraint::Length(7), Constraint::Length(5), Constraint::Fill(1), Constraint::Fill(1)];
    if geo {
        c.push(Constraint::Fill(1));
    }
    c.extend([Constraint::Length(12), Constraint::Length(10), Constraint::Length(10), Constraint::Length(10), Constraint::Length(8)]);
    c
}

fn conn_headers(geo: bool) -> Vec<&'static str> {
    let mut h = vec!["Process", "PID", "Proto", "Local", "Remote"];
    if geo {
        h.push("Geo (DB-IP)");
    }
    h.extend(["Iface", "State", "↑", "↓", "Total"]);
    h
}

/// Row ids of the Hosts tab: the host blocks, then the lists.
pub fn host_row_ids(rules: &Rules) -> Vec<RowId> {
    rules.hosts.iter().map(|h| h.id).chain(rules.blocklists.iter().map(|l| l.id)).map(RowId::Host).collect()
}

/// " (name from tls)" when the row has a hostname.
fn name_source(r: &ConnRow) -> String {
    if r.host.is_some() { format!(" (name from {})", r.host_source) } else { String::new() }
}

/// "   opened out, allowed" from the kernel's connection state.
fn verdict(r: &ConnRow) -> String {
    match r.conn {
        Some(c) => format!(
            "   opened {}, {}",
            if c.dir == DIR_IN { "in" } else { "out" },
            if c.action == ACTION_DENY { "denied" } else { "allowed" }
        ),
        None => String::new(),
    }
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

fn draw_procs(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, rules: &Rules, area: Rect) {
    let rows = app.proc_rows(c, names);
    let ids: Vec<RowId> = rows.iter().map(|r| r.id()).collect();
    let table = Table::new(
        rows.into_iter().map(|r| {
            let blocked = rules.denies_exe(&r.exe);
            let style = if blocked { Style::new().fg(Color::Red) } else { Style::new() };
            Row::new(vec![
                Cell::from(r.process),
                Cell::from(r.pid),
                Cell::from(r.user),
                Cell::from(r.exe),
                Cell::from(Line::from(r.conns.to_string()).right_aligned()),
                Cell::from(Line::from(rate(r.tx_rate)).right_aligned()),
                Cell::from(Line::from(rate(r.rx_rate)).right_aligned()),
                Cell::from(Line::from(human(r.total as f64)).right_aligned()),
            ])
            .style(style)
        }),
        [
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(header_row(&["Process", "PID", "User", "Exe", "Flows", "↑", "↓", "Total"]));
    render_table(f, app, table, &ids, area);
}

fn draw_ifaces(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, area: Rect) {
    let rows = app.iface_rows(c, names);
    let [list, spark] = Layout::vertical([Constraint::Min(3), Constraint::Length(8)]).areas(area);
    let ids: Vec<RowId> = rows.iter().map(|r| r.id()).collect();
    let selected = app.selected_in(&ids).map(|i| (rows[i].index, rows[i].name.clone()));
    let table = Table::new(
        rows.into_iter().map(|r| {
            Row::new(vec![
                Cell::from(r.name),
                Cell::from(r.kind),
                Cell::from(Line::from(rate(r.tx_rate)).right_aligned()),
                Cell::from(Line::from(rate(r.rx_rate)).right_aligned()),
                Cell::from(Line::from(human(r.total as f64)).right_aligned()),
            ])
        }),
        [Constraint::Fill(1), Constraint::Length(10), Constraint::Length(12), Constraint::Length(12), Constraint::Length(10)],
    )
    .header(header_row(&["Interface", "Kind", "↑", "↓", "Total"]));
    render_table(f, app, table, &ids, list);

    if let Some((idx, name)) = selected {
        let data: Vec<u64> = c.ifaces.get(&idx).map(|s| s.history.iter().copied().collect()).unwrap_or_default();
        let peak = data.iter().copied().max().unwrap_or(0);
        f.render_widget(
            Sparkline::default()
                .block(Block::bordered().title(format!(" {name}: history, peak {} ", rate(peak as f64))))
                .data(&data)
                .style(Style::new().fg(Color::Green)),
            spark,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmon_common::{FlowKey, FlowStats};
    use ratatui::{Terminal, backend::TestBackend};

    /// Renders with fake traffic: a download ramp and a small upload.
    fn render(width: u16, height: u16, show_graph: bool) -> String {
        let mut c = Collector::new(1000);
        let mut k = FlowKey { family: 4, proto: 6, local_port: 1, remote_port: 443, ifindex: 2, ..Default::default() };
        k.local_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        k.remote_addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        let (mut tx, mut rx) = (0u64, 0u64);
        for i in 0..90u64 {
            tx += 20_000 + (i % 7) * 3_000;
            rx += (i % 30) * 40_000;
            c.ingest([(k, FlowStats { tx_bytes: tx, rx_bytes: rx, ..Default::default() })], 1.0);
        }
        let mut app = App { show_graph, ..App::default() };
        let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &Rules::default())).unwrap();
        let buf = term.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn graph_shows_on_top() {
        let screen = render(100, 30, true);
        println!("{screen}");
        assert!(screen.lines().nth(1).unwrap().contains("traffic (excl. lo)"));
        assert!(screen.contains("now"));
    }

    #[test]
    fn capture_view_lists_and_decodes() {
        use crate::capture::{Capture, Captured, Target};
        use crate::decode::tests::tcp_syn;
        use netmon_common::{CAPTURE_LEN, PacketEvent};
        let syn = tcp_syn();
        let mut ev = PacketEvent {
            ts_ns: 0, ifindex: 2, len: syn.len() as u32, cap_len: syn.len() as u32,
            ethertype: 0x0800, egress: 1, has_l2: 1, data: [0; CAPTURE_LEN],
        };
        ev.data[..syn.len()].copy_from_slice(&syn);
        let mut cap = Capture::new(Target::Interface { index: 2, name: "eth0".into() });
        for _ in 0..3 {
            cap.push(Captured::from_event(&ev, 0));
        }
        cap.dropped = 7;
        let mut app = App { tab: Tab::Capture, show_graph: false, ..App::default() };
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        let c = Collector::new(30);
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), Some(&cap), &Rules::default())).unwrap();
        let buf = term.backend().buffer();
        let screen = (0..30)
            .map(|y| (0..140).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        println!("{screen}");
        assert!(screen.contains("capturing interface eth0"));
        assert!(screen.contains("ring drops 7"));
        assert!(screen.contains("[SYN] seq 1000"));
        assert!(screen.contains("TCP     40000 → 443"));
        assert!(screen.contains("0000  aa bb cc dd ee ff"));
        // A filter that shows nothing: an empty list, no detail.
        cap.set_filter(Some(crate::pfilter::Filter::parse("dns").unwrap()));
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), Some(&cap), &Rules::default())).unwrap();
        let s = self::screen(&term);
        assert!(s.contains("filter [dns] shows 0") && !s.contains("[SYN] seq 1000"), "{s}");
    }

    #[test]
    fn log_tab_lists_entries_and_filters() {
        let e = |event: &str, port: u16, comm: &str| crate::connlog::Entry {
            time: "2026-11-23T14:08:08Z".into(),
            event: event.into(),
            dir: "out".into(),
            proto: "tcp".into(),
            remote: "1.1.1.1".parse().unwrap(),
            port,
            host: "one.one.one.one".into(),
            pid: 7,
            comm: comm.into(),
            exe: format!("/usr/bin/{comm}"),
        };
        let mut app = App { tab: Tab::Log, show_graph: false, ..App::default() };
        app.log = vec![e("denied", 25, "curl"), e("new", 443, "firefox")];
        let draw_log_tab = |app: &mut App| {
            let mut term = Terminal::new(TestBackend::new(140, 12)).unwrap();
            term.draw(|f| draw(f, app, &Collector::new(1), &Names::default(), None, &Rules::default())).unwrap();
            screen(&term)
        };
        let s = draw_log_tab(&mut app);
        assert!(s.contains("8 Log") && s.contains("Time (UTC)"), "{s}");
        assert!(s.contains("2026-11-23 14:08:08") && s.contains("1.1.1.1:25") && s.contains("curl (/usr/bin/curl)"), "{s}");
        app.filter = "firefox".into();
        let s = draw_log_tab(&mut app);
        assert!(s.contains("1.1.1.1:443") && !s.contains("1.1.1.1:25"), "{s}");
        app.log.clear();
        app.log_error = "/var/log/netmon/connections.log: No such file or directory".into();
        assert!(draw_log_tab(&mut app).contains("No such file"));
    }

    #[test]
    fn geo_column_only_with_databases() {
        assert_eq!(conn_columns(false).len(), conn_headers(false).len());
        assert_eq!(conn_columns(true).len(), conn_headers(true).len());
        assert!(!render(140, 20, false).contains("Geo (DB-IP)"), "no files, no column");
        let Some(dir) = std::env::var_os("NETMON_GEO_TEST_DIR") else { return };
        let mut c = Collector::new(30);
        let mut k = FlowKey { family: 4, proto: 6, local_port: 1, remote_port: 443, ifindex: 2, ..Default::default() };
        k.remote_addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        c.ingest([(k, FlowStats { tx_bytes: 5, ..Default::default() })], 1.0);
        let mut app = App { show_graph: false, ..App::default() };
        app.geo = crate::geo::Geo::open(std::path::Path::new(&dir));
        let mut term = Terminal::new(TestBackend::new(160, 12)).unwrap();
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &Rules::default())).unwrap();
        let s = screen(&term);
        assert!(s.contains("Geo (DB-IP)") && s.contains("AS13335 Cloudflare"), "{s}");
        app.filter = "cloudflare".into();
        assert_eq!(app.conn_rows(&c, &Names::default()).len(), 1, "the filter finds the AS name");
    }

    #[test]
    fn usage_tab_lists_programs() {
        let mut app = App { tab: Tab::Usage, show_graph: false, ..App::default() };
        let mut f = crate::usage::UsageFile::default();
        f.add("2026-11-23", "/usr/lib/firefox/firefox", 2_000_000, 300_000_000);
        f.add("2026-11-22", "/usr/lib/firefox/firefox", 0, 1_000_000_000);
        f.add("2026-11-23", "/usr/bin/curl", 10, 1000);
        app.usage = f.rows("2026-11-23");
        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|fr| draw(fr, &mut app, &Collector::new(1), &Names::default(), None, &Rules::default())).unwrap();
        let s = screen(&term);
        assert!(s.contains("9 Usage") && s.contains("Today ↓") && s.contains("30 days"), "{s}");
        let ff = s.lines().find(|l| l.contains("firefox")).unwrap();
        assert!(ff.contains(&human(300_000_000.0)) && ff.contains(&human(1_000_000_000.0)), "{ff}");
        assert!(s.find("firefox").unwrap() < s.find("curl").unwrap(), "busiest first");
    }

    #[test]
    fn profile_picker_marks_the_active_profile() {
        let mut app = App { tab: Tab::Rules, show_graph: false, picking_profile: true, ..App::default() };
        app.profiles = vec!["default".into(), "home".into(), "work".into()];
        app.profile_sel = 2;
        let mut rules = Rules::default();
        rules.profile = "home".into();
        let mut term = Terminal::new(TestBackend::new(100, 20)).unwrap();
        term.draw(|f| draw(f, &mut app, &Collector::new(1), &Names::default(), None, &rules)).unwrap();
        let s = screen(&term);
        assert!(s.contains("rule profile") && s.contains("home (active)") && s.contains(" work "), "{s}");
        assert!(s.contains("PROFILE home"), "header: {s}");
    }

    #[test]
    fn graph_hidden_by_toggle_or_small_terminal() {
        assert!(!render(100, 30, false).contains("traffic (excl. lo)"));
        assert!(!render(100, 15, true).contains("traffic (excl. lo)"));
    }

    fn screen(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer();
        let (w, h) = (buf.area.width, buf.area.height);
        (0..h).map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn owner_details_in_detail_line_and_process_tab() {
        use crate::procmap::{Owner, ProcDetails};
        let mut c = Collector::new(30);
        let mut k = FlowKey { family: 4, proto: 6, local_port: 1, remote_port: 443, ifindex: 2, ..Default::default() };
        k.local_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        c.ingest([(k, FlowStats { tx_bytes: 5, cookie: 9, ..Default::default() })], 1.0);
        let f = c.flows.get_mut(&k).unwrap();
        f.owner_cookie = 9;
        f.owner_source = crate::collector::OwnerSource::Kernel;
        f.owner = Some(Owner {
            details: Some(ProcDetails {
                name: String::new(),
                exe: "/usr/bin/curl".into(),
                user: "j".into(),
                unit: "app-foo.scope".into(),
                cgroup: "/user.slice/app-foo.scope".into(),
            }),
            ..Owner::new(7, "renamed")
        });
        let mut app = App { show_graph: false, ..App::default() };
        let mut term = Terminal::new(TestBackend::new(140, 12)).unwrap();
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &Rules::default())).unwrap();
        let s = screen(&term);
        println!("{s}");
        assert!(s.contains("exe /usr/bin/curl   user j   unit app-foo.scope   owner from kernel"));
        app.tab = Tab::Processes;
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &Rules::default())).unwrap();
        let s = screen(&term);
        println!("{s}");
        assert!(s.contains("renamed") && s.contains("/usr/bin/curl"));
    }

    #[test]
    fn blocked_rows_and_rules_tab() {
        use crate::rules::BlockTarget;
        let mut c = Collector::new(30);
        let mut k = FlowKey { family: 4, proto: 6, local_port: 1, remote_port: 443, ifindex: 2, ..Default::default() };
        k.remote_addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        c.ingest([(k, FlowStats { tx_bytes: 5, ..Default::default() })], 1.0);
        let mut rules = Rules::default();
        rules.block(BlockTarget::host("1.1.1.1".parse().unwrap())).unwrap();
        rules.rules[0].hits = 42;
        let mut app = App { show_graph: false, ..App::default() };
        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &rules)).unwrap();
        let buf = term.backend().buffer();
        let row = (0..10).find(|y| (0..120).map(|x| buf[(x, *y)].symbol()).collect::<String>().contains("1.1.1.1:443")).unwrap();
        assert_eq!(buf[(0, row)].fg, Color::Red, "blocked row is red");
        assert!(screen(&term).contains("RULES 1"));
        rules.default = Action::Deny;
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &rules)).unwrap();
        assert!(screen(&term).contains("DEFAULT DENY"));
        let dest = |last: u8, port, n| crate::ask::Dest {
            remote: std::net::IpAddr::from([93, 184, 215, last]),
            port,
            proto: 6,
            host: (last == 14).then(|| "example.com".to_string()),
            conns: vec![netmon_common::ConnKey::default(); n],
        };
        app.ask = Some((
            crate::ask::Prompt {
                id: 1,
                pid: 42,
                comm: "curl".into(),
                exe: "/usr/bin/curl".into(),
                user: "j".into(),
                dests: vec![dest(14, 443, 2), dest(15, 80, 1)],
                since: std::time::Instant::now(),
                selected: 1,
                scope: crate::ask::Scope::Port,
            },
            2,
        ));
        let mut big = Terminal::new(TestBackend::new(120, 20)).unwrap();
        big.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &rules)).unwrap();
        let s = screen(&big);
        println!("{s}");
        assert!(s.contains("netmon asks") && s.contains("wants 3 connections to 2 destinations"), "{s}");
        assert!(s.contains("example.com (93.184.215.14)  tcp 443  ×2"), "{s}");
        assert!(s.contains("> 93.184.215.15  tcp 80"), "{s}");
        assert!(s.contains("rule: out exe /usr/bin/curl tcp port 80") && s.contains("2 more waiting"), "{s}");
        app.ask = None;
        app.tab = Tab::Rules;
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &rules)).unwrap();
        let s = screen(&term);
        println!("{s}");
        assert!(s.contains("deny") && s.contains("host 1.1.1.1") && s.contains("42"));
    }

    #[test]
    fn graph_tab_draws_nodes_and_labels() {
        let mut c = Collector::new(30);
        let mut k = FlowKey { family: 4, proto: 6, local_port: 40000, remote_port: 443, ifindex: 2, ..Default::default() };
        k.local_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        k.remote_addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        c.ingest([(k, FlowStats { tx_bytes: 0, ..Default::default() })], 1.0);
        c.ingest([(k, FlowStats { tx_bytes: 50_000, rx_bytes: 900_000, ..Default::default() })], 1.0);
        let mut app = App { tab: Tab::Graph, anim: 1.3, ..App::default() };
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &Rules::default())).unwrap();
        let buf = term.backend().buffer();
        let text: String = (0..40).map(|y| (0..120).map(|x| buf[(x, y)].symbol()).collect::<String>() + "\n").collect();
        assert!(text.contains("this host"), "{text}");
        assert!(text.contains("1.1.1.1"), "{text}");
        assert!(text.contains("6 Graph"));
        assert_eq!(app.graph_labels, vec!["this host", "(forwarded)", "1.1.1.1"]);
        assert_eq!(app.graph_targets[2], graph::Target::Addr("1.1.1.1".parse().unwrap()), "b blocks the address");
        assert_eq!(app.graph_targets[1], graph::Target::None, "no exe known");
        // z: containers; the host's own processes share one node.
        app.on_key(crate::app::Key::Char('z'));
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None, &Rules::default())).unwrap();
        assert_eq!(app.graph_labels[1], "host processes");
    }

}

