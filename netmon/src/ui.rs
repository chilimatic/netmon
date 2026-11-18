//! Rendering with ratatui.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::Marker,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Sparkline, Table, TableState, Tabs},
};

use crate::{
    app::{App, Sort, Tab, human},
    capture::Capture,
    decode::hexdump,
    collector::{Collector, HISTORY},
    ifaces::Names,
};

fn rate(v: f64) -> String {
    format!("{}/s", human(v))
}

/// Rows the traffic graph takes. Hidden when the terminal is too short.
const GRAPH_HEIGHT: u16 = 10;

pub fn draw(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, cap: Option<&Capture>) {
    let graph_height = if app.show_graph && f.area().height >= GRAPH_HEIGHT + 10 { GRAPH_HEIGHT } else { 0 };
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
    let capturing = match cap {
        Some(k) if k.running => format!("  ● capturing {}", k.target.label()),
        Some(k) => format!("  ■ stopped {}", k.target.label()),
        None => String::new(),
    };
    f.render_widget(
        Paragraph::new(format!(
            " netmon   ↑ {}  ↓ {}   flows {}{}{}   {}",
            rate(tx),
            rate(rx),
            c.flows.len(),
            paused,
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
        Tab::Connections => draw_conns(f, app, c, names, body),
        Tab::Processes => draw_procs(f, app, c, body),
        Tab::Interfaces => draw_ifaces(f, app, c, names, body),
        Tab::Capture => draw_capture(f, cap, names, body),
    }

    let sort = match app.sort {
        Sort::Rate => "rate",
        Sort::Total => "total",
        Sort::Process => "name",
    };
    let footer_text = if app.editing_filter {
        format!(" filter: {}█   (Enter keep, Esc clear)", app.filter)
    } else if app.tab == Tab::Capture {
        " q quit  ←→/1-4 view  ↑↓ PgUp/PgDn Home select  End/f follow  s save .pcap  c clear  x stop  g graph".to_string()
    } else {
        format!(
            " q quit  ←→/1-4 view  Enter capture selected  r/t/n sort [{sort}]  / filter [{}]  p pause  g graph  ↑↓ select",
            app.filter
        )
    };
    f.render_widget(Paragraph::new(footer_text).style(Style::new().fg(Color::DarkGray)), footer);
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
    let follow = match (cap.running, cap.follow) {
        (false, _) => "STOPPED (Enter on a row in tabs 1-3 starts a new capture)",
        (true, true) => "following",
        (true, false) => "paused view (End to follow)",
    };
    f.render_widget(
        Paragraph::new(format!(
            " {}   kept {}  received {}  ring drops {}   {follow}",
            cap.target.label(),
            cap.packets.len(),
            cap.received,
            cap.dropped
        ))
        .style(Style::new().fg(Color::Yellow)),
        info,
    );

    // Only build rows for the visible window: a capture can hold 20k packets.
    let visible = list.height.saturating_sub(2).max(1) as usize;
    let start = cap.selected.saturating_sub(visible - 1);
    let first_no = cap.received - cap.packets.len() as u64 + 1;
    let rows = cap.packets.iter().enumerate().skip(start).take(visible).map(|(i, p)| {
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
    let mut state = TableState::default().with_selected(Some(cap.selected - start));
    f.render_stateful_widget(table, list, &mut state);

    let Some(p) = cap.packets.get(cap.selected) else { return };
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

fn render_table(f: &mut Frame, app: &mut App, table: Table, len: usize, area: Rect) {
    app.selected = app.selected.min(len.saturating_sub(1));
    let mut state = TableState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(
        table
            .block(Block::new().borders(Borders::TOP))
            .row_highlight_style(Style::new().bg(Color::DarkGray)),
        area,
        &mut state,
    );
}

fn draw_conns(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, area: Rect) {
    let rows = app.conn_rows(c, names);
    let len = rows.len();
    let table = Table::new(
        rows.into_iter().map(|r| {
            Row::new(vec![
                Cell::from(r.process),
                Cell::from(r.pid),
                Cell::from(r.proto),
                Cell::from(r.local),
                Cell::from(r.remote),
                Cell::from(r.iface),
                Cell::from(r.state),
                Cell::from(Line::from(rate(r.tx_rate)).right_aligned()),
                Cell::from(Line::from(rate(r.rx_rate)).right_aligned()),
                Cell::from(Line::from(human(r.total as f64)).right_aligned()),
            ])
        }),
        [
            Constraint::Length(16),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .header(header_row(&["Process", "PID", "Proto", "Local", "Remote", "Iface", "State", "↑", "↓", "Total"]));
    render_table(f, app, table, len, area);
}

fn draw_procs(f: &mut Frame, app: &mut App, c: &Collector, area: Rect) {
    let rows = app.proc_rows(c);
    let len = rows.len();
    let table = Table::new(
        rows.into_iter().map(|r| {
            Row::new(vec![
                Cell::from(r.process),
                Cell::from(r.pid),
                Cell::from(Line::from(r.conns.to_string()).right_aligned()),
                Cell::from(Line::from(rate(r.tx_rate)).right_aligned()),
                Cell::from(Line::from(rate(r.rx_rate)).right_aligned()),
                Cell::from(Line::from(human(r.total as f64)).right_aligned()),
            ])
        }),
        [
            Constraint::Fill(1),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(header_row(&["Process", "PID", "Flows", "↑", "↓", "Total"]));
    render_table(f, app, table, len, area);
}

fn draw_ifaces(f: &mut Frame, app: &mut App, c: &Collector, names: &Names, area: Rect) {
    let rows = app.iface_rows(c, names);
    let [list, spark] = Layout::vertical([Constraint::Min(3), Constraint::Length(8)]).areas(area);
    let selected = rows.get(app.selected.min(rows.len().saturating_sub(1))).map(|r| (r.index, r.name.clone()));
    let len = rows.len();
    let table = Table::new(
        rows.into_iter().map(|r| {
            Row::new(vec![
                Cell::from(r.name),
                Cell::from(Line::from(rate(r.tx_rate)).right_aligned()),
                Cell::from(Line::from(rate(r.rx_rate)).right_aligned()),
                Cell::from(Line::from(human(r.total as f64)).right_aligned()),
            ])
        }),
        [Constraint::Fill(1), Constraint::Length(12), Constraint::Length(12), Constraint::Length(10)],
    )
    .header(header_row(&["Interface", "↑", "↓", "Total"]));
    render_table(f, app, table, len, list);

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
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), None)).unwrap();
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
            cap.push(Captured::from_event(&ev, cap.mono_to_wall));
        }
        cap.dropped = 7;
        let mut app = App { tab: Tab::Capture, show_graph: false, ..App::default() };
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        let c = Collector::new(30);
        term.draw(|f| draw(f, &mut app, &c, &Names::default(), Some(&cap))).unwrap();
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
    }

    #[test]
    fn graph_hidden_by_toggle_or_small_terminal() {
        assert!(!render(100, 30, false).contains("traffic (excl. lo)"));
        assert!(!render(100, 15, true).contains("traffic (excl. lo)"));
    }
}
