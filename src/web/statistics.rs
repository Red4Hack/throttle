//! `/stats`, laid out like the old site's: counters, crashes per hour and per day,
//! the top crashers (Day / Week / Month / All) with a drill-down by module, function
//! and stack (`/stats/{module}`, `/stats/{module}/{function}`, `/stats/{stack hash}`),
//! the latest crashes and how the processing is doing. Charts are inline SVG made here:
//! no JavaScript (the CSP forbids it) and no charting library.
//!
//! Public, like the old one: everything shown is aggregate or a crash ID, and comes from
//! processed crashes (module and function names, counts). Never an owner or an address.
//!
//! The site-wide charts come from the hourly counters, so they keep their history after
//! the retention deletes old crashes (the old site used RRD files for the same reason),
//! and they count repeats. A filtered chart can only count the crashes still on record.

use std::collections::HashMap;
use std::fmt::Write;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use minijinja::context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use super::session::{MaybeUser, User};
use super::{WebError, format, render};
use crate::app::AppState;
use crate::stats;

const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
const DAYS_SHOWN: i64 = 90;
const HOURS_SHOWN: i64 = 168;
const TOP_ROWS: i64 = 10;
const LATEST_ROWS: i64 = 10;
/// Longest module or function name taken from a URL.
const MAX_NAME: usize = 512;
/// A stack hash is eight hex digits per frame, and ten frames feed it.
const MAX_STACK_HASH: usize = 80;

#[derive(Deserialize)]
pub struct Params {
    scope: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Day,
    Week,
    Month,
    All,
}

impl Scope {
    const ALL: [Scope; 4] = [Scope::Day, Scope::Week, Scope::Month, Scope::All];

    /// All time is the default, as it was on the old site.
    fn parse(s: Option<&str>) -> Self {
        Self::ALL
            .into_iter()
            .find(|c| Some(c.key()) == s)
            .unwrap_or(Scope::All)
    }

    fn key(self) -> &'static str {
        match self {
            Scope::Day => "day",
            Scope::Week => "week",
            Scope::Month => "month",
            Scope::All => "all",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Scope::Day => "Day",
            Scope::Week => "Week",
            Scope::Month => "Month",
            Scope::All => "All",
        }
    }

    /// Unix time the period starts at.
    fn since(self, now: i64) -> i64 {
        match self {
            Scope::Day => now - DAY,
            Scope::Week => now - 7 * DAY,
            Scope::Month => now - 30 * DAY,
            Scope::All => 0,
        }
    }
}

/// What the page is about: everything, one module, one function of it, or one stack.
#[derive(Default)]
struct Filter {
    module: Option<String>,
    function: Option<String>,
    stack: Option<String>,
}

impl Filter {
    fn is_root(&self) -> bool {
        self.module.is_none() && self.function.is_none() && self.stack.is_none()
    }

    /// Below a module, the list is of frames; above, of modules and functions.
    fn by_frame(&self) -> bool {
        self.function.is_some() || self.stack.is_some()
    }

    fn path(&self) -> String {
        match (&self.module, &self.function, &self.stack) {
            (_, _, Some(stack)) => format!("/stats/{}", enc(stack)),
            (Some(module), Some(function), _) => {
                format!("/stats/{}/{}", enc(module), enc(function))
            }
            (Some(module), None, _) => format!("/stats/{}", enc(module)),
            _ => "/stats".into(),
        }
    }
}

/// Percent-encoding for one path segment: a `/` inside a function name must not split it.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NAME && !s.chars().any(char::is_control)
}

fn is_stack_hash(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_STACK_HASH
        && s.len().is_multiple_of(8)
        && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A bar chart as an inline SVG. Every bar has a `<title>` (the tooltip); the
/// styling lives in app.css (`.chart`), because inline styles are blocked.
pub fn bar_chart(title: &str, bars: &[(String, i64)]) -> String {
    bar_chart_sized(title, bars, 720.0, 150.0)
}

fn bar_chart_sized(title: &str, bars: &[(String, i64)], width: f64, height: f64) -> String {
    const LABEL_H: f64 = 16.0;
    const TOP_PAD: f64 = 12.0;

    let max = bars.iter().map(|b| b.1).max().unwrap_or(0).max(1);
    let slot = width / bars.len().max(1) as f64;
    let plot_h = height - LABEL_H - TOP_PAD;
    let base = TOP_PAD + plot_h;
    let label_y = height - 3.0;

    let mut svg = format!(
        "<svg class=\"chart\" viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{}\">",
        esc(title)
    );
    for (i, (label, value)) in bars.iter().enumerate() {
        let h = *value as f64 / max as f64 * plot_h;
        let _ = write!(
            svg,
            "<rect class=\"bar\" x=\"{:.2}\" y=\"{:.2}\" width=\"{:.2}\" height=\"{:.2}\"><title>{}: {}</title></rect>",
            i as f64 * slot + slot * 0.1,
            base - h,
            slot * 0.8,
            h,
            esc(label),
            value
        );
    }
    let _ = write!(
        svg,
        "<line class=\"base\" x1=\"0\" y1=\"{base}\" x2=\"{width}\" y2=\"{base}\"/>"
    );
    let _ = write!(svg, "<text class=\"axis\" x=\"0\" y=\"9\">{max}</text>");
    if let (Some(first), Some(last)) = (bars.first(), bars.last()) {
        let _ = write!(
            svg,
            "<text class=\"axis\" x=\"0\" y=\"{label_y}\">{}</text><text class=\"axis\" x=\"{width}\" y=\"{label_y}\" text-anchor=\"end\">{}</text>",
            esc(&first.0),
            esc(&last.0),
        );
    }
    // A long, wide chart gets its quarters labelled too, so a week of hours can be read.
    if bars.len() >= 8 && width >= 600.0 {
        for quarter in 1..4 {
            let i = bars.len() * quarter / 4;
            let _ = write!(
                svg,
                "<text class=\"axis\" x=\"{:.1}\" y=\"{label_y}\" text-anchor=\"middle\">{}</text>",
                (i as f64 + 0.5) * slot,
                esc(&bars[i].0),
            );
        }
    }
    svg.push_str("</svg>");
    svg
}

/// Crashes in the hourly counter buckets from `since` (a multiple of an hour): the ones
/// accepted and the ones counted as repeats.
async fn counter_hours(db: &SqlitePool, since: i64) -> sqlx::Result<HashMap<i64, i64>> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT bucket, SUM(value) FROM counter \
         WHERE bucket >= ? AND name IN ('crashes:accepted', 'crashes:repeated') GROUP BY bucket",
    )
    .bind(since)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().collect())
}

/// `n` buckets of `step` seconds from `since`, each the sum of the hours in it.
fn bin(hours: &HashMap<i64, i64>, since: i64, step: i64, n: i64) -> Vec<i64> {
    let mut out = vec![0; n as usize];
    for (bucket, value) in hours {
        let offset = bucket - since;
        if offset >= 0
            && let Some(slot) = out.get_mut((offset / step) as usize)
        {
            *slot += value;
        }
    }
    out
}

/// Crashes still on record that match the filter, in `n` buckets of `step` seconds.
async fn filtered_series(
    db: &SqlitePool,
    f: &Filter,
    since: i64,
    step: i64,
    n: i64,
) -> sqlx::Result<Vec<i64>> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT (c.created_at - ?) / ? AS bucket, COUNT(*) FROM crash c \
         WHERE c.created_at >= ? AND c.status = 2 \
           AND (? IS NULL OR c.crash_module = ?) \
           AND (? IS NULL OR c.crash_function = ?) \
           AND (? IS NULL OR c.stackhash = ?) \
         GROUP BY bucket",
    )
    .bind(since)
    .bind(step)
    .bind(since)
    .bind(&f.module)
    .bind(&f.module)
    .bind(&f.function)
    .bind(&f.function)
    .bind(&f.stack)
    .bind(&f.stack)
    .fetch_all(db)
    .await?;
    let by_bucket: HashMap<i64, i64> = rows.into_iter().collect();
    Ok((0..n)
        .map(|i| by_bucket.get(&i).copied().unwrap_or(0))
        .collect())
}

fn labelled(since: i64, step: i64, values: &[i64], width: usize) -> Vec<(String, i64)> {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            (
                format::utc(since + i as i64 * step)[..width].to_string(),
                *v,
            )
        })
        .collect()
}

#[derive(sqlx::FromRow)]
struct RawTop {
    module: Option<String>,
    function: Option<String>,
    crashes: i64,
    servers: i64,
    owners: i64,
}

#[derive(sqlx::FromRow)]
struct RawFrameTop {
    label: String,
    crashes: i64,
    servers: i64,
    owners: i64,
}

#[derive(Serialize)]
struct TopRow {
    rank: usize,
    module: Option<String>,
    function: Option<String>,
    /// A frame as it is on the crash page (when the rows are frames).
    label: Option<String>,
    /// Where the row leads: one level further down.
    href: Option<String>,
    crashes: i64,
    servers: i64,
    owners: i64,
}

/// A module-and-function row. It links to the function (or, on the site-wide list for a
/// function-less row, to the module); inside a module the module itself is not a link.
fn top_row(rank: usize, r: RawTop, in_module: bool) -> TopRow {
    let module = r.module.filter(|m| !m.is_empty());
    let function = r.function.filter(|f| !f.is_empty());
    let href = match (&module, &function) {
        (Some(m), Some(f)) => Some(format!("/stats/{}/{}", enc(m), enc(f))),
        (Some(m), None) if !in_module => Some(format!("/stats/{}", enc(m))),
        _ => None,
    };
    TopRow {
        rank,
        module,
        function,
        label: None,
        href,
        crashes: r.crashes,
        servers: r.servers,
        owners: r.owners,
    }
}

async fn top_rows(db: &SqlitePool, f: &Filter, since: i64) -> sqlx::Result<Vec<TopRow>> {
    if !f.by_frame() {
        let rows: Vec<RawTop> = sqlx::query_as(
            "SELECT crash_module AS module, crash_function AS function, \
                    COUNT(*) + COALESCE(SUM(repeats), 0) AS crashes, \
                    COUNT(DISTINCT ip) AS servers, COUNT(DISTINCT owner) AS owners \
             FROM crash WHERE status = 2 AND created_at >= ? AND (? IS NULL OR crash_module = ?) \
             GROUP BY crash_module, crash_function \
             ORDER BY crashes DESC, crash_module, crash_function LIMIT ?",
        )
        .bind(since)
        .bind(&f.module)
        .bind(&f.module)
        .bind(TOP_ROWS)
        .fetch_all(db)
        .await?;
        let in_module = f.module.is_some();
        return Ok(rows
            .into_iter()
            .enumerate()
            .map(|(i, r)| top_row(i + 1, r, in_module))
            .collect());
    }

    // The first frame of the crashing thread (the second after a bad jump), as rendered.
    let rows: Vec<RawFrameTop> = sqlx::query_as(
        "SELECT f.rendered AS label, COUNT(*) + COALESCE(SUM(c.repeats), 0) AS crashes, \
                COUNT(DISTINCT c.ip) AS servers, COUNT(DISTINCT c.owner) AS owners \
         FROM crash c JOIN frame f ON f.crash = c.id AND f.thread = c.thread AND f.frame = c.bad_jump \
         WHERE c.status = 2 AND c.created_at >= ? \
           AND (? IS NULL OR c.crash_module = ?) \
           AND (? IS NULL OR c.crash_function = ?) \
           AND (? IS NULL OR c.stackhash = ?) \
         GROUP BY f.rendered ORDER BY crashes DESC, f.rendered LIMIT ?",
    )
    .bind(since)
    .bind(&f.module)
    .bind(&f.module)
    .bind(&f.function)
    .bind(&f.function)
    .bind(&f.stack)
    .bind(&f.stack)
    .bind(TOP_ROWS)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| TopRow {
            rank: i + 1,
            module: None,
            function: None,
            label: Some(r.label),
            href: None,
            crashes: r.crashes,
            servers: r.servers,
            owners: r.owners,
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct RawLatest {
    id: String,
    created_at: i64,
    repeats: i64,
    rendered: String,
    cmdline: Option<String>,
}

#[derive(Serialize)]
struct Latest {
    id: String,
    created_at: i64,
    repeats: i64,
    rendered: String,
    /// A short hash of the server's command line, for its identicon. The command line
    /// itself never leaves the database.
    server: Option<String>,
}

async fn latest_rows(db: &SqlitePool, f: &Filter) -> sqlx::Result<Vec<Latest>> {
    let rows: Vec<RawLatest> = sqlx::query_as(
        "SELECT c.id, c.created_at, c.repeats, f.rendered, c.cmdline \
         FROM crash c JOIN frame f ON f.crash = c.id AND f.thread = c.thread AND f.frame = c.bad_jump \
         WHERE c.status = 2 \
           AND (? IS NULL OR c.crash_module = ?) \
           AND (? IS NULL OR c.crash_function = ?) \
           AND (? IS NULL OR c.stackhash = ?) \
         ORDER BY c.created_at DESC, c.id DESC LIMIT ?",
    )
    .bind(&f.module)
    .bind(&f.module)
    .bind(&f.function)
    .bind(&f.function)
    .bind(&f.stack)
    .bind(&f.stack)
    .bind(LATEST_ROWS)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Latest {
            server: r
                .cmdline
                .filter(|c| !c.is_empty())
                .map(|c| hex::encode(&Sha256::digest(c.as_bytes())[..8])),
            id: r.id,
            created_at: r.created_at,
            repeats: r.repeats,
            rendered: r.rendered,
        })
        .collect())
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Line,
    Stack,
    /// Stacked, each column scaled to 100%.
    Share,
    /// Stacked, fixed 0-100 axis.
    Percent,
}

#[derive(Clone)]
struct Series {
    label: &'static str,
    class: &'static str,
    values: Vec<Option<f64>>,
}

#[derive(Serialize)]
struct LegendRow {
    label: &'static str,
    class: &'static str,
    cur: String,
    min: String,
    avg: String,
    max: String,
}

#[derive(Serialize)]
struct Chart {
    title: &'static str,
    svg: String,
    legend: Vec<LegendRow>,
}

/// The site-wide numbers: only the unfiltered page has them.
#[derive(Serialize)]
struct Overview {
    servers: i64,
    on_record: i64,
    last_day: i64,
    charts: Vec<Chart>,
}

fn nice_max(m: f64) -> f64 {
    if m <= 0.0 {
        return 1.0;
    }
    let mag = 10f64.powf(m.log10().floor());
    [1.0, 2.0, 2.5, 5.0, 10.0]
        .iter()
        .map(|f| f * mag)
        .find(|v| *v >= m)
        .unwrap_or(10.0 * mag)
}

fn num(v: f64) -> String {
    format!("{v:.2}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

/// A multi-series line or stacked-area chart with a Cur/Min/Avg/Max legend, like the old
/// site's RRD graphs. Colours come from CSS classes (inline styles are blocked).
fn perf_chart(
    title: &'static str,
    y_label: &'static str,
    mode: Mode,
    series: Vec<Series>,
    ticks: &[(usize, String)],
) -> Chart {
    const W: f64 = 400.0;
    const H: f64 = 190.0;
    const X0: f64 = 34.0;
    const X1: f64 = 394.0;
    const Y0: f64 = 8.0;
    const Y1: f64 = 160.0;

    let n = series.first().map_or(0, |s| s.values.len());
    let mut plot: Vec<Vec<f64>> = series
        .iter()
        .map(|s| s.values.iter().map(|v| v.unwrap_or(0.0)).collect())
        .collect();
    let mut shown: Vec<Vec<Option<f64>>> = series.iter().map(|s| s.values.clone()).collect();
    if mode == Mode::Share {
        for i in 0..n {
            let total: f64 = plot.iter().map(|p| p[i]).sum();
            for k in 0..plot.len() {
                if total > 0.0 {
                    plot[k][i] = plot[k][i] / total * 100.0;
                    shown[k][i] = Some(plot[k][i]);
                } else {
                    plot[k][i] = 0.0;
                    shown[k][i] = None;
                }
            }
        }
    }
    let stacked = mode != Mode::Line;
    let top = match mode {
        Mode::Share | Mode::Percent => 100.0,
        Mode::Stack => nice_max(
            (0..n)
                .map(|i| plot.iter().map(|p| p[i]).sum::<f64>())
                .fold(0.0, f64::max),
        ),
        Mode::Line => nice_max(plot.iter().flatten().copied().fold(0.0, f64::max)),
    };
    let x = |i: usize| X0 + (X1 - X0) * i as f64 / (n.max(2) - 1) as f64;
    let y = |v: f64| Y1 - (Y1 - Y0) * (v / top).clamp(0.0, 1.0);

    let mut svg = format!(
        "<svg class=\"chart perf\" viewBox=\"0 0 {W} {H}\" role=\"img\" aria-label=\"{}\">",
        esc(title)
    );
    for g in 0..=5 {
        let v = top * f64::from(g) / 5.0;
        let _ = write!(
            svg,
            "<line class=\"grid\" x1=\"{X0}\" y1=\"{yy:.1}\" x2=\"{X1}\" y2=\"{yy:.1}\"/><text class=\"axis\" x=\"{}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>",
            X0 - 3.0,
            y(v) + 2.5,
            num(v),
            yy = y(v),
        );
    }
    for (i, label) in ticks {
        let _ = write!(
            svg,
            "<line class=\"grid\" x1=\"{xx:.1}\" y1=\"{Y0}\" x2=\"{xx:.1}\" y2=\"{Y1}\"/><text class=\"axis\" x=\"{xx:.1}\" y=\"172\" text-anchor=\"middle\">{}</text>",
            esc(label),
            xx = x(*i),
        );
    }
    let _ = write!(
        svg,
        "<text class=\"axis\" transform=\"rotate(-90)\" x=\"-84\" y=\"7\" text-anchor=\"middle\">{}</text>",
        esc(y_label)
    );

    let mut below = vec![0.0; n];
    for (k, s) in series.iter().enumerate() {
        let mut d = String::new();
        if stacked {
            let upper: Vec<f64> = (0..n).map(|i| below[i] + plot[k][i]).collect();
            for (i, v) in upper.iter().enumerate() {
                let _ = write!(d, "{}{:.1} {:.1}", if i == 0 { "M" } else { "L" }, x(i), y(*v));
            }
            for (i, v) in below.iter().enumerate().rev() {
                let _ = write!(d, "L{:.1} {:.1}", x(i), y(*v));
            }
            d.push('Z');
            let _ = write!(svg, "<path class=\"area {}\" d=\"{d}\"/>", s.class);
            below = upper;
        } else {
            let mut pen = false;
            for (i, v) in s.values.iter().enumerate() {
                match v {
                    Some(v) => {
                        let _ = write!(d, "{}{:.1} {:.1}", if pen { "L" } else { "M" }, x(i), y(*v));
                        pen = true;
                    }
                    None => pen = false,
                }
            }
            let _ = write!(svg, "<path class=\"line {}\" d=\"{d}\"/>", s.class);
        }
    }
    svg.push_str("</svg>");

    let legend = series
        .iter()
        .zip(&shown)
        .map(|(s, vals)| {
            let some: Vec<f64> = vals.iter().flatten().copied().collect();
            let f = |v: Option<f64>| v.map_or("-".to_string(), |v| format!("{v:.2}"));
            LegendRow {
                label: s.label,
                class: s.class,
                cur: f(vals.iter().rev().find_map(|v| *v)),
                min: f(some.iter().copied().reduce(f64::min)),
                avg: f((!some.is_empty()).then(|| some.iter().sum::<f64>() / some.len() as f64)),
                max: f(some.iter().copied().reduce(f64::max)),
            }
        })
        .collect();
    Chart { title, svg, legend }
}

/// Sum of the counters `names` in `n` buckets of `step` seconds from `since`.
fn per_bucket(
    rows: &[(i64, String, i64)],
    since: i64,
    step: i64,
    n: usize,
    names: &[&str],
) -> Vec<i64> {
    let mut out = vec![0; n];
    for r in rows.iter().filter(|r| names.contains(&r.1.as_str())) {
        let offset = r.0 - since;
        if offset >= 0
            && let Some(slot) = out.get_mut((offset / step) as usize)
        {
            *slot += r.2;
        }
    }
    out
}

/// Per-minute rate of each bucket; the one still running is divided by the time elapsed.
fn rates(vals: &[i64], since: i64, step: i64, now: i64) -> Vec<Option<f64>> {
    vals.iter()
        .enumerate()
        .map(|(i, v)| {
            let span = (now - (since + i as i64 * step)).clamp(60, step) as f64 / 60.0;
            Some(*v as f64 / span)
        })
        .collect()
}

/// Share of the symbol lookups that found a file, per bucket (none when nothing was looked up).
fn coverage(rows: &[(i64, String, i64)], since: i64, step: i64, n: usize) -> Vec<Option<f64>> {
    let hit = per_bucket(
        rows,
        since,
        step,
        n,
        &[
            "symbols:lookup:cached",
            "symbols:lookup:found",
            "symbols:lookup:compressed",
        ],
    );
    let miss = per_bucket(rows, since, step, n, &["symbols:lookup:missing"]);
    (0..n)
        .map(|i| {
            let total = hit[i] + miss[i];
            (total > 0).then(|| hit[i] as f64 * 100.0 / total as f64)
        })
        .collect()
}

fn ticks(
    since: i64,
    step: i64,
    n: usize,
    pick: impl Fn(&str) -> Option<String>,
) -> Vec<(usize, String)> {
    (0..n)
        .filter_map(|i| pick(&format::utc(since + i as i64 * step)).map(|l| (i, l)))
        .collect()
}

fn tail(series: &[Series], n: usize) -> Vec<Series> {
    series
        .iter()
        .map(|s| Series {
            values: s.values[s.values.len() - n..].to_vec(),
            ..s.clone()
        })
        .collect()
}

async fn overview(db: &SqlitePool, now: i64, hourly: &[i64]) -> sqlx::Result<Overview> {
    // How many servers crashed lately: told apart by their id, or their command line.
    let servers: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT COALESCE(server_id, cmdline, hex(ip))) FROM crash WHERE created_at >= ?",
    )
    .bind(now - DAY)
    .fetch_one(db)
    .await?;
    let on_record: i64 =
        sqlx::query_scalar("SELECT COUNT(*) + COALESCE(SUM(repeats), 0) FROM crash")
            .fetch_one(db)
            .await?;
    let last_day = hourly.iter().rev().take(24).sum();

    let n = HOURS_SHOWN as usize;
    let hour_since = (now / HOUR - (HOURS_SHOWN - 1)) * HOUR;
    let day_since = hour_since + (HOURS_SHOWN - 24) * HOUR;
    let rows: Vec<(i64, String, i64)> =
        sqlx::query_as("SELECT bucket, name, value FROM counter WHERE bucket >= ?")
            .bind(hour_since)
            .fetch_all(db)
            .await?;
    let years = 365;
    let year_since = (now / DAY - (years - 1)) * DAY;
    let year_rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT bucket, name, value FROM counter WHERE bucket >= ? AND name LIKE 'symbols:lookup:%'",
    )
    .bind(year_since)
    .fetch_all(db)
    .await?;

    let wk = |names: &[&str]| per_bucket(&rows, hour_since, HOUR, n, names);
    let rate = |names: &[&str]| rates(&wk(names), hour_since, HOUR, now);
    let series = |spec: &[(&'static str, &'static str, &[&str])]| -> Vec<Series> {
        spec.iter()
            .map(|(label, class, names)| Series {
                label,
                class,
                values: rate(names),
            })
            .collect()
    };

    let hour_pick = |t: &str| {
        t[11..13]
            .parse::<u32>()
            .ok()
            .filter(|h| h % 6 == 0)
            .map(|_| t[11..16].to_string())
    };
    let midnight_pick = |t: &str| (&t[11..13] == "00").then(|| t[5..10].to_string());
    let quarter_pick = |t: &str| {
        (&t[8..10] == "01" && matches!(&t[5..7], "01" | "04" | "07" | "10"))
            .then(|| t[..7].to_string())
    };
    let day_ticks = ticks(day_since, HOUR, 24, hour_pick);
    let week_ticks = ticks(hour_since, HOUR, n, midnight_pick);
    let year_ticks = ticks(year_since, DAY, years as usize, quarter_pick);

    let submitted = series(&[
        ("accepted", "c-green", &["crashes:accepted"]),
        ("rejected: no minidump", "c-blue", &["crashes:rejected:no-minidump"]),
        ("rejected: no steam", "c-orange", &["crashes:rejected:no-steam"]),
        ("rejected: rate limited", "c-yellow", &["crashes:rejected:rate-limit"]),
        ("rejected: disk full", "c-red", &["crashes:rejected:no-space"]),
        ("presubmitted", "c-purple", &["crashes:presubmitted"]),
        ("submitted", "c-black", &["crashes:submitted"]),
    ]);
    let processed = series(&[
        ("failed", "c-orange", &["crashes:failed"]),
        ("processed", "c-green", &["crashes:processed"]),
        ("marked for reprocessing", "c-blue", &["crashes:needs-reprocessing"]),
    ]);
    let cleaned = series(&[
        ("reached user limit", "c-green", &["cleaned:user-limit"]),
        ("reached age limit", "c-blue", &["cleaned:age"]),
        ("reached disk quota", "c-orange", &["cleaned:quota"]),
        ("orphaned minidumps", "c-black", &["cleaned:orphans"]),
    ]);

    let counts = wk(&["processing:count"]);
    let totals = wk(&["processing:millis"]);
    let mins = wk(&["processing:min-ms"]);
    let maxs = wk(&["processing:max-ms"]);
    let secs = |f: &dyn Fn(usize) -> f64| -> Vec<Option<f64>> {
        (0..n)
            .map(|i| (counts[i] > 0).then(|| f(i) / 1000.0))
            .collect()
    };
    let duration = vec![
        Series {
            label: "min",
            class: "c-green",
            values: secs(&|i| mins[i] as f64),
        },
        Series {
            label: "average",
            class: "c-blue",
            values: secs(&|i| totals[i] as f64 / counts[i] as f64),
        },
        Series {
            label: "max",
            class: "c-orange",
            values: secs(&|i| maxs[i] as f64),
        },
    ];

    let lookups: Vec<Series> = [
        ("missing", "c-orange", "symbols:lookup:missing"),
        ("found compressed", "c-green", "symbols:lookup:compressed"),
        ("found", "c-blue", "symbols:lookup:found"),
        ("found cached", "c-purple", "symbols:lookup:cached"),
    ]
    .iter()
    .map(|(label, class, name)| Series {
        label,
        class,
        values: wk(&[name]).iter().map(|v| Some(*v as f64)).collect(),
    })
    .collect();
    let found = |values| {
        vec![Series {
            label: "found",
            class: "c-green",
            values,
        }]
    };

    let per_min = "crashes per minute";
    let charts = vec![
        perf_chart("Crashes submitted - by day", per_min, Mode::Line, tail(&submitted, 24), &day_ticks),
        perf_chart("Crashes submitted - by week", per_min, Mode::Line, submitted, &week_ticks),
        perf_chart("Crashes processed - by week", per_min, Mode::Stack, processed, &week_ticks),
        perf_chart("Processing duration - by week", "duration (seconds)", Mode::Line, duration, &week_ticks),
        perf_chart("Crashes cleaned - by week", per_min, Mode::Stack, cleaned, &week_ticks),
        perf_chart("Symbol lookups % - by week", "% lookups", Mode::Share, lookups, &week_ticks),
        perf_chart(
            "Symbol coverage % - by week",
            "% coverage",
            Mode::Percent,
            found(coverage(&rows, hour_since, HOUR, n)),
            &week_ticks,
        ),
        perf_chart(
            "Symbol coverage % - by year",
            "% coverage",
            Mode::Percent,
            found(coverage(&year_rows, year_since, DAY, years as usize)),
            &year_ticks,
        ),
    ];

    Ok(Overview {
        servers,
        on_record,
        last_day,
        charts,
    })
}

#[derive(Serialize)]
struct ScopeLink {
    label: &'static str,
    href: String,
    active: bool,
}

#[derive(Serialize)]
struct Crumb {
    label: String,
    href: Option<String>,
}

fn crumbs(f: &Filter) -> Vec<Crumb> {
    let mut out = vec![Crumb {
        label: "Stats".into(),
        href: Some("/stats".into()),
    }];
    if let Some(module) = &f.module {
        out.push(Crumb {
            label: module.clone(),
            href: f
                .function
                .is_some()
                .then(|| format!("/stats/{}", enc(module))),
        });
    }
    if let Some(function) = &f.function {
        out.push(Crumb {
            label: function.clone(),
            href: None,
        });
    }
    if let Some(stack) = &f.stack {
        out.push(Crumb {
            label: stack.clone(),
            href: None,
        });
    }
    out
}

async fn page(
    state: AppState,
    user: Option<User>,
    params: Params,
    filter: Filter,
) -> Result<Response, WebError> {
    let db = &state.db;
    let now = stats::now();
    let scope = Scope::parse(params.scope.as_deref());
    let root = filter.is_root();

    let day_since = (now / DAY - (DAYS_SHOWN - 1)) * DAY;
    let hour_since = (now / HOUR - (HOURS_SHOWN - 1)) * HOUR;
    let (daily, hourly) = if root {
        let hours = counter_hours(db, day_since).await?;
        (
            bin(&hours, day_since, DAY, DAYS_SHOWN),
            bin(&hours, hour_since, HOUR, HOURS_SHOWN),
        )
    } else {
        (
            filtered_series(db, &filter, day_since, DAY, DAYS_SHOWN).await?,
            filtered_series(db, &filter, hour_since, HOUR, HOURS_SHOWN).await?,
        )
    };

    let overview = if root {
        Some(overview(db, now, &hourly).await?)
    } else {
        None
    };
    let top = top_rows(db, &filter, scope.since(now)).await?;
    let latest = latest_rows(db, &filter).await?;

    let base = filter.path();
    let scopes: Vec<ScopeLink> = Scope::ALL
        .into_iter()
        .map(|s| ScopeLink {
            label: s.label(),
            href: format!("{base}?scope={}", s.key()),
            active: s == scope,
        })
        .collect();

    let html = render(
        &state,
        "stats.html",
        user.as_ref(),
        context! {
            filtered => !root,
            crumbs => crumbs(&filter),
            overview => overview,
            hourly => bar_chart("Crashes per hour", &labelled(hour_since, HOUR, &hourly, 16)),
            daily => bar_chart("Crashes per day", &labelled(day_since, DAY, &daily, 10)),
            scopes => scopes,
            top => top,
            latest => latest,
        },
    )?;

    let mut res = html.into_response();
    // The page is the same for everybody except the header, so only the browser may cache it.
    res.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=60"),
    );
    Ok(res)
}

pub async fn stats_page(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Query(params): Query<Params>,
) -> Result<Response, WebError> {
    page(state, user, params, Filter::default()).await
}

/// `/stats/{module}`; or `/stats/{stack hash}`, which looks like eight-digit hex groups.
pub async fn stats_module(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(module): Path<String>,
    Query(params): Query<Params>,
) -> Result<Response, WebError> {
    let filter = if is_stack_hash(&module) {
        Filter {
            stack: Some(module),
            ..Filter::default()
        }
    } else if valid_name(&module) {
        Filter {
            module: Some(module),
            ..Filter::default()
        }
    } else {
        return Err(WebError::NotFound);
    };
    page(state, user, params, filter).await
}

pub async fn stats_function(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path((module, function)): Path<(String, String)>,
    Query(params): Query<Params>,
) -> Result<Response, WebError> {
    if !valid_name(&module) || !valid_name(&function) {
        return Err(WebError::NotFound);
    }
    let filter = Filter {
        module: Some(module),
        function: Some(function),
        stack: None,
    };
    page(state, user, params, filter).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perf_chart_scales_and_summarises() {
        let s = vec![Series {
            label: "a",
            class: "c-green",
            values: vec![Some(1.0), Some(3.0), None],
        }];
        let c = perf_chart("t", "y", Mode::Line, s, &[]);
        let l = &c.legend[0];
        assert_eq!((l.min.as_str(), l.max.as_str(), l.cur.as_str()), ("1.00", "3.00", "3.00"));
        assert!(c.svg.starts_with("<svg") && c.svg.ends_with("</svg>"));
    }

    fn bars(values: &[i64]) -> Vec<(String, i64)> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("day {i}"), *v))
            .collect()
    }

    #[test]
    fn one_bar_per_value_scaled_to_the_maximum() {
        let svg = bar_chart("Crashes", &bars(&[0, 5, 10]));
        assert_eq!(svg.matches("<rect").count(), 3);
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        // The tallest bar fills the plot area (150 - 16 - 12), the half one is half as tall, zero has none.
        assert!(svg.contains("height=\"122.00\""));
        assert!(svg.contains("height=\"61.00\""));
        assert!(svg.contains("height=\"0.00\""));
        assert!(svg.contains("<title>day 2: 10</title>"));
        assert!(svg.contains(">10</text>"), "the axis shows the maximum");
    }

    #[test]
    fn empty_and_all_zero_charts_are_still_valid() {
        let svg = bar_chart("Nothing", &[]);
        assert_eq!(svg.matches("<rect").count(), 0);
        assert!(svg.ends_with("</svg>"));
        let svg = bar_chart("Zeros", &bars(&[0, 0]));
        assert_eq!(svg.matches("height=\"0.00\"").count(), 2);
        assert!(!svg.contains("NaN") && !svg.contains("inf"));
    }

    #[test]
    fn text_is_escaped() {
        let svg = bar_chart("a\"b<c", &[("<img onerror=x>".into(), 1)]);
        assert!(!svg.contains("<img") && !svg.contains("b<c"));
        assert!(svg.contains("&lt;img onerror=x&gt;") && svg.contains("a&quot;b&lt;c"));
    }

    #[test]
    fn a_long_wide_chart_labels_its_quarters() {
        let labels = |svg: &str| svg.matches("class=\"axis\"").count();
        // The maximum, the first and the last, and three in between.
        assert_eq!(labels(&bar_chart("c", &bars(&[1; 8]))), 1 + 2 + 3);
        assert_eq!(labels(&bar_chart("c", &bars(&[1, 2, 3]))), 1 + 2);
        // A narrow chart has no room for them.
        assert_eq!(
            labels(&bar_chart_sized("c", &bars(&[1; 8]), 480.0, 130.0)),
            1 + 2
        );
    }

    #[test]
    fn scopes_parse_with_a_safe_default() {
        assert!(Scope::parse(Some("day")) == Scope::Day);
        assert!(Scope::parse(Some("week")) == Scope::Week);
        for odd in [
            None,
            Some(""),
            Some("year"),
            Some("DAY"),
            Some("week; DROP TABLE crash"),
        ] {
            assert!(Scope::parse(odd) == Scope::All, "{odd:?}");
        }
        assert_eq!(Scope::All.since(1000), 0);
        assert_eq!(Scope::Day.since(100_000), 100_000 - DAY);
    }

    #[test]
    fn names_are_percent_encoded_for_one_path_segment() {
        assert_eq!(enc("server_srv.so"), "server_srv.so");
        assert_eq!(
            enc("Foo::bar(int/char*) 100%"),
            "Foo%3A%3Abar%28int%2Fchar%2A%29%20100%25"
        );
        assert_eq!(enc("ü"), "%C3%BC");
    }

    #[test]
    fn stack_hashes_and_names_are_told_apart() {
        assert!(is_stack_hash("abcd1234"));
        assert!(is_stack_hash(&"ab".repeat(40)));
        for bad in [
            "",
            "abcd123",
            "ABCD1234",
            "abcd123g",
            "mod_a",
            &"abcd1234".repeat(11),
        ] {
            assert!(!is_stack_hash(bad), "{bad:?}");
        }
        assert!(valid_name("server_srv.so"));
        assert!(!valid_name("") && !valid_name("a\0b") && !valid_name("a\nb"));
        assert!(!valid_name(&"x".repeat(MAX_NAME + 1)));
    }

    #[test]
    fn counter_buckets_fall_into_hours_and_days() {
        let hours: HashMap<i64, i64> = [(0, 1), (3600, 2), (86_400, 4), (-3600, 100), (3 * 86_400, 8)]
            .into_iter()
            .collect();
        // Before the start and after the last bucket do not count.
        assert_eq!(bin(&hours, 0, 86_400, 2), [3, 4]);
        assert_eq!(bin(&hours, 0, 3600, 3), [1, 2, 0]);
    }

    #[test]
    fn rows_link_down_one_level_at_a_time() {
        let raw = |m: Option<&str>, f: Option<&str>| RawTop {
            module: m.map(Into::into),
            function: f.map(Into::into),
            crashes: 1,
            servers: 1,
            owners: 1,
        };
        let href = |m, f, in_module| top_row(1, raw(m, f), in_module).href;

        assert_eq!(
            href(Some("a.so"), Some("f(int)"), false).as_deref(),
            Some("/stats/a.so/f%28int%29")
        );
        // A row without a function leads to its module, but inside the module it is the module.
        assert_eq!(href(Some("a.so"), None, false).as_deref(), Some("/stats/a.so"));
        assert_eq!(href(Some("a.so"), None, true), None);
        assert_eq!(
            href(Some("a.so"), Some("f"), true).as_deref(),
            Some("/stats/a.so/f")
        );
        // Nothing is known about it: nothing to lead to. Empty names are absent names.
        assert_eq!(href(None, None, false), None);
        let row = top_row(3, raw(Some(""), Some("")), false);
        assert!(row.module.is_none() && row.function.is_none() && row.rank == 3);
    }
}
