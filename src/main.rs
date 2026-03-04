use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead, BufReader};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL},
    Engine,
};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use rand::rngs::OsRng;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline, Wrap};
use ratatui::Terminal;
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tungstenite::client::{uri_mode, IntoClientRequest};
use tungstenite::error::{Error as WsError, UrlError};
use tungstenite::handshake::client::Response as WsResponse;
use tungstenite::stream::{MaybeTlsStream, Mode};
use tungstenite::http::header::{HeaderName, AUTHORIZATION};
use tungstenite::{client_tls_with_config, connect, Connector, HandshakeError, Message, WebSocket};
use url::Url;
use uuid::Uuid;

const NEON: Color = Color::Rgb(0, 255, 140);
const NEON_HOT: Color = Color::Rgb(0, 255, 200);
const DIM: Color = Color::Rgb(0, 120, 60);
const ALERT: Color = Color::Rgb(255, 64, 64);
const BG: Color = Color::Black;
const PULSE_HISTORY_LEN: usize = 120;
const PULSE_SAMPLE_MIN_MS: u64 = 50;

#[derive(Parser, Debug)]
#[command(name = "openclaw-visualizer", version, about = "OpenClaw gateway cyberpunk visualizer")]
struct Args {
    /// WebSocket gateway URL, e.g. ws://127.0.0.1:9001
    #[arg(long)]
    gateway: Option<String>,

    /// Auth token for the gateway (if required)
    #[arg(long)]
    token: Option<String>,

    /// Allow invalid TLS certificates (self-signed)
    #[arg(long)]
    insecure_tls: bool,

    /// Echo connection status to stderr (useful for debugging)
    #[arg(long)]
    debug: bool,

    /// Read newline-delimited events from stdin instead of WebSocket
    #[arg(long)]
    stdin: bool,

    /// Run in demo mode with synthetic traffic
    #[arg(long)]
    demo: bool,
}

#[derive(Debug, Clone)]
struct GatewayEvent {
    at: Instant,
    raw: String,
    event_type: String,
    status: String,
}

#[derive(Debug)]
enum GatewayMessage {
    Line(String),
    Status(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceIdentity {
    private_key: String,
    public_key: String,
}

#[derive(Debug, Clone)]
struct AgentState {
    status: String,
    last_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    show_all_messages: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            show_all_messages: false,
        }
    }
}

struct App {
    start: Instant,
    last_tick: Instant,
    last_event_at: Option<Instant>,
    total: u64,
    errors: u64,
    unique_devices: HashSet<String>,
    types: HashMap<String, u64>,
    recent: VecDeque<GatewayEvent>,
    transcript: VecDeque<String>,
    status: String,
    connection: String,
    pulse_history: VecDeque<u64>,
    last_pulse_sample: Instant,
    last_latency_ms: Option<f64>,
    last_line: String,
    throughput_window: VecDeque<Instant>,
    token_window: VecDeque<(Instant, usize)>,
    tokens_per_sec: u64,
    total_tokens: u64,
    gateway_health_ok: Option<bool>,
    gateway_health_at: Option<Instant>,
    gateway_health_note: String,
    agent_statuses: HashMap<String, AgentState>,
    stream_cache: HashMap<String, String>,
    show_all_messages: bool,
    settings_path: PathBuf,
    last_display_was_json_line: bool,
    paused: bool,
}

impl App {
    fn new(connection: String, settings_path: PathBuf, settings: Settings) -> Self {
        Self {
            start: Instant::now(),
            last_tick: Instant::now(),
            last_event_at: None,
            total: 0,
            errors: 0,
            unique_devices: HashSet::new(),
            types: HashMap::new(),
            recent: VecDeque::with_capacity(200),
            transcript: VecDeque::with_capacity(2000),
            status: "Awaiting telemetry...".to_string(),
            connection,
            pulse_history: VecDeque::from(vec![0; PULSE_HISTORY_LEN]),
            last_pulse_sample: Instant::now(),
            last_latency_ms: None,
            last_line: String::new(),
            throughput_window: VecDeque::with_capacity(512),
            token_window: VecDeque::with_capacity(512),
            tokens_per_sec: 0,
            total_tokens: 0,
            gateway_health_ok: None,
            gateway_health_at: None,
            gateway_health_note: String::new(),
            agent_statuses: HashMap::new(),
            stream_cache: HashMap::new(),
            show_all_messages: settings.show_all_messages,
            settings_path,
            last_display_was_json_line: false,
            paused: false,
        }
    }

    fn ingest_line(&mut self, line: String) {
        if self.paused {
            return;
        }

        let now = Instant::now();
        let mut event_type = "raw".to_string();
        let mut status = "ok".to_string();
        let mut device_id: Option<String> = None;
        let mut latency_ms: Option<f64> = None;

        let mut display_text: Option<String> = None;
        let mut display_is_stream = false;
        let mut is_json_line = false;

        if let Ok(value) = serde_json::from_str::<Value>(&line) {
            is_json_line = true;
            self.ingest_system_events(&value);
            if let Some(text) = extract_display_text(&value, &mut self.stream_cache) {
                display_text = Some(text);
                display_is_stream = true;
            } else if self.show_all_messages {
                let event = value.get("event").and_then(|v| v.as_str());
                if event != Some("chat") {
                    display_text = Some(line.clone());
                }
            }
            if let Some(val) = value.get("type").and_then(|v| v.as_str()) {
                event_type = val.to_string();
            } else if let Some(val) = value.get("event").and_then(|v| v.as_str()) {
                event_type = val.to_string();
            }

            if let Some(val) = value.get("status").and_then(|v| v.as_str()) {
                status = val.to_string();
            } else if let Some(val) = value.get("level").and_then(|v| v.as_str()) {
                status = val.to_string();
            }

            if let Some(val) = value.get("device_id").and_then(|v| v.as_str()) {
                device_id = Some(val.to_string());
            } else if let Some(val) = value.get("device").and_then(|v| v.as_str()) {
                device_id = Some(val.to_string());
            }

            if let Some(val) = value.get("latency_ms").and_then(|v| v.as_f64()) {
                latency_ms = Some(val);
            } else if let Some(val) = value.get("latency").and_then(|v| v.as_f64()) {
                latency_ms = Some(val);
            }
        } else {
            let lower = line.to_lowercase();
            if lower.contains("error") || lower.contains("fail") || lower.contains("critical") {
                status = "error".to_string();
            }
            if lower.contains("telemetry") {
                event_type = "telemetry".to_string();
            }
            if self.show_all_messages {
                display_text = Some(line.clone());
            }
        }

        if let Some(device) = device_id {
            self.unique_devices.insert(device);
        }
        if let Some(latency) = latency_ms {
            self.last_latency_ms = Some(latency);
        }

        *self.types.entry(event_type.clone()).or_insert(0) += 1;
        if status.contains("err") || status.contains("fail") || status.contains("crit") {
            self.errors += 1;
        }

        self.total += 1;
        self.last_event_at = Some(now);
        self.throughput_window.push_back(now);
        self.record_pulse(now, false);
        if let Some(text) = display_text {
            if !text.is_empty() {
                if self.show_all_messages && !display_is_stream {
                    let gap_before = self.last_display_was_json_line && is_json_line;
                    self.append_transcript_line(&text, now, gap_before);
                    self.last_display_was_json_line = is_json_line;
                } else {
                    self.append_transcript(&text, now);
                    self.last_display_was_json_line = false;
                }
                if let Some(last) = self.transcript.back() {
                    self.last_line = last.clone();
                }
            }
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        self.throughput_window
            .retain(|instant| now.duration_since(*instant) <= Duration::from_secs(1));
        self.token_window
            .retain(|(instant, _)| now.duration_since(*instant) <= Duration::from_secs(5));
        let token_sum: u64 = self
            .token_window
            .iter()
            .map(|(_, count)| *count as u64)
            .sum();
        self.tokens_per_sec = (token_sum + 2) / 5;
        self.record_pulse(now, true);
        self.last_tick = now;
    }

    fn append_transcript(&mut self, text: &str, at: Instant) {
        let tokens = estimate_tokens(text);
        if tokens > 0 {
            self.token_window.push_back((at, tokens));
            self.total_tokens = self.total_tokens.saturating_add(tokens as u64);
        }
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        if self.transcript.is_empty() {
            self.transcript.push_back(String::new());
        }
        let mut remaining = normalized.as_str();
        while let Some(pos) = remaining.find('\n') {
            let (head, tail) = remaining.split_at(pos);
            if let Some(last) = self.transcript.back_mut() {
                last.push_str(head);
            }
            self.transcript.push_back(String::new());
            remaining = &tail[1..];
        }
        if let Some(last) = self.transcript.back_mut() {
            last.push_str(remaining);
        }
        while self.transcript.len() > 2000 {
            self.transcript.pop_front();
        }
    }

    fn append_transcript_line(&mut self, line: &str, at: Instant, gap_before: bool) {
        let tokens = estimate_tokens(line);
        if tokens > 0 {
            self.token_window.push_back((at, tokens));
            self.total_tokens = self.total_tokens.saturating_add(tokens as u64);
        }
        let want_gap = gap_before && !self.transcript.is_empty();
        if self.transcript.is_empty() {
            self.transcript.push_back(String::new());
        }
        if want_gap {
            if let Some(last) = self.transcript.back() {
                if !last.is_empty() {
                    self.transcript.push_back(String::new());
                }
            }
            if let Some(last) = self.transcript.back() {
                if last.is_empty() {
                    self.transcript.push_back(String::new());
                }
            }
        } else if let Some(last) = self.transcript.back() {
            if !last.is_empty() {
                self.transcript.push_back(String::new());
            }
        }
        if let Some(last) = self.transcript.back_mut() {
            last.push_str(line);
        }
        self.transcript.push_back(String::new());
        while self.transcript.len() > 2000 {
            self.transcript.pop_front();
        }
    }

    fn record_pulse(&mut self, now: Instant, force: bool) {
        if !force && now.duration_since(self.last_pulse_sample) < Duration::from_millis(PULSE_SAMPLE_MIN_MS) {
            return;
        }
        let pulse = self.throughput_window.len() as u64;
        self.pulse_history.push_back(pulse);
        while self.pulse_history.len() > PULSE_HISTORY_LEN {
            self.pulse_history.pop_front();
        }
        self.last_pulse_sample = now;
    }

    fn ingest_system_events(&mut self, value: &Value) {
        let msg_type = value.get("type").and_then(|v| v.as_str());
        let event = value.get("event").and_then(|v| v.as_str());
        if msg_type != Some("event") {
            return;
        }

        if event == Some("health") {
            let ok = value
                .get("payload")
                .and_then(|p| p.get("ok"))
                .and_then(|v| v.as_bool());
            self.gateway_health_ok = ok;
            self.gateway_health_at = Some(Instant::now());
            if let Some(duration) = value
                .get("payload")
                .and_then(|p| p.get("durationMs"))
                .and_then(|v| v.as_i64())
            {
                self.gateway_health_note = format!("{}ms", duration);
            } else {
                self.gateway_health_note.clear();
            }
        }

        if event == Some("agent") {
            let payload = match value.get("payload") {
                Some(p) => p,
                None => return,
            };
            let stream = payload.get("stream").and_then(|v| v.as_str());
            if stream != Some("lifecycle") {
                return;
            }
            let phase = payload
                .get("data")
                .and_then(|d| d.get("phase"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let status = match phase {
                "start" | "running" | "resume" => "RUNNING".to_string(),
                "end" | "stop" | "stopped" => "ENDED".to_string(),
                "error" | "failed" => "ERROR".to_string(),
                other => other.to_ascii_uppercase(),
            };
            let id = payload
                .get("sessionKey")
                .and_then(|v| v.as_str())
                .or_else(|| payload.get("runId").and_then(|v| v.as_str()))
                .unwrap_or("agent");
            self.agent_statuses.insert(
                id.to_string(),
                AgentState {
                    status,
                    last_at: Instant::now(),
                },
            );
        }
    }
}

enum Source {
    WebSocket {
        url: String,
        token: Option<String>,
        insecure_tls: bool,
        debug: bool,
    },
    Stdin,
    Demo,
}

struct TerminalGuard;

impl TerminalGuard {
    fn init() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
    }
}

fn main() -> io::Result<()> {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    let dotenv_map = read_dotenv_file(Path::new(".env"));
    let env_gateway = lookup_env(
        &dotenv_map,
        &["openclaw-endpoint", "OPENCLAW_ENDPOINT"],
    );
    let env_token = lookup_env(
        &dotenv_map,
        &[
            "openclaw-token",
            "OPENCLAW_TOKEN",
            "openclaw-gateway-token",
            "OPENCLAW_GATEWAY_TOKEN",
        ],
    );
    let env_insecure_tls =
        lookup_env(&dotenv_map, &["openclaw-insecure-tls", "OPENCLAW_INSECURE_TLS"]);

    let gateway = args
        .gateway
        .or(env_gateway)
        .unwrap_or_else(|| "ws://127.0.0.1:9001".to_string());
    let token = args.token.or(env_token);

    let insecure_tls = args.insecure_tls || parse_bool(env_insecure_tls);

    let source = if args.demo {
        Source::Demo
    } else if args.stdin {
        Source::Stdin
    } else {
        Source::WebSocket {
            url: gateway.clone(),
            token: token.clone(),
            insecure_tls,
            debug: args.debug,
        }
    };

    let settings_path = settings_path();
    let settings = load_settings(&settings_path);

    let connection = match &source {
        Source::WebSocket { url, .. } => url.clone(),
        Source::Stdin => "stdin".to_string(),
        Source::Demo => "demo".to_string(),
    };

    let (tx, rx) = mpsc::channel::<GatewayMessage>();
    spawn_reader(source, tx);

    let _guard = TerminalGuard::init()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new(connection, settings_path, settings);
    let tick_rate = Duration::from_millis(70);

    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                GatewayMessage::Line(line) => app.ingest_line(line),
                GatewayMessage::Status(status) => app.status = status,
            }
        }

        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('p') => app.paused = !app.paused,
                        KeyCode::Char('a') => {
                            app.show_all_messages = !app.show_all_messages;
                            let settings = Settings {
                                show_all_messages: app.show_all_messages,
                            };
                            if let Err(err) = save_settings(&app.settings_path, &settings) {
                                app.status = format!("Settings save failed: {err}");
                            } else {
                                app.status = if app.show_all_messages {
                                    "Display: ALL messages".to_string()
                                } else {
                                    "Display: text only".to_string()
                                };
                            }
                        }
                        KeyCode::Char('r') => {
                            let settings = Settings {
                                show_all_messages: app.show_all_messages,
                            };
                            app = App::new(
                                app.connection.clone(),
                                app.settings_path.clone(),
                                settings,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }

        if app.last_tick.elapsed() >= tick_rate {
            app.tick();
        }

        terminal.draw(|frame| render(frame, &app))?;
        thread::sleep(Duration::from_millis(16));
    }

    Ok(())
}

fn spawn_reader(source: Source, tx: mpsc::Sender<GatewayMessage>) {
    thread::spawn(move || match source {
        Source::WebSocket {
            url,
            token,
            insecure_tls,
            debug,
        } => read_websocket(url, token, insecure_tls, debug, tx),
        Source::Stdin => read_stdin(tx),
        Source::Demo => read_demo(tx),
    });
}

fn read_websocket(
    url: String,
    token: Option<String>,
    insecure_tls: bool,
    debug: bool,
    tx: mpsc::Sender<GatewayMessage>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let parsed = match Url::parse(&url) {
            Ok(parsed) => parsed,
            Err(err) => {
                send_status(&tx, debug, format!("Bad URL: {err}"));
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        let mut request = match parsed.into_client_request() {
            Ok(request) => request,
            Err(err) => {
                send_status(&tx, debug, format!("Bad request: {err}"));
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        if let Some(token) = &token {
            if let Ok(value) = format!("Bearer {token}").parse() {
                request.headers_mut().insert(AUTHORIZATION, value);
            }
            if let Ok(value) = token.parse() {
                request
                    .headers_mut()
                    .insert(HeaderName::from_static("x-openclaw-token"), value);
            }
        }

        send_status(&tx, debug, format!("Connecting to {url}..."));
        match connect_gateway(request, insecure_tls) {
            Ok((mut socket, _)) => {
                backoff = Duration::from_secs(1);
                send_status(&tx, debug, format!("Connected to {url}"));
                let (device_id, signing_key) = load_or_create_device_identity();
                let mut connect_id: Option<String> = None;
                let mut connect_sent = false;
                loop {
                    match socket.read() {
                        Ok(Message::Text(text)) => {
                            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                                if !connect_sent
                                    && value.get("type").and_then(|v| v.as_str()) == Some("event")
                                    && value.get("event").and_then(|v| v.as_str())
                                        == Some("connect.challenge")
                                {
                                    let nonce = value
                                        .get("payload")
                                        .and_then(|p| p.get("nonce"))
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let ts = value
                                        .get("payload")
                                        .and_then(|p| p.get("ts"))
                                        .and_then(|v| v.as_u64());

                                    let Some(token) = &token else {
                                        send_status(
                                            &tx,
                                            debug,
                                            "Missing gateway token; cannot authenticate"
                                                .to_string(),
                                        );
                                        continue;
                                    };
                                    let Some(nonce) = nonce else {
                                        send_status(
                                            &tx,
                                            debug,
                                            "Challenge missing nonce; cannot authenticate"
                                                .to_string(),
                                        );
                                        continue;
                                    };
                                    let Some(ts) = ts else {
                                        send_status(
                                            &tx,
                                            debug,
                                            "Challenge missing ts; cannot authenticate"
                                                .to_string(),
                                        );
                                        continue;
                                    };

                                    let id = connect_id.get_or_insert_with(new_request_id);
                                    let message = build_connect_request(
                                        id,
                                        token,
                                        &nonce,
                                        ts,
                                        &device_id,
                                        &signing_key,
                                    );
                                    if debug {
                                        eprintln!(
                                            "[openclaw] connect params: client_id=cli, client_mode=cli, role=operator, scopes=operator.read,operator.write,operator.admin, device_id={}",
                                            device_id
                                        );
                                    }
                                    match socket.send(Message::Text(message)) {
                                        Ok(_) => {
                                            connect_sent = true;
                                            send_status(&tx, debug, "Sent connect request".into());
                                        }
                                        Err(err) => {
                                            send_status(
                                                &tx,
                                                debug,
                                                format!("Connect send failed: {err}"),
                                            );
                                        }
                                    }
                                } else if value.get("type").and_then(|v| v.as_str()) == Some("res") {
                                    if let Some(id) = value.get("id").and_then(|v| v.as_str()) {
                                        if connect_id.as_deref() == Some(id) {
                                            let ok = value
                                                .get("ok")
                                                .and_then(|v| v.as_bool())
                                                .unwrap_or(false);
                                            if ok {
                                                send_status(
                                                    &tx,
                                                    debug,
                                                    "Gateway connect accepted".to_string(),
                                                );
                                                if let Some(device_token) = value
                                                    .get("payload")
                                                    .and_then(|p| p.get("auth"))
                                                    .and_then(|a| a.get("deviceToken"))
                                                    .and_then(|v| v.as_str())
                                                {
                                                    send_status(
                                                        &tx,
                                                        debug,
                                                        format!(
                                                            "Device token issued (persist it): {}",
                                                            device_token
                                                        ),
                                                    );
                                                }
                                            } else {
                                                let err = value
                                                    .get("error")
                                                    .and_then(|v| v.get("message"))
                                                    .and_then(|v| v.as_str())
                                                    .or_else(|| {
                                                        value
                                                            .get("err")
                                                            .and_then(|v| v.as_str())
                                                    })
                                                    .unwrap_or("unknown error");
                                                send_status(
                                                    &tx,
                                                    debug,
                                                    format!("Gateway connect rejected: {err}"),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            let _ = tx.send(GatewayMessage::Line(text));
                        }
                        Ok(Message::Binary(data)) => {
                            let preview = format!("binary:{} bytes", data.len());
                            let _ = tx.send(GatewayMessage::Line(preview));
                        }
                        Ok(Message::Ping(payload)) => {
                            let _ = socket.send(Message::Pong(payload));
                        }
                        Ok(Message::Pong(_)) => {}
                        Ok(Message::Close(_)) => {
                            send_status(&tx, debug, "Gateway closed connection".to_string());
                            break;
                        }
                        Err(err) => {
                            send_status(&tx, debug, format!("Gateway error: {err}"));
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(err) => {
                send_status(&tx, debug, format!("Connect failed: {err}"));
            }
        }

        send_status(
            &tx,
            debug,
            format!("Reconnecting in {}s", backoff.as_secs()),
        );
        thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(20));
    }
}

fn send_status(tx: &mpsc::Sender<GatewayMessage>, debug: bool, message: String) {
    if debug {
        eprintln!("[openclaw] {message}");
    }
    let _ = tx.send(GatewayMessage::Status(message));
}

fn connect_gateway<Req: IntoClientRequest>(
    request: Req,
    insecure_tls: bool,
) -> tungstenite::Result<(WebSocket<MaybeTlsStream<TcpStream>>, WsResponse)> {
    let request = request.into_client_request()?;
    let mode = uri_mode(request.uri())?;
    if !insecure_tls || matches!(mode, Mode::Plain) {
        return connect(request);
    }

    let host = request
        .uri()
        .host()
        .ok_or(WsError::Url(UrlError::NoHostName))?;
    let port = request.uri().port_u16().unwrap_or(443);
    let addrs = (host, port).to_socket_addrs()?;
    let mut last_err = None;
    let mut stream = None;
    for addr in addrs {
        match TcpStream::connect(addr) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(err) => last_err = Some(err),
        }
    }
    let stream = match stream {
        Some(stream) => stream,
        None => {
            if let Some(err) = last_err {
                return Err(WsError::Io(err));
            }
            return Err(WsError::Url(UrlError::UnableToConnect(
                request.uri().to_string(),
            )));
        }
    };
    let _ = stream.set_nodelay(true);

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|err| WsError::Tls(err.into()))?;
    let client = client_tls_with_config(
        request,
        stream,
        None,
        Some(Connector::NativeTls(connector)),
    );
    match client {
        Ok(result) => Ok(result),
        Err(HandshakeError::Failure(f)) => Err(f),
        Err(HandshakeError::Interrupted(_)) => Err(WsError::Io(io::Error::new(
            io::ErrorKind::Other,
            "TLS handshake interrupted",
        ))),
    }
}

fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        })
        .join("nina-cli")
}

fn derive_device_id(signing_key: &SigningKey) -> String {
    let public_key = signing_key.verifying_key();
    hex::encode(Sha256::digest(public_key.as_bytes()))
}

fn load_or_create_device_identity() -> (String, SigningKey) {
    let config_dir = get_config_dir();
    let device_file = config_dir.join("device.json");

    if let Ok(contents) = std::fs::read_to_string(&device_file) {
        if let Ok(identity) = serde_json::from_str::<DeviceIdentity>(&contents) {
            if let Ok(key_bytes) = BASE64.decode(&identity.private_key) {
                if let Ok(key_array) = key_bytes.try_into() {
                    let signing_key = SigningKey::from_bytes(&key_array);
                    return (derive_device_id(&signing_key), signing_key);
                }
            }
        }
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let device_id = derive_device_id(&signing_key);
    let identity = DeviceIdentity {
        private_key: BASE64.encode(signing_key.to_bytes()),
        public_key: BASE64.encode(signing_key.verifying_key().as_bytes()),
    };

    let _ = std::fs::create_dir_all(&config_dir);
    let _ = std::fs::write(&device_file, serde_json::to_string_pretty(&identity).unwrap());

    (device_id, signing_key)
}

fn build_connect_request(
    connect_id: &str,
    token: &str,
    nonce: &str,
    ts: u64,
    device_id: &str,
    signing_key: &SigningKey,
) -> String {
    let public_key = signing_key.verifying_key();
    let public_key_b64 = BASE64URL.encode(public_key.as_bytes());

    let payload = format!(
        "v2|{}|cli|cli|operator|operator.read,operator.write,operator.admin|{}|{}|{}",
        device_id, ts, token, nonce
    );
    let signature = signing_key.sign(payload.as_bytes());
    let signature_b64 = BASE64URL.encode(signature.to_bytes());

    json!({
        "type": "req",
        "id": connect_id,
        "method": "connect",
        "params": {
            "minProtocol": 3,
            "maxProtocol": 3,
            "client": {
                "id": "cli",
                "version": env!("CARGO_PKG_VERSION"),
                "platform": std::env::consts::OS,
                "mode": "cli"
            },
            "role": "operator",
            "scopes": ["operator.read", "operator.write", "operator.admin"],
            "caps": [],
            "commands": [],
            "permissions": {},
            "auth": { "token": token },
            "locale": "en-US",
            "userAgent": format!("nina-cli/{}", env!("CARGO_PKG_VERSION")),
            "device": {
                "id": device_id,
                "publicKey": public_key_b64,
                "signature": signature_b64,
                "signedAt": ts,
                "nonce": nonce
            }
        }
    })
    .to_string()
}

fn lookup_env(dotenv_map: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        if let Some(value) = dotenv_map.get(*key) {
            if !value.is_empty() {
                return Some(value.clone());
            }
        }
    }
    None
}

fn parse_bool(value: Option<String>) -> bool {
    match value {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y" | "on"
        ),
        None => false,
    }
}

fn estimate_tokens(text: &str) -> usize {
    let non_ws = text.chars().filter(|c| !c.is_whitespace()).count();
    if non_ws == 0 {
        0
    } else {
        (non_ws + 3) / 4
    }
}

fn status_style_for(status: &str) -> Style {
    match status {
        "RUNNING" => Style::default().fg(NEON),
        "ERROR" => Style::default().fg(ALERT),
        "ENDED" => Style::default().fg(DIM),
        _ => Style::default().fg(NEON),
    }
}

fn is_root_agent(id: &str) -> bool {
    let parts: Vec<&str> = id.split(':').collect();
    parts.len() >= 3 && parts[0] == "agent" && parts[2] == "main"
}

fn is_guid_like(value: &str) -> bool {
    value.contains('-')
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn shorten_guid(value: &str) -> String {
    value
        .rsplit('-')
        .next()
        .unwrap_or(value)
        .to_string()
}

fn shorten_session_key(value: &str) -> String {
    value
        .split(':')
        .map(|part| {
            if is_guid_like(part) {
                shorten_guid(part)
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}

fn strip_agent_prefix(value: &str) -> String {
    value.strip_prefix("agent:").unwrap_or(value).to_string()
}

fn format_agent_line(
    label: &str,
    status: &str,
    age: &str,
    label_width: usize,
    status_width: usize,
    age_width: usize,
) -> String {
    let label_text = pad_right(label, label_width.max(1));
    let status_text = pad_right(status, status_width.max(1));
    let age_text = right_align(age, age_width.max(1));
    format!("{label_text}  {status_text}  {age_text}")
}

fn fit_line(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let len = text.chars().count();
    if len <= max {
        return text.to_string();
    }
    if max == 1 {
        return "…".to_string();
    }
    let mut out = text.chars().take(max.saturating_sub(1)).collect::<String>();
    out.push('…');
    out
}

fn pulse_series(history: &VecDeque<u64>, width: usize) -> Vec<u64> {
    if width == 0 {
        return vec![0];
    }
    if history.is_empty() {
        return vec![0; width];
    }
    if history.len() >= width {
        history.iter().rev().take(width).rev().copied().collect()
    } else {
        let mut data = Vec::with_capacity(width);
        let pad = width - history.len();
        data.extend(std::iter::repeat(0).take(pad));
        data.extend(history.iter().copied());
        data
    }
}

fn extract_gateway_domain(connection: &str) -> String {
    if let Ok(url) = Url::parse(connection) {
        if let Some(host) = url.host_str() {
            return host.to_string();
        }
    }
    if connection.starts_with("ws://") || connection.starts_with("wss://") {
        return connection
            .trim_start_matches("ws://")
            .trim_start_matches("wss://")
            .split('/')
            .next()
            .unwrap_or(connection)
            .to_string();
    }
    connection.to_string()
}

fn settings_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        })
        .join("cyberpunk-openclaw-visualizer")
        .join("settings.yaml")
}

fn load_settings(path: &Path) -> Settings {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Settings::default();
    };
    serde_yaml::from_str(&contents).unwrap_or_default()
}

fn save_settings(path: &Path, settings: &Settings) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let serialized = serde_yaml::to_string(settings).unwrap_or_default();
    std::fs::write(path, serialized)
}

fn right_align(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return fit_line(text, width);
    }
    let mut out = String::with_capacity(width);
    for _ in 0..(width - len) {
        out.push(' ');
    }
    out.push_str(text);
    out
}

fn pad_right(text: &str, width: usize) -> String {
    let trimmed = fit_line(text, width);
    let len = trimmed.chars().count();
    if len >= width {
        return trimmed;
    }
    let mut out = String::with_capacity(width);
    out.push_str(&trimmed);
    for _ in 0..(width - len) {
        out.push(' ');
    }
    out
}

fn extract_display_text(
    value: &Value,
    cache: &mut HashMap<String, String>,
) -> Option<String> {
    let msg_type = value.get("type").and_then(|v| v.as_str());
    let event = value.get("event").and_then(|v| v.as_str());

    if msg_type == Some("event") && event == Some("agent") {
        let payload = value.get("payload")?;
        let stream = payload.get("stream").and_then(|v| v.as_str())?;
        if stream != "assistant" {
            return None;
        }
        let run_id = payload.get("runId").and_then(|v| v.as_str()).unwrap_or("unknown");
        let key = format!("{run_id}:{stream}");
        let data = payload.get("data")?;

        if let Some(delta) = data.get("delta").and_then(|v| v.as_str()) {
            if !delta.is_empty() {
                let entry = cache.entry(key).or_default();
                entry.push_str(delta);
                return Some(delta.to_string());
            }
        }

        if let Some(text) = data.get("text").and_then(|v| v.as_str()) {
            let entry = cache.entry(key).or_default();
            if text.starts_with(entry.as_str()) {
                let delta = &text[entry.len()..];
                entry.clear();
                entry.push_str(text);
                if delta.is_empty() {
                    return None;
                }
                return Some(delta.to_string());
            }
            entry.clear();
            entry.push_str(text);
            return Some(text.to_string());
        }
    }

    if msg_type == Some("event") && event == Some("chat") {
        let payload = value.get("payload")?;
        let state = payload.get("state").and_then(|v| v.as_str());
        if state != Some("final") {
            return None;
        }
        if let Some(run_id) = payload.get("runId").and_then(|v| v.as_str()) {
            let key = format!("{run_id}:assistant");
            if cache.contains_key(&key) {
                return None;
            }
        }
        let text = payload
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|f| f.get("text"))
            .and_then(|t| t.as_str())?;
        if !text.is_empty() {
            return Some(text.to_string());
        }
    }

    None
}

fn read_stdin(tx: mpsc::Sender<GatewayMessage>) {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = tx.send(GatewayMessage::Status("stdin closed".to_string()));
                thread::sleep(Duration::from_millis(200));
            }
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\n', '\r']);
                let _ = tx.send(GatewayMessage::Line(trimmed.to_string()));
            }
            Err(err) => {
                let _ = tx.send(GatewayMessage::Status(format!("stdin error: {err}")));
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn read_demo(tx: mpsc::Sender<GatewayMessage>) {
    let mut rng = rand::thread_rng();
    let devices = ["alpha", "beta", "gamma", "delta", "omega"];
    let types = ["telemetry", "control", "heartbeat", "alert", "sync"];
    loop {
        let device = devices[rng.gen_range(0..devices.len())];
        let event_type = types[rng.gen_range(0..types.len())];
        let latency = rng.gen_range(5.0..180.0);
        let status = if rng.gen_bool(0.92) { "ok" } else { "error" };
        let payload = serde_json::json!({
            "type": event_type,
            "status": status,
            "device_id": device,
            "latency_ms": latency,
            "signal": rng.gen_range(-80..-40),
            "temperature": rng.gen_range(28.0..62.0),
        });
        let _ = tx.send(GatewayMessage::Line(payload.to_string()));
        thread::sleep(Duration::from_millis(rng.gen_range(40..160)));
    }
}

fn render(frame: &mut ratatui::Frame<'_>, app: &App) {
    let size = frame.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(8),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(size);

    render_header(frame, chunks[0], app);
    render_stats(frame, chunks[1], app);
    render_log(frame, chunks[2], app);
    render_footer(frame, chunks[3], app);
}

fn render_header(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let uptime = format_duration(app.start.elapsed());
    let title_style = Style::default().fg(NEON_HOT).add_modifier(Modifier::BOLD);
    let status_style = Style::default().fg(NEON);
    let gateway = extract_gateway_domain(&app.connection);
    let header = Line::from(vec![
        Span::styled("OPENCLAW GATEWAY VISUALIZER", title_style),
        Span::raw("  "),
        Span::styled(gateway, status_style),
        Span::raw("  "),
        Span::styled(format!("uptime {uptime}"), Style::default().fg(DIM)),
    ]);

    let status_line = Line::from(vec![
        Span::styled("STATUS: ", Style::default().fg(DIM)),
        Span::styled(app.status.clone(), Style::default().fg(NEON)),
        Span::raw("  "),
        Span::styled("CONN: ", Style::default().fg(DIM)),
        Span::styled(app.connection.clone(), Style::default().fg(NEON)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    let text = Text::from(vec![header, status_line]);
    let paragraph = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

fn render_stats(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(area);

    render_metrics(frame, columns[0], app);
    render_pulse(frame, columns[1], app);
    render_health(frame, columns[2], app);
}

fn render_metrics(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let msg_rate = app.throughput_window.len() as u64;
    let last_event_age = app
        .last_event_at
        .map(|t| format_duration(t.elapsed()))
        .unwrap_or_else(|| "--".to_string());

    let mut top_types = app.types.iter().collect::<Vec<_>>();
    top_types.sort_by(|a, b| b.1.cmp(a.1));
    let top_str = top_types
        .iter()
        .take(3)
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(" ");

    let left_lines = vec![
        Line::from(vec![Span::styled(
            format!("Msgs/s: {msg_rate}"),
            Style::default().fg(NEON).add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            format!("Tokens/s (5s): {}", app.tokens_per_sec),
            Style::default().fg(NEON).add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            format!("Errors: {}", app.errors),
            Style::default().fg(if app.errors > 0 { ALERT } else { NEON }),
        )]),
        Line::from(vec![Span::styled(
            format!("Devices: {}", app.unique_devices.len()),
            Style::default().fg(NEON),
        )]),
        Line::from(vec![Span::styled(
            format!("Last: {last_event_age} ago"),
            Style::default().fg(NEON),
        )]),
        Line::from(vec![Span::styled(
            format!("Top: {top_str}"),
            Style::default().fg(DIM),
        )]),
    ];

    let block = Block::default()
        .title(Span::styled("LIVE METRICS", Style::default().fg(NEON_HOT)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    frame.render_widget(&block, area);
    let inner = block.inner(area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(inner);

    let left = Paragraph::new(Text::from(left_lines)).alignment(Alignment::Left);
    frame.render_widget(left, cols[0]);

    let right_lines = vec![
        Line::from(vec![Span::styled(
            format!("Total Msgs: {}", app.total),
            Style::default().fg(NEON).add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            format!("Total Tokens: {}", app.total_tokens),
            Style::default().fg(NEON).add_modifier(Modifier::BOLD),
        )]),
    ];
    let right = Paragraph::new(Text::from(right_lines)).alignment(Alignment::Left);
    frame.render_widget(right, cols[1]);
}

fn render_pulse(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled("PULSE", Style::default().fg(NEON_HOT)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    let width = inner.width.max(1) as usize;
    let data = pulse_series(&app.pulse_history, width);

    let sparkline = Sparkline::default()
        .block(block)
        .data(&data)
        .style(Style::default().fg(NEON));

    frame.render_widget(sparkline, area);
}

fn render_health(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let mut lines: Vec<Line> = Vec::new();
    let block = Block::default()
        .title(Span::styled("GATEWAY HEALTH", Style::default().fg(NEON_HOT)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    let (health_label, health_style) = match app.gateway_health_ok {
        Some(true) => ("OK", Style::default().fg(NEON).add_modifier(Modifier::BOLD)),
        Some(false) => ("DEGRADED", Style::default().fg(ALERT).add_modifier(Modifier::BOLD)),
        None => ("UNKNOWN", Style::default().fg(DIM)),
    };
    let last = app
        .gateway_health_at
        .map(|at| format_duration(at.elapsed()))
        .unwrap_or_else(|| "--".to_string());
    let status_line = Line::from(vec![
        Span::styled("Status: ", Style::default().fg(DIM)),
        Span::styled(health_label, health_style),
        Span::raw("  "),
        Span::styled("Last: ", Style::default().fg(DIM)),
        Span::styled(last, Style::default().fg(NEON)),
    ]);
    lines.push(status_line);

    if !app.gateway_health_note.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Duration: ", Style::default().fg(DIM)),
            Span::styled(app.gateway_health_note.clone(), Style::default().fg(NEON)),
        ]));
    }

    lines.push(Line::from(Span::styled(
        "Agents:",
        Style::default().fg(NEON_HOT),
    )));

    let mut agents = app
        .agent_statuses
        .iter()
        .map(|(id, state)| (id.clone(), state.clone()))
        .collect::<Vec<_>>();
    agents.sort_by(|a, b| b.1.last_at.cmp(&a.1.last_at));

    let mut roots = agents
        .iter()
        .filter(|(id, _)| is_root_agent(id))
        .map(|(id, state)| (id.clone(), state.clone()))
        .collect::<Vec<_>>();
    roots.sort_by(|a, b| b.1.last_at.cmp(&a.1.last_at));

    let mut agent_lines: Vec<(String, String, String, Style)> = Vec::new();
    if roots.is_empty() {
        for (id, state) in agents.iter() {
            let label = shorten_session_key(id);
            let age = format_duration(state.last_at.elapsed());
            let status_style = status_style_for(&state.status);
            agent_lines.push((label, state.status.clone(), age, status_style));
        }
    } else {
        for (root_id, root_state) in roots.iter() {
            let label = strip_agent_prefix(&shorten_session_key(root_id));
            let age = format_duration(root_state.last_at.elapsed());
            agent_lines.push((
                label,
                root_state.status.clone(),
                age,
                status_style_for(&root_state.status),
            ));

            let root_prefix = if let Some(stripped) = root_id.strip_suffix(":main") {
                format!("{stripped}:")
            } else {
                format!("{root_id}:")
            };
            let mut children = agents
                .iter()
                .filter(|(id, _)| id.starts_with(&root_prefix) && id.as_str() != root_id)
                .map(|(id, state)| (id.clone(), state.clone()))
                .collect::<Vec<_>>();
            children.sort_by(|a, b| b.1.last_at.cmp(&a.1.last_at));
            for (idx, (child_id, child_state)) in children.iter().enumerate() {
                let mut label = if child_id.starts_with(&root_prefix) {
                    child_id[root_prefix.len()..].to_string()
                } else {
                    child_id.clone()
                };
                label = strip_agent_prefix(&shorten_session_key(&label));
                let age = format_duration(child_state.last_at.elapsed());
                let connector = if idx + 1 == children.len() { "└" } else { "├" };
                agent_lines.push((
                    format!("{connector} {label}"),
                    child_state.status.clone(),
                    age,
                    status_style_for(&child_state.status),
                ));
            }
        }
    }

    let max_lines = area.height.saturating_sub(2) as usize;
    let mut remaining = max_lines.saturating_sub(lines.len());
    if remaining == 0 {
        let paragraph = Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
        return;
    }

    let max_width = area.width.saturating_sub(2) as usize;
    let label_width = agent_lines
        .iter()
        .map(|(label, _, _, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    let status_width = agent_lines
        .iter()
        .map(|(_, status, _, _)| status.chars().count())
        .max()
        .unwrap_or(0);
    let age_width = agent_lines
        .iter()
        .map(|(_, _, age, _)| age.chars().count())
        .max()
        .unwrap_or(0);

    if agent_lines.len() > remaining {
        let show = remaining.saturating_sub(1);
        for (label, status, age, style) in agent_lines.iter().take(show) {
            let line_text =
                format_agent_line(label, status, age, label_width, status_width, age_width);
            let clipped = fit_line(&line_text, max_width);
            lines.push(Line::from(Span::styled(clipped, *style)));
        }
        let extra = agent_lines.len().saturating_sub(show);
        lines.push(Line::from(Span::styled(
            format!("... +{extra} more"),
            Style::default().fg(DIM),
        )));
    } else {
        for (label, status, age, style) in agent_lines {
            if remaining == 0 {
                break;
            }
            let line_text =
                format_agent_line(&label, &status, &age, label_width, status_width, age_width);
            let clipped = fit_line(&line_text, max_width);
            lines.push(Line::from(Span::styled(clipped, style)));
            remaining = remaining.saturating_sub(1);
        }
    }

    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_log(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let mut end = app.transcript.len();
    while end > 0 {
        if let Some(last) = app.transcript.get(end - 1) {
            if last.is_empty() {
                end = end.saturating_sub(1);
                continue;
            }
        }
        break;
    }

    let block = Block::default()
        .title(Span::styled("LIVE FEED", Style::default().fg(NEON_HOT)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    let inner = block.inner(area);
    let wrap_width = inner.width as usize;
    let visible_lines = inner.height as usize;
    let mut wrapped_lines: Vec<String> = Vec::new();

    if wrap_width > 0 && visible_lines > 0 {
        for line in app.transcript.iter().take(end) {
            if line.is_empty() {
                wrapped_lines.push(String::new());
                continue;
            }
            let mut buf = String::new();
            let mut count = 0usize;
            for ch in line.chars() {
                buf.push(ch);
                count += 1;
                if count >= wrap_width {
                    wrapped_lines.push(buf);
                    buf = String::new();
                    count = 0;
                }
            }
            if !buf.is_empty() {
                wrapped_lines.push(buf);
            }
        }
    }

    let start = wrapped_lines.len().saturating_sub(visible_lines);
    let mut lines = Vec::new();
    for line in wrapped_lines.iter().skip(start) {
        lines.push(Line::from(Span::styled(line.clone(), Style::default().fg(NEON))));
    }

    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

fn render_footer(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let all_style = if app.show_all_messages {
        Style::default().fg(NEON).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(DIM)
    };
    let help = Line::from(vec![
        Span::styled("[q] Quit", Style::default().fg(DIM)),
        Span::raw("  "),
        Span::styled("[p] Pause", Style::default().fg(DIM)),
        Span::raw("  "),
        Span::styled("[a] All", all_style),
        Span::raw("  "),
        Span::styled("[r] Reset", Style::default().fg(DIM)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    let text = Text::from(vec![help]);
    let paragraph = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let mins = secs / 60;
    let secs = secs % 60;
    if mins > 0 {
        format!("{mins}m{secs:02}s")
    } else {
        format!("{secs}s")
    }
}

fn read_dotenv_file(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(content) = std::fs::read_to_string(path) else {
        return map;
    };
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut value = value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len().saturating_sub(1)].to_string();
        }
        map.insert(key.to_string(), value);
    }
    map
}
