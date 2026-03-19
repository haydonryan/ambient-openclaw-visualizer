use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead, BufReader};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL},
};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use rand::rngs::OsRng;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Axis, Block, Borders, Chart, Clear, Dataset, GraphType, Paragraph, Wrap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tungstenite::client::{IntoClientRequest, uri_mode};
use tungstenite::error::{Error as WsError, UrlError};
use tungstenite::handshake::client::Response as WsResponse;
use tungstenite::http::header::{AUTHORIZATION, HeaderName};
use tungstenite::stream::{MaybeTlsStream, Mode};
use tungstenite::{Connector, HandshakeError, Message, WebSocket, client_tls_with_config, connect};
use url::Url;
use uuid::Uuid;

const NEON: Color = Color::Rgb(0, 255, 140);
const NEON_HOT: Color = Color::Rgb(0, 255, 200);
const DIM: Color = Color::Rgb(0, 120, 60);
const ALERT: Color = Color::Rgb(255, 64, 64);
const BG: Color = Color::Black;
const PULSE_HISTORY_LEN: usize = 120;
const PULSE_SAMPLE_MIN_MS: u64 = 700;

#[derive(Parser, Debug)]
#[command(
    name = "openclaw-visualizer",
    version,
    about = "OpenClaw gateway cyberpunk visualizer"
)]
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

    /// Headless mode: print all gateway messages to stdout
    #[arg(long)]
    headless: bool,

    /// Active window (minutes) for startup agent snapshot (0 = skip)
    #[arg(long, default_value_t = 15)]
    active_minutes: u64,
}

#[derive(Debug)]
enum GatewayMessage {
    Line(String),
    Status(String),
}

#[derive(Debug, Clone)]
enum GatewayCommand {
    SendChat {
        session_key: String,
        message: String,
    },
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

#[derive(Debug, Clone, Copy)]
enum TranscriptTone {
    Default,
    User,
}

#[derive(Debug, Clone)]
struct TranscriptEntry {
    text: String,
    tone: TranscriptTone,
}

impl Default for TranscriptEntry {
    fn default() -> Self {
        Self {
            text: String::new(),
            tone: TranscriptTone::Default,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Settings {
    show_all_messages: bool,
}

struct App {
    start: Instant,
    last_tick: Instant,
    last_event_at: Option<Instant>,
    total: u64,
    errors: u64,
    unique_devices: HashSet<String>,
    types: HashMap<String, u64>,
    transcript: VecDeque<TranscriptEntry>,
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
    show_help: bool,
    input: String,
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
            show_help: false,
            input: String::new(),
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
            self.ingest_gateway_responses(&value);
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
        if let Some(text) = display_text
            && !text.is_empty()
        {
            if self.show_all_messages && !display_is_stream {
                let gap_before = self.last_display_was_json_line && is_json_line;
                self.append_transcript_line(&text, now, gap_before);
                self.last_display_was_json_line = is_json_line;
            } else {
                self.append_transcript(&text, now);
                self.last_display_was_json_line = false;
            }
            if let Some(last) = self.transcript.back() {
                self.last_line = last.text.clone();
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
        self.record_pulse(now, false);
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
            self.transcript.push_back(TranscriptEntry::default());
        }
        let mut remaining = normalized.as_str();
        while let Some(pos) = remaining.find('\n') {
            let (head, tail) = remaining.split_at(pos);
            if let Some(last) = self.transcript.back_mut() {
                last.text.push_str(head);
            }
            self.transcript.push_back(TranscriptEntry::default());
            remaining = &tail[1..];
        }
        if let Some(last) = self.transcript.back_mut() {
            last.text.push_str(remaining);
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
            self.transcript.push_back(TranscriptEntry::default());
        }
        if want_gap {
            if let Some(last) = self.transcript.back()
                && !last.text.is_empty()
            {
                self.transcript.push_back(TranscriptEntry::default());
            }
            if let Some(last) = self.transcript.back()
                && last.text.is_empty()
            {
                self.transcript.push_back(TranscriptEntry::default());
            }
        } else if let Some(last) = self.transcript.back()
            && !last.text.is_empty()
        {
            self.transcript.push_back(TranscriptEntry::default());
        }
        if let Some(last) = self.transcript.back_mut() {
            last.text.push_str(line);
        }
        self.transcript.push_back(TranscriptEntry::default());
        while self.transcript.len() > 2000 {
            self.transcript.pop_front();
        }
    }

    fn append_local_user_message(&mut self, message: &str, at: Instant) {
        if self.transcript.is_empty() {
            self.transcript.push_back(TranscriptEntry::default());
        }
        if let Some(last) = self.transcript.back()
            && !last.text.is_empty()
        {
            self.transcript.push_back(TranscriptEntry::default());
        }
        let tokens = estimate_tokens(message);
        if tokens > 0 {
            self.token_window.push_back((at, tokens));
            self.total_tokens = self.total_tokens.saturating_add(tokens as u64);
        }
        self.transcript.push_back(TranscriptEntry {
            text: message.to_string(),
            tone: TranscriptTone::User,
        });
        self.transcript.push_back(TranscriptEntry::default());
        self.transcript.push_back(TranscriptEntry::default());
        while self.transcript.len() > 2000 {
            self.transcript.pop_front();
        }
        self.last_display_was_json_line = false;
        self.last_line = message.to_string();
    }

    fn record_pulse(&mut self, now: Instant, force: bool) {
        if !force
            && now.duration_since(self.last_pulse_sample)
                < Duration::from_millis(PULSE_SAMPLE_MIN_MS)
        {
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

    fn ingest_gateway_responses(&mut self, value: &Value) {
        if value.get("type").and_then(|v| v.as_str()) != Some("res") {
            return;
        }
        let payload = match value.get("payload") {
            Some(p) => p,
            None => return,
        };

        let mut running: Vec<(String, String)> = Vec::new();
        collect_running_agents(payload, &mut running);
        collect_active_sessions(payload, &mut running);
        if running.is_empty() {
            return;
        }

        self.agent_statuses.clear();
        let now = Instant::now();
        let mut seen: HashSet<String> = HashSet::new();
        for (id, status) in running {
            if !seen.insert(id.clone()) {
                continue;
            }
            self.agent_statuses.insert(
                id,
                AgentState {
                    status,
                    last_at: now,
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
        active_minutes: u64,
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
    let env_gateway = lookup_env(&dotenv_map, &["openclaw-endpoint", "OPENCLAW_ENDPOINT"]);
    let env_token = lookup_env(
        &dotenv_map,
        &[
            "openclaw-token",
            "OPENCLAW_TOKEN",
            "openclaw-gateway-token",
            "OPENCLAW_GATEWAY_TOKEN",
        ],
    );
    let env_insecure_tls = lookup_env(
        &dotenv_map,
        &["openclaw-insecure-tls", "OPENCLAW_INSECURE_TLS"],
    );

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
            active_minutes: args.active_minutes,
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
    let (command_tx, command_rx) = mpsc::channel::<GatewayCommand>();
    let allow_input = matches!(source, Source::WebSocket { .. });
    spawn_reader(source, tx, command_rx);

    if args.headless {
        return run_headless(rx);
    }

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

        if event::poll(Duration::from_millis(0))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if app.show_help {
                app.show_help = false;
                continue;
            }
            match key.code {
                KeyCode::Char('d') if key.modifiers == KeyModifiers::CONTROL => break,
                KeyCode::Char('p') if key.modifiers == KeyModifiers::CONTROL => {
                    app.paused = !app.paused
                }
                KeyCode::Char('a') if key.modifiers == KeyModifiers::CONTROL => {
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
                KeyCode::Char('h') if key.modifiers == KeyModifiers::CONTROL => {
                    app.show_help = !app.show_help;
                }
                KeyCode::Enter if key.modifiers == KeyModifiers::NONE => {
                    if !allow_input {
                        app.status = "Message input only works with --gateway".to_string();
                        continue;
                    }
                    let now = Instant::now();
                    let message = app.input.trim().to_string();
                    if message.is_empty() {
                        continue;
                    }
                    match command_tx.send(GatewayCommand::SendChat {
                        session_key: "main".to_string(),
                        message: message.clone(),
                    }) {
                        Ok(_) => {
                            app.append_local_user_message(&message, now);
                            app.status = "Queued message for main agent".to_string();
                            app.input.clear();
                        }
                        Err(err) => {
                            app.status = format!("Send queue failed: {err}");
                        }
                    }
                }
                KeyCode::Backspace if key.modifiers == KeyModifiers::NONE => {
                    app.input.pop();
                }
                KeyCode::Esc if key.modifiers == KeyModifiers::NONE => {
                    app.input.clear();
                }
                KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                    app.input.clear();
                }
                KeyCode::Char(ch)
                    if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                {
                    if allow_input {
                        app.input.push(ch);
                    }
                }
                _ => {}
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

fn run_headless(rx: mpsc::Receiver<GatewayMessage>) -> io::Result<()> {
    while let Ok(msg) = rx.recv() {
        match msg {
            GatewayMessage::Line(line) => {
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    let msg_type = value.get("type").and_then(|v| v.as_str());
                    let event = value.get("event").and_then(|v| v.as_str());
                    let label = match (msg_type, event) {
                        (Some(t), Some(e)) => format!("{t}/{e}"),
                        (Some(t), None) => t.to_string(),
                        (None, Some(e)) => e.to_string(),
                        (None, None) => String::new(),
                    };
                    if label.is_empty() {
                        println!("{line}");
                    } else {
                        println!("[{label}] {line}");
                    }
                } else {
                    println!("{line}");
                }
            }
            GatewayMessage::Status(status) => {
                eprintln!("[status] {status}");
            }
        }
    }
    Ok(())
}

fn spawn_reader(
    source: Source,
    tx: mpsc::Sender<GatewayMessage>,
    command_rx: mpsc::Receiver<GatewayCommand>,
) {
    thread::spawn(move || match source {
        Source::WebSocket {
            url,
            token,
            insecure_tls,
            debug,
            active_minutes,
        } => read_websocket(
            url,
            token,
            insecure_tls,
            debug,
            active_minutes,
            tx,
            command_rx,
        ),
        Source::Stdin => read_stdin(tx),
        Source::Demo => read_demo(tx),
    });
}

fn read_websocket(
    url: String,
    token: Option<String>,
    insecure_tls: bool,
    debug: bool,
    active_minutes: u64,
    tx: mpsc::Sender<GatewayMessage>,
    command_rx: mpsc::Receiver<GatewayCommand>,
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
                configure_socket_timeouts(socket.get_mut());
                backoff = Duration::from_secs(1);
                send_status(&tx, debug, format!("Connected to {url}"));
                let (device_id, signing_key) = load_or_create_device_identity();
                let mut connect_id: Option<String> = None;
                let mut connect_sent = false;
                let mut status_sent = false;
                let mut sessions_sent = false;
                loop {
                    while let Ok(command) = command_rx.try_recv() {
                        handle_gateway_command(&mut socket, &tx, debug, command);
                    }
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
                                            "Challenge missing ts; cannot authenticate".to_string(),
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
                                } else if value.get("type").and_then(|v| v.as_str()) == Some("res")
                                    && let Some(id) = value.get("id").and_then(|v| v.as_str())
                                    && connect_id.as_deref() == Some(id)
                                {
                                    let ok =
                                        value.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                                    if ok {
                                        send_status(
                                            &tx,
                                            debug,
                                            "Gateway connect accepted".to_string(),
                                        );
                                        if !status_sent {
                                            let request_id = new_request_id();
                                            let message = build_status_request(&request_id);
                                            match socket.send(Message::Text(message)) {
                                                Ok(_) => {
                                                    status_sent = true;
                                                    send_status(
                                                        &tx,
                                                        debug,
                                                        "Requested running agent snapshot"
                                                            .to_string(),
                                                    );
                                                }
                                                Err(err) => {
                                                    send_status(
                                                        &tx,
                                                        debug,
                                                        format!(
                                                            "Agent snapshot request failed: {err}"
                                                        ),
                                                    );
                                                }
                                            }
                                        }
                                        if !sessions_sent && active_minutes > 0 {
                                            let request_id = new_request_id();
                                            let message = build_sessions_list_request(
                                                &request_id,
                                                active_minutes,
                                            );
                                            match socket.send(Message::Text(message)) {
                                                Ok(_) => {
                                                    sessions_sent = true;
                                                    send_status(
                                                        &tx,
                                                        debug,
                                                        format!(
                                                            "Requested active sessions (last {}m)",
                                                            active_minutes
                                                        ),
                                                    );
                                                }
                                                Err(err) => {
                                                    send_status(
                                                        &tx,
                                                        debug,
                                                        format!(
                                                            "Active sessions request failed: {err}"
                                                        ),
                                                    );
                                                }
                                            }
                                        }
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
                                            .or_else(|| value.get("err").and_then(|v| v.as_str()))
                                            .unwrap_or("unknown error");
                                        send_status(
                                            &tx,
                                            debug,
                                            format!("Gateway connect rejected: {err}"),
                                        );
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
                            if is_timeout_error(&err) {
                                continue;
                            }
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

fn handle_gateway_command(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    tx: &mpsc::Sender<GatewayMessage>,
    debug: bool,
    command: GatewayCommand,
) {
    match command {
        GatewayCommand::SendChat {
            session_key,
            message,
        } => {
            let request_id = new_request_id();
            let payload = build_chat_send_request(&request_id, &session_key, &message);
            match socket.send(Message::Text(payload)) {
                Ok(_) => {
                    send_status(tx, debug, format!("Sent chat.send to {session_key}"));
                }
                Err(err) => {
                    send_status(tx, debug, format!("chat.send failed: {err}"));
                }
            }
        }
    }
}

fn configure_socket_timeouts(stream: &mut MaybeTlsStream<TcpStream>) {
    let timeout = Some(Duration::from_millis(100));
    match stream {
        MaybeTlsStream::Plain(inner) => {
            let _ = inner.set_read_timeout(timeout);
        }
        MaybeTlsStream::NativeTls(inner) => {
            let _ = inner.get_mut().set_read_timeout(timeout);
        }
        _ => {}
    }
}

fn is_timeout_error(err: &WsError) -> bool {
    match err {
        WsError::Io(io_err) => matches!(
            io_err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ),
        _ => false,
    }
}

type GatewayConnectResult =
    Result<(WebSocket<MaybeTlsStream<TcpStream>>, WsResponse), Box<WsError>>;

fn connect_gateway<Req: IntoClientRequest>(
    request: Req,
    insecure_tls: bool,
) -> GatewayConnectResult {
    let request = request.into_client_request()?;
    let mode = uri_mode(request.uri())?;
    if !insecure_tls || matches!(mode, Mode::Plain) {
        return connect(request).map_err(Box::new);
    }

    let host = request
        .uri()
        .host()
        .ok_or_else(|| Box::new(WsError::Url(UrlError::NoHostName)))?;
    let port = request.uri().port_u16().unwrap_or(443);
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|err| Box::new(WsError::Io(err)))?;
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
                return Err(Box::new(WsError::Io(err)));
            }
            return Err(Box::new(WsError::Url(UrlError::UnableToConnect(
                request.uri().to_string(),
            ))));
        }
    };
    let _ = stream.set_nodelay(true);

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|err| Box::new(WsError::Tls(err.into())))?;
    let client =
        client_tls_with_config(request, stream, None, Some(Connector::NativeTls(connector)));
    match client {
        Ok(result) => Ok(result),
        Err(HandshakeError::Failure(f)) => Err(Box::new(f)),
        Err(HandshakeError::Interrupted(_)) => Err(Box::new(WsError::Io(io::Error::other(
            "TLS handshake interrupted",
        )))),
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

    if let Ok(contents) = std::fs::read_to_string(&device_file)
        && let Ok(identity) = serde_json::from_str::<DeviceIdentity>(&contents)
        && let Ok(key_bytes) = BASE64.decode(&identity.private_key)
        && let Ok(key_array) = key_bytes.try_into()
    {
        let signing_key = SigningKey::from_bytes(&key_array);
        return (derive_device_id(&signing_key), signing_key);
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let device_id = derive_device_id(&signing_key);
    let identity = DeviceIdentity {
        private_key: BASE64.encode(signing_key.to_bytes()),
        public_key: BASE64.encode(signing_key.verifying_key().as_bytes()),
    };

    let _ = std::fs::create_dir_all(&config_dir);
    let _ = std::fs::write(
        &device_file,
        serde_json::to_string_pretty(&identity).unwrap(),
    );

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

fn build_status_request(request_id: &str) -> String {
    json!({
        "type": "req",
        "id": request_id,
        "method": "status",
        "params": {}
    })
    .to_string()
}

fn build_sessions_list_request(request_id: &str, active_minutes: u64) -> String {
    json!({
        "type": "req",
        "id": request_id,
        "method": "sessions.list",
        "params": {
            "activeMinutes": active_minutes
        }
    })
    .to_string()
}

fn build_chat_send_request(request_id: &str, session_key: &str, message: &str) -> String {
    json!({
        "type": "req",
        "id": request_id,
        "method": "chat.send",
        "params": {
            "sessionKey": session_key,
            "message": message,
            "idempotencyKey": request_id
        }
    })
    .to_string()
}

fn lookup_env(dotenv_map: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = std::env::var(key)
            && !value.is_empty()
        {
            return Some(value);
        }
        if let Some(value) = dotenv_map.get(*key)
            && !value.is_empty()
        {
            return Some(value.clone());
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
    if non_ws == 0 { 0 } else { non_ws.div_ceil(4) }
}

fn status_style_for(status: &str) -> Style {
    match status {
        "RUNNING" => Style::default().fg(NEON),
        "ERROR" => Style::default().fg(ALERT),
        "ENDED" => Style::default().fg(DIM),
        _ => Style::default().fg(NEON),
    }
}

fn normalize_agent_status(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "start" | "started" | "running" | "resume" | "resumed" | "in_flight" | "in-flight"
        | "streaming" | "active" => "RUNNING".to_string(),
        "end" | "ended" | "stop" | "stopped" | "done" | "completed" | "ok" => "ENDED".to_string(),
        "error" | "failed" | "failure" | "crashed" => "ERROR".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

fn is_active_status(status: &str) -> bool {
    matches!(status, "RUNNING" | "IN_FLIGHT" | "STREAMING" | "ACTIVE")
}

fn collect_running_agents(payload: &Value, out: &mut Vec<(String, String)>) {
    let implicit_running_keys = [
        "running",
        "runningRuns",
        "running_runs",
        "activeRuns",
        "active_runs",
        "agentRuns",
        "agent_runs",
        "inFlight",
        "in_flight",
    ];

    for key in implicit_running_keys {
        if let Some(list) = payload.get(key).and_then(|v| v.as_array()) {
            collect_running_from_array(list, out, false);
        }
    }

    if let Some(list) = payload.get("runs").and_then(|v| v.as_array()) {
        collect_running_from_array(list, out, true);
    }

    if let Some(agents) = payload.get("agents") {
        if let Some(list) = agents.get("running").and_then(|v| v.as_array()) {
            collect_running_from_array(list, out, false);
        }
        if let Some(list) = agents.get("active").and_then(|v| v.as_array()) {
            collect_running_from_array(list, out, false);
        }
    }

    if let Some(sessions) = payload.get("sessions").and_then(|v| v.as_array()) {
        for session in sessions {
            if let Some(entry) = extract_running_from_session(session) {
                out.push(entry);
            }
        }
    }
}

fn collect_running_from_array(
    entries: &[Value],
    out: &mut Vec<(String, String)>,
    require_status: bool,
) {
    for entry in entries {
        if let Some(value) = extract_running_from_value(entry, require_status) {
            out.push(value);
        }
    }
}

fn collect_active_sessions(payload: &Value, out: &mut Vec<(String, String)>) {
    if let Some(list) = payload.as_array() {
        collect_active_sessions_from_array(list, out);
        return;
    }
    if let Some(list) = payload.get("rows").and_then(|v| v.as_array()) {
        collect_active_sessions_from_array(list, out);
        return;
    }
    if let Some(list) = payload.get("sessions").and_then(|v| v.as_array()) {
        collect_active_sessions_from_array(list, out);
        return;
    }
    if let Some(list) = payload.get("items").and_then(|v| v.as_array()) {
        collect_active_sessions_from_array(list, out);
    }
}

fn collect_active_sessions_from_array(entries: &[Value], out: &mut Vec<(String, String)>) {
    for entry in entries {
        if let Some(value) = extract_active_session(entry) {
            out.push(value);
        }
    }
}

fn extract_active_session(entry: &Value) -> Option<(String, String)> {
    if let Some(id) = entry.as_str() {
        return Some((id.to_string(), "RUNNING".to_string()));
    }
    let obj = entry.as_object()?;

    if obj.get("active").and_then(|v| v.as_bool()) == Some(false) {
        return None;
    }

    let id = obj
        .get("key")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("sessionKey").and_then(|v| v.as_str()))
        .or_else(|| obj.get("sessionId").and_then(|v| v.as_str()))
        .or_else(|| obj.get("id").and_then(|v| v.as_str()))?;

    let raw_status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("phase").and_then(|v| v.as_str()))
        .or_else(|| obj.get("state").and_then(|v| v.as_str()));
    let status = raw_status
        .map(normalize_agent_status)
        .unwrap_or_else(|| "RUNNING".to_string());

    Some((id.to_string(), status))
}

fn extract_running_from_value(entry: &Value, require_status: bool) -> Option<(String, String)> {
    if let Some(id) = entry.as_str() {
        if require_status {
            return None;
        }
        return Some((id.to_string(), "RUNNING".to_string()));
    }
    let obj = entry.as_object()?;

    let active_flag = obj
        .get("active")
        .and_then(|v| v.as_bool())
        .or_else(|| obj.get("running").and_then(|v| v.as_bool()));
    if matches!(active_flag, Some(false)) {
        return None;
    }

    let raw_status = obj
        .get("status")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("phase").and_then(|v| v.as_str()))
        .or_else(|| obj.get("state").and_then(|v| v.as_str()));
    let status = raw_status.map(normalize_agent_status);
    let active_by_status = status.as_deref().map(is_active_status).unwrap_or(false);
    if require_status && !active_by_status && !matches!(active_flag, Some(true)) {
        return None;
    }
    if let Some(ref normalized) = status
        && !is_active_status(normalized)
    {
        return None;
    }

    let id = obj
        .get("sessionKey")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("runId").and_then(|v| v.as_str()))
        .or_else(|| obj.get("id").and_then(|v| v.as_str()))
        .or_else(|| obj.get("agent").and_then(|v| v.as_str()))
        .or_else(|| obj.get("agentId").and_then(|v| v.as_str()))
        .or_else(|| obj.get("key").and_then(|v| v.as_str()))?;

    Some((
        id.to_string(),
        status.unwrap_or_else(|| "RUNNING".to_string()),
    ))
}

fn extract_running_from_session(session: &Value) -> Option<(String, String)> {
    let obj = session.as_object()?;
    let active_flag = obj
        .get("active")
        .and_then(|v| v.as_bool())
        .or_else(|| obj.get("running").and_then(|v| v.as_bool()));
    if matches!(active_flag, Some(false)) {
        return None;
    }

    let has_run = obj
        .get("activeRunId")
        .or_else(|| obj.get("runId"))
        .is_some();
    if !has_run {
        return None;
    }

    let raw_status = obj
        .get("runStatus")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("status").and_then(|v| v.as_str()))
        .or_else(|| obj.get("phase").and_then(|v| v.as_str()));
    let status = raw_status
        .map(normalize_agent_status)
        .unwrap_or_else(|| "RUNNING".to_string());
    if !is_active_status(&status) {
        return None;
    }

    let id = obj
        .get("sessionKey")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("activeRunId").and_then(|v| v.as_str()))
        .or_else(|| obj.get("runId").and_then(|v| v.as_str()))?;

    Some((id.to_string(), status))
}

fn is_root_agent(id: &str) -> bool {
    let parts: Vec<&str> = id.split(':').collect();
    parts.len() >= 3 && parts[0] == "agent" && parts[2] == "main"
}

fn is_guid_like(value: &str) -> bool {
    value.contains('-') && value.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn shorten_guid(value: &str) -> String {
    value.rsplit('-').next().unwrap_or(value).to_string()
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
        data.extend(std::iter::repeat_n(0, pad));
        data.extend(history.iter().copied());
        data
    }
}

fn extract_gateway_domain(connection: &str) -> String {
    if let Ok(url) = Url::parse(connection)
        && let Some(host) = url.host_str()
    {
        return host.to_string();
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

fn extract_display_text(value: &Value, cache: &mut HashMap<String, String>) -> Option<String> {
    let msg_type = value.get("type").and_then(|v| v.as_str());
    let event = value.get("event").and_then(|v| v.as_str());

    if msg_type == Some("event") && event == Some("agent") {
        let payload = value.get("payload")?;
        let stream = payload.get("stream").and_then(|v| v.as_str())?;
        if stream != "assistant" {
            return None;
        }
        let run_id = payload
            .get("runId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let key = format!("{run_id}:{stream}");
        let data = payload.get("data")?;

        if let Some(delta) = data.get("delta").and_then(|v| v.as_str())
            && !delta.is_empty()
        {
            let entry = cache.entry(key).or_default();
            entry.push_str(delta);
            return Some(delta.to_string());
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
    if app.show_help {
        render_help(frame, size);
    }
}

fn render_header(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let uptime = format_duration(app.start.elapsed());
    let title_style = Style::default().fg(NEON_HOT).add_modifier(Modifier::BOLD);
    let status_style = Style::default().fg(NEON);
    let gateway = extract_gateway_domain(&app.connection);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));
    let inner_width = block.inner(area).width as usize;
    let title_text = "OPENCLAW GATEWAY INTERFACE";
    let uptime_text = format!("uptime {uptime}");
    let all_style = if app.show_all_messages {
        Style::default().fg(NEON).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(DIM)
    };
    let help_text = "Ctrl-H Help";
    let left_len =
        title_text.chars().count() + 2 + gateway.chars().count() + 2 + uptime_text.chars().count();
    let right_len = 3 + 2 + help_text.chars().count();
    let pad = inner_width.saturating_sub(left_len + right_len).max(1);
    let header = Line::from(vec![
        Span::styled(title_text, title_style),
        Span::raw("  "),
        Span::styled(gateway, status_style),
        Span::raw("  "),
        Span::styled(uptime_text, Style::default().fg(DIM)),
        Span::raw(" ".repeat(pad)),
        Span::styled("ALL", all_style),
        Span::raw("  "),
        Span::styled(help_text, Style::default().fg(DIM)),
    ]);

    let status_line = Line::from(vec![
        Span::styled("STATUS: ", Style::default().fg(DIM)),
        Span::styled(app.status.clone(), Style::default().fg(NEON)),
        Span::raw("  "),
        Span::styled("CONN: ", Style::default().fg(DIM)),
        Span::styled(app.connection.clone(), Style::default().fg(NEON)),
    ]);

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
    let points: Vec<(f64, f64)> = data
        .iter()
        .enumerate()
        .map(|(idx, &val)| (idx as f64, val as f64))
        .collect();
    let max_val = data.iter().copied().max().unwrap_or(1).max(4) as f64 + 1.0;
    let axis_style = Style::default().fg(DIM);
    let datasets = vec![
        Dataset::default()
            .name("pulse")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(NEON))
            .data(&points),
    ];
    let chart = Chart::new(datasets)
        .block(block)
        .style(Style::default().bg(BG))
        .x_axis(
            Axis::default()
                .bounds([0.0, width.saturating_sub(1) as f64])
                .style(axis_style),
        )
        .y_axis(Axis::default().bounds([0.0, max_val]).style(axis_style));

    frame.render_widget(chart, area);
}

fn render_health(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let mut lines: Vec<Line> = Vec::new();
    let block = Block::default()
        .title(Span::styled(
            "GATEWAY HEALTH",
            Style::default().fg(NEON_HOT),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    let (health_label, health_style) = match app.gateway_health_ok {
        Some(true) => ("OK", Style::default().fg(NEON).add_modifier(Modifier::BOLD)),
        Some(false) => (
            "DEGRADED",
            Style::default().fg(ALERT).add_modifier(Modifier::BOLD),
        ),
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
                let connector = if idx + 1 == children.len() {
                    "└"
                } else {
                    "├"
                };
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
        if let Some(last) = app.transcript.get(end - 1)
            && last.text.is_empty()
        {
            end = end.saturating_sub(1);
            continue;
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
    let mut wrapped_lines: Vec<TranscriptEntry> = Vec::new();

    if wrap_width > 0 && visible_lines > 0 {
        for line in app.transcript.iter().take(end) {
            if line.text.is_empty() {
                wrapped_lines.push(TranscriptEntry {
                    text: String::new(),
                    tone: line.tone,
                });
                continue;
            }
            let mut buf = String::new();
            let mut count = 0usize;
            for ch in line.text.chars() {
                buf.push(ch);
                count += 1;
                if count >= wrap_width {
                    wrapped_lines.push(TranscriptEntry {
                        text: buf,
                        tone: line.tone,
                    });
                    buf = String::new();
                    count = 0;
                }
            }
            if !buf.is_empty() {
                wrapped_lines.push(TranscriptEntry {
                    text: buf,
                    tone: line.tone,
                });
            }
        }
    }

    let start = wrapped_lines.len().saturating_sub(visible_lines);
    let mut lines = Vec::new();
    for line in wrapped_lines.iter().skip(start) {
        let style = match line.tone {
            TranscriptTone::Default => Style::default().fg(NEON),
            TranscriptTone::User => Style::default().fg(NEON_HOT),
        };
        lines.push(Line::from(Span::styled(line.text.clone(), style)));
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
        Span::styled("[Enter] Send", Style::default().fg(DIM)),
        Span::raw("  "),
        Span::styled("[Esc] Clear", Style::default().fg(DIM)),
        Span::raw("  "),
        Span::styled("[Ctrl-U] Clear", Style::default().fg(DIM)),
        Span::raw("  "),
        Span::styled("[Ctrl-P] Pause", Style::default().fg(DIM)),
        Span::raw("  "),
        Span::styled("[Ctrl-A] All", all_style),
        Span::raw("  "),
        Span::styled("[Ctrl-H] Help", Style::default().fg(DIM)),
        Span::raw("  "),
        Span::styled("[Ctrl-D] Quit", Style::default().fg(DIM)),
    ]);

    let prompt_style = Style::default().fg(NEON_HOT).add_modifier(Modifier::BOLD);
    let input_text = if app.input.is_empty() {
        Span::styled(
            "Type a message for the main agent...",
            Style::default().fg(DIM),
        )
    } else {
        Span::styled(app.input.clone(), Style::default().fg(NEON))
    };
    let input_line = Line::from(vec![Span::styled("> ", prompt_style), input_text]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));
    let inner = block.inner(area);

    let text = Text::from(vec![input_line, help]);
    let paragraph = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
    let cursor_x = inner
        .x
        .saturating_add(2)
        .saturating_add(app.input.chars().count() as u16);
    let cursor_y = inner.y;
    if cursor_x < area.right().saturating_sub(1) {
        frame.set_cursor(cursor_x, cursor_y);
    }
}

fn render_help(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let popup = centered_rect(60, 60, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled("HELP", Style::default().fg(NEON_HOT)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .style(Style::default().bg(BG));

    let lines = vec![
        Line::from(Span::styled(
            "Keys",
            Style::default().fg(NEON).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Type to compose a message to session `main`",
            Style::default().fg(NEON),
        )),
        Line::from(Span::styled(
            "[Enter] Send message",
            Style::default().fg(NEON),
        )),
        Line::from(Span::styled("[Esc] Clear input", Style::default().fg(NEON))),
        Line::from(Span::styled(
            "[Ctrl-U] Clear input",
            Style::default().fg(NEON),
        )),
        Line::from(Span::styled("[Ctrl-D] Quit", Style::default().fg(NEON))),
        Line::from(Span::styled(
            "[Ctrl-P] Pause/Resume",
            Style::default().fg(NEON),
        )),
        Line::from(Span::styled(
            "[Ctrl-A] Toggle ALL messages",
            Style::default().fg(NEON),
        )),
        Line::from(Span::styled(
            "[Ctrl-H] Toggle Help",
            Style::default().fg(NEON),
        )),
    ];

    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, popup);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    let vertical = popup_layout[1];
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical);

    horizontal[1]
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
