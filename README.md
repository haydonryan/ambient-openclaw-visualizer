# OpenClaw Gateway Visualizer

Cyberpunk TUI for monitoring OpenClaw gateway traffic in real time.

![OpenClaw Gateway Visualizer](assets/openclaw-gateway-visualizer.png)

## Quick start

```sh
cargo run -- --gateway wss://your-gateway --token YOUR_TOKEN
```

Use demo data without a gateway:

```sh
cargo run -- --demo
```

Read newline-delimited events from stdin:

```sh
tail -f events.ndjson | cargo run -- --stdin
```

## Configuration

Environment variables are read from `.env` and the process environment. CLI flags override env values.

| Variable | Purpose |
| --- | --- |
| `openclaw-endpoint` / `OPENCLAW_ENDPOINT` | WebSocket gateway URL (default `ws://127.0.0.1:9001`) |
| `openclaw-token` / `OPENCLAW_TOKEN` / `openclaw-gateway-token` / `OPENCLAW_GATEWAY_TOKEN` | Auth token for the gateway |
| `openclaw-insecure-tls` / `OPENCLAW_INSECURE_TLS` | Allow invalid TLS certificates (`true`/`false`) |

## CLI flags

- `--gateway` WebSocket gateway URL
- `--token` Auth token for the gateway
- `--insecure-tls` Allow invalid TLS certificates (self-signed)
- `--debug` Echo connection status to stderr
- `--stdin` Read newline-delimited events from stdin
- `--demo` Run with synthetic traffic

## Controls

- Type in the footer to compose a message for the `main` agent session
- `Enter` Send the current message
- `Esc` Clear the current message
- `Ctrl-U` Clear the current message
- `Ctrl-P` Pause
- `Ctrl-A` Toggle all messages
- `Ctrl-H` Toggle help
- `Ctrl-D` Quit

## Build

```sh
cargo build --release
```

## Development

Enable the repo's pre-commit hook to run `just pre-commit` before each commit:

```bash
git config core.hooksPath .githooks
```

You can run the same suite manually with:

```bash
just pre-commit
```
