//! `hive-acp` — run an ACP harness inside a container, and get out of the way.
//!
//! # What this is for
//!
//! Buzz has two extension seams, and which one hive occupies decides a lot.
//!
//! As a **backend provider** ("where to run"), hive competes with Buzz's own
//! notion of location — which is why the desktop shim had to reimplement remote
//! deployment over ssh. As a **harness**, `harness=hive` composes with whatever
//! Buzz already does about location: local, a remote provider, or this box
//! acting as a provider for a laptop. Location stays Buzz's axis; the
//! environment becomes hive's.
//!
//! So this is a Tier-3 custom harness (BYOH, buzz v0.5.0). `buzz-acp` spawns it
//! exactly as it would spawn `claude-agent-acp`, and it speaks ACP on stdio.
//! Below, it runs the real harness inside that agent's container — with hive's
//! isolation, MCP servers and broker-held credentials already in place.
//!
//! # Why it intercepts exactly one method
//!
//! ACP's `McpServer` is a union — `McpServerHttp`, `McpServerSse`,
//! `McpServerAcp`, `McpServerStdio` — and the HTTP variant carries a `headers`
//! array. Buzz implements only the stdio one, which is why an HTTP MCP server
//! cannot be configured from the desktop. The protocol was never the limit.
//!
//! So `session/new` is rewritten on its way down: hive appends the agent's own
//! MCP servers, with credentials fetched from the broker, to whatever Buzz
//! sent. Verified against `claude-agent-acp`, which advertises
//! `mcpCapabilities {http, sse}` and duly listed every Parachute tool.
//!
//! That is worth doing here rather than by writing harness config files,
//! because it is protocol rather than per-harness plumbing: it works for any
//! harness advertising `mcpCapabilities.http`, not only the one whose config
//! format hive happens to know.
//!
//! **Everything else is copied verbatim, in both directions.** A proxy that
//! re-frames JSON-RPC it has no reason to read can corrupt a stream it was only
//! meant to carry, so anything that is not a `session/new` request — including
//! every response and notification coming back up — is passed through
//! untouched, and a line that does not parse as JSON is forwarded as bytes
//! rather than dropped.
//!
//! Routing between several backends, and switching harness mid-conversation,
//! would need real session bookkeeping. That is a different program.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use hive_core::harness::CATALOG;
use hive_spec::AgentSpec;

/// Locate the Docker CLI without trusting PATH.
///
/// This process is spawned by a GUI application. On macOS that means a minimal
/// launchd environment whose PATH does not include Homebrew — so `docker` is
/// simply not found, while the identical command works in the developer's
/// shell. Same list as `hive_core::docker::DockerBackend::discover`.
fn find_docker() -> String {
    for p in [
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/usr/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
    ] {
        if std::path::Path::new(p).is_file() {
            return p.to_string();
        }
    }
    "docker".to_string()
}

struct Config {
    agent: String,
    container: String,
    /// The harness entrypoint and its arguments, from hive's catalog.
    argv: Vec<String>,
    /// HTTP MCP servers from this agent's spec, injected at `session/new`.
    mcp: Vec<McpEntry>,
}

#[derive(Clone)]
struct McpEntry {
    name: String,
    url: String,
    /// Broker key. `None` for a server that needs no credential.
    credential: Option<String>,
}

/// Ask the broker for a server's headers, from inside the container.
///
/// The broker listens on a unix socket bind-mounted into the agent's container,
/// which this process — running on the host, possibly on the far side of a
/// Docker VM — cannot reach. `hive-headers` already lives in the image for
/// exactly this conversation, so it is reused rather than reimplemented: the
/// fetch stays grant-checked and audited, and there is one code path that talks
/// to the broker instead of two.
///
/// A failure is logged and the server is attached WITHOUT credentials rather
/// than dropped. An MCP server the agent can see and gets 401 from is a
/// diagnosable problem; a server that silently vanished is not.
fn fetch_headers(container: &str, server: &str) -> Vec<(String, String)> {
    let out = Command::new(find_docker())
        .args(["exec", "-e"])
        .arg(format!("CLAUDE_CODE_MCP_SERVER_NAME={server}"))
        .args([container, "hive-headers"])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            eprintln!(
                "hive-acp: no credentials for MCP server {server:?}: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return Vec::new();
        }
        Err(e) => {
            eprintln!("hive-acp: could not reach the broker for {server:?}: {e}");
            return Vec::new();
        }
    };
    let body = String::from_utf8_lossy(&out.stdout);
    // The helper prints `{"headers": {name: value, …}}` — the map is NESTED,
    // not the whole document. Parsing it flat yields zero headers and an MCP
    // server that 401s, with nothing in the logs to say why.
    let parsed: serde_json::Value = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hive-acp: broker returned unparseable headers for {server:?}: {e}");
            return Vec::new();
        }
    };
    let Some(map) = parsed.get("headers").and_then(|h| h.as_object()) else {
        eprintln!("hive-acp: broker response for {server:?} had no headers object");
        return Vec::new();
    };
    map.iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

/// Append this agent's MCP servers to a `session/new` request.
///
/// Returns `None` for anything that is not a `session/new` request, including
/// lines that are not JSON — the caller then forwards the original bytes.
///
/// Buzz's own `mcpServers` are preserved and hive's are appended, rather than
/// replaced: a stdio server configured in the desktop and an HTTP server
/// configured in hive are not alternatives, and silently dropping the former
/// would make hive's involvement look like a Buzz bug.
fn rewrite_session_new(line: &str, mcp: &[McpEntry], container: &str) -> Option<String> {
    inject(line, mcp, &|e: &McpEntry| match &e.credential {
        Some(_) => fetch_headers(container, &e.name),
        None => Vec::new(),
    })
}

/// The pure half: everything except talking to the broker.
///
/// Split out so the rewrite can be tested without Docker — the parts most
/// likely to be wrong are the passthrough conditions, not the header fetch.
fn inject(
    line: &str,
    mcp: &[McpEntry],
    headers_for: &dyn Fn(&McpEntry) -> Vec<(String, String)>,
) -> Option<String> {
    if mcp.is_empty() {
        return None;
    }
    let mut msg: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if msg.get("method")?.as_str()? != "session/new" {
        return None;
    }
    let params = msg.get_mut("params")?.as_object_mut()?;
    let servers = params
        .entry("mcpServers")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()?;

    for e in mcp {
        let headers: Vec<serde_json::Value> = headers_for(e)
            .into_iter()
            .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
            .collect();
        // `type: "http"` selects the McpServerHttp variant of ACP's McpServer
        // union. `headers` is required by the schema even when empty.
        servers.push(serde_json::json!({
            "type": "http",
            "name": e.name,
            "url": e.url,
            "headers": headers,
        }));
        eprintln!("hive-acp: attached MCP server {} -> {}", e.name, e.url);
    }
    let mut s = msg.to_string();
    s.push('\n');
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> McpEntry {
        McpEntry {
            name: name.into(),
            url: format!("https://vault.example/{name}/mcp"),
            credential: Some(format!("mcp/{name}")),
        }
    }
    fn creds(_: &McpEntry) -> Vec<(String, String)> {
        vec![("Authorization".into(), "Bearer TOKEN".into())]
    }
    fn none(_: &McpEntry) -> Vec<(String, String)> {
        Vec::new()
    }

    #[test]
    fn only_session_new_is_touched() {
        // Everything else — prompts, cancels, and every response coming back —
        // must reach the far side byte-for-byte. Rewriting a message this
        // program has no reason to read is how a proxy corrupts a stream it was
        // only meant to carry.
        let e = [entry("parachute")];
        for line in [
            r#"{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"s"}}"#,
        ] {
            assert!(inject(line, &e, &none).is_none(), "rewrote: {line}");
        }
    }

    #[test]
    fn a_line_that_is_not_json_is_passed_through_rather_than_dropped() {
        // ACP framing is not something to assume. If messages ever stop being
        // newline-delimited, this must degrade to a transparent pipe instead of
        // silently swallowing traffic.
        assert!(inject("not json at all", &[entry("p")], &none).is_none());
        assert!(inject("", &[entry("p")], &none).is_none());
    }

    #[test]
    fn an_agent_with_no_mcp_servers_is_never_rewritten() {
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"mcpServers":[]}}"#;
        assert!(inject(line, &[], &creds).is_none());
    }

    #[test]
    fn the_clients_own_mcp_servers_are_kept_and_hives_are_appended() {
        // A stdio server configured in Buzz and an HTTP server configured in
        // hive are not alternatives. Dropping the client's would look like a
        // Buzz bug rather than something hive did.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/w","mcpServers":[{"name":"buzzy","command":"x","args":[],"env":[]}]}}"#;
        let out = inject(line, &[entry("parachute")], &creds).expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let servers = v["params"]["mcpServers"].as_array().unwrap();
        assert_eq!(servers.len(), 2, "{out}");
        assert_eq!(servers[0]["name"], "buzzy");
        assert_eq!(servers[1]["name"], "parachute");
        assert_eq!(servers[1]["type"], "http");
        assert_eq!(v["params"]["cwd"], "/w", "unrelated params must survive");
    }

    #[test]
    fn the_injected_server_matches_the_mcpserverhttp_variant() {
        // ACP selects the variant by `type`, and `headers` is required by the
        // schema even when empty. Emitting the stdio shape here means the
        // harness never reaches the server at all.
        let out = inject(
            r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}"#,
            &[entry("parachute")],
            &creds,
        )
        .expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let s = &v["params"]["mcpServers"][0];
        assert_eq!(s["type"], "http");
        assert_eq!(s["url"], "https://vault.example/parachute/mcp");
        assert_eq!(s["headers"][0]["name"], "Authorization");
        assert_eq!(s["headers"][0]["value"], "Bearer TOKEN");
    }

    #[test]
    fn a_server_whose_credential_cannot_be_fetched_is_still_attached() {
        // Attached-and-401 is diagnosable; silently absent is not. The agent
        // reports an authorization failure naming the server, which points at
        // the broker rather than at a mystery.
        let out = inject(
            r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}"#,
            &[entry("parachute")],
            &none,
        )
        .expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["params"]["mcpServers"][0]["name"], "parachute");
        assert!(v["params"]["mcpServers"][0]["headers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn the_rewritten_line_stays_newline_terminated() {
        // The child reads line-delimited JSON. Dropping the terminator makes
        // the harness wait for the rest of a message that already arrived.
        let out = inject(
            r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}"#,
            &[entry("p")],
            &none,
        )
        .expect("rewritten");
        assert!(out.ends_with('\n'), "{out:?}");
    }
}

/// Resolve everything from the agent name plus its spec.
///
/// The harness is read from the spec rather than from an environment variable
/// because the spec is what hived reconciled the container from. Taking it from
/// the environment would let the two disagree — and the symptom would be a
/// harness that starts, answers `initialize`, and has none of the credentials
/// the container was built for.
fn resolve() -> Result<Config> {
    let agent = std::env::var("HIVE_AGENT").ok().filter(|s| !s.is_empty()).context(
        "HIVE_AGENT is not set. hive-acp runs one specific agent's harness; set it in the \
         harness definition's env, or per-agent in Buzz's agent environment variables.",
    )?;

    let spec_dir =
        std::env::var("HIVE_SPEC_DIR").unwrap_or_else(|_| "/etc/hive/agents".to_string());
    let path = std::path::Path::new(&spec_dir).join(format!("{agent}.toml"));

    // Read the spec locally when it is there, and through the daemon container
    // when it is not.
    //
    // Where hived runs in a container — which on macOS and Windows it must,
    // because the broker's unix sockets cannot cross the Docker VM boundary —
    // the spec directory is a volume this process cannot see. Requiring the
    // operator to bind-mount it onto the host as well would mean two sources of
    // truth for the same file, and the one this program read would be the one
    // nobody edited.
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(local_err) => {
            let daemon =
                std::env::var("HIVE_DAEMON_CONTAINER").unwrap_or_else(|_| "hived".to_string());
            let out = Command::new(find_docker())
                .args(["exec", &daemon, "cat"])
                .arg(&path)
                .output()
                .with_context(|| format!("reading {} via {daemon}", path.display()))?;
            if !out.status.success() {
                bail!(
                    "cannot read {}: locally {local_err}; via container {daemon}: {}. \
                     Has this agent been deployed? `hive status`",
                    path.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            String::from_utf8(out.stdout).context("spec was not valid UTF-8")?
        }
    };
    let spec: AgentSpec =
        toml::from_str(&text).with_context(|| format!("{} is not a valid agent spec", path.display()))?;

    // A spec names either a catalog id or an explicit command. The escape hatch
    // is honoured here too: a harness the catalog does not know still runs, it
    // just brings its own image, and refusing it would make hive-acp stricter
    // than hived about the very same spec.
    let argv: Vec<String> = match (&spec.harness.id, &spec.harness.command) {
        (Some(id), _) => {
            let def = CATALOG.iter().find(|h| h.id == id.as_str()).with_context(|| {
                format!(
                    "{agent} names harness {id:?}, which is not in hive's catalog. \
                     `hive harnesses` lists the ids this build knows."
                )
            })?;
            if let Some(reason) = &def.unsupported {
                bail!("harness {id:?} is deliberately absent from the image: {reason:?}");
            }
            let mut v = vec![def.command.to_string()];
            v.extend(def.args.iter().map(|s| s.to_string()));
            v
        }
        (None, Some(cmd)) => cmd.split_whitespace().map(String::from).collect(),
        (None, None) => bail!(
            "{agent} names neither [harness].id nor [harness].command, so there is nothing to run"
        ),
    };

    // Only HTTP servers are attached over ACP. A stdio server in a spec is
    // hived's business — it is spawned inside the container — and duplicating
    // it here would start a second copy.
    let mcp = spec
        .mcp
        .iter()
        .filter(|m| m.url.is_some())
        .map(|m| McpEntry {
            name: m.name.clone(),
            url: m.url.clone().unwrap_or_default(),
            credential: m.credential.clone(),
        })
        .collect();

    Ok(Config {
        container: std::env::var("HIVE_CONTAINER").unwrap_or_else(|_| format!("hive-{agent}")),
        agent,
        argv,
        mcp,
    })
}

fn main() -> Result<()> {
    // stderr, never stdout: stdout is the ACP channel and one stray line of
    // logging corrupts the stream. The failure looks like a harness that
    // connects and then ignores everything.
    let cfg = match resolve() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hive-acp: {e:#}");
            std::process::exit(78); // EX_CONFIG
        }
    };

    eprintln!(
        "hive-acp: agent={} container={} harness={}",
        cfg.agent,
        cfg.container,
        cfg.argv.join(" ")
    );

    // -i, no -t. There is no terminal here, and `docker exec -t` fails outright
    // when stdin is a pipe — which it always is, because buzz-acp owns it.
    let mut cmd = Command::new(find_docker());
    cmd.arg("exec").arg("-i");
    // Forward the environment buzz-acp set for this harness. That is how the
    // relay URL, the agent's identity and Buzz's per-agent settings reach the
    // harness; without it the harness starts unconfigured and idles.
    for (k, v) in std::env::vars() {
        if k.starts_with("BUZZ_") || k.starts_with("ACP_") {
            cmd.arg("-e").arg(format!("{k}={v}"));
        }
    }
    cmd.arg(&cfg.container);
    cmd.args(&cfg.argv);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "starting the harness in {}. Is the container running? `hive status`",
                cfg.container
            )
        })?;

    let mut to_child = child.stdin.take().context("child stdin")?;
    let mut from_child = child.stdout.take().context("child stdout")?;

    // Two directions, two threads, raw bytes. Copying in fixed chunks rather
    // than by line: a line-oriented copy would block a partial message until a
    // newline arrived, which stalls a streaming `session/update` mid-token.
    let up = std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        let mut out = std::io::stdout().lock();
        loop {
            match from_child.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.write_all(&buf[..n]).is_err() || out.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mcp = cfg.mcp.clone();
    let container = cfg.container.clone();
    let down = std::thread::spawn(move || {
        // Line-oriented only in this direction, and only to find `session/new`.
        // A line that is not JSON, or is any other method, is written through
        // byte-for-byte — so a framing change or an unknown method degrades to
        // the transparent behaviour rather than to a corrupted stream.
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let out = match rewrite_session_new(&line, &mcp, &container) {
                Some(modified) => modified,
                None => line.clone(),
            };
            if to_child.write_all(out.as_bytes()).is_err() || to_child.flush().is_err() {
                break;
            }
        }
        // Closing the child's stdin is what tells the harness the client is
        // gone. Without it the harness waits for input that will never come and
        // has to be killed rather than exiting.
        drop(to_child);
    });

    let status = child.wait().context("waiting for the harness")?;
    let _ = up.join();
    // The downstream thread is parked in a blocking read on our own stdin and
    // only unblocks when the parent closes it. Not joined: waiting for it would
    // hang this process after the harness has already exited.
    drop(down);

    // Propagate rather than flattening. buzz-acp distinguishes a harness that
    // exited cleanly from one that crashed, and reporting 0 for a crash makes a
    // crash-looping agent look like a healthy one that keeps finishing.
    std::process::exit(status.code().unwrap_or(1));
}
