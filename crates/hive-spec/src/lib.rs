//! Agent specs: types, parsing, validation.
//!
//! This crate does no I/O. It is the one thing every other crate depends on,
//! and the dependency direction is strictly downward into it.
//!
//! Nearly every validation rule here exists because the behaviour it prevents
//! was observed in production and cost real time to diagnose. Each one carries
//! the reason, and each has a test. They are not stylistic.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub mod validate;

pub use validate::{ValidationError, ValidationReport};

/// A complete agent definition. One TOML file per agent; files are the single
/// source of truth. Observed state (container ids, health) lives elsewhere and
/// is never written back here.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AgentSpec {
    pub identity: Identity,
    pub harness: Harness,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub resources: Resources,
    #[serde(default)]
    pub network: Network,
    /// MCP servers this agent should hold. Credentials are broker KEYS, never
    /// literal secrets — see [`Mcp::credential`].
    #[serde(default, rename = "mcp")]
    pub mcp: Vec<Mcp>,
    /// Credential FILES to place inside the container before it starts.
    ///
    /// For credentials with no environment-variable form — codex's `auth.json`
    /// being the one that matters, since its subscription auth cannot be
    /// expressed as an env var. Each names a broker key, never a literal secret,
    /// and lands inside the agent's own state volume.
    #[serde(default, rename = "file")]
    pub files: Vec<CredentialFile>,

    /// Extra volumes, for sharing a workspace between agents.
    ///
    /// The agent's own state volume is always mounted and is never shared.
    /// These are additional: two agents naming the same volume see the same
    /// files, which is how a Claude agent and a Codex agent can work on one tree
    /// while keeping separate skills, credentials and harness state.
    #[serde(default, rename = "volume")]
    pub volumes: Vec<SharedVolume>,

    /// Non-secret environment only. Validated against a deny-list.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CredentialFile {
    /// A *broker key* (e.g. `codex/auth`), never a literal secret.
    pub credential: String,
    /// Absolute path inside the container. Must be under the state volume, or
    /// the file is written to the container filesystem and destroyed on the next
    /// recreate — after which the agent silently reverts to unauthenticated.
    pub target: String,
    /// Octal, as a STRING so `0600` survives TOML instead of being read as the
    /// decimal integer 600 (which is 0o1130 — world-writable).
    #[serde(default = "default_file_mode")]
    pub mode: String,
}

fn default_file_mode() -> String {
    "0600".into()
}

impl CredentialFile {
    /// Parsed mode, falling back to 0600 rather than to something permissive.
    /// A typo must never widen access to a credential.
    pub fn mode_bits(&self) -> u32 {
        u32::from_str_radix(self.mode.trim_start_matches("0o"), 8).unwrap_or(0o600)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SharedVolume {
    /// Docker volume name. Agents naming the same volume share its contents.
    pub name: String,
    /// Absolute mount point inside the container.
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    /// Agent's Nostr public key (64 lowercase hex). The secret key lives in the
    /// broker under `nsec/<agent>` and never appears in a spec.
    pub pubkey: String,
    pub relay_url: String,
    /// Plain owner pubkey. Sets `BUZZ_ACP_AGENT_OWNER`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<String>,
    /// NIP-OA owner attestation (`["auth", owner, conditions, sig]`). Sets
    /// `BUZZ_AUTH_TAG`. Preferred over `owner_pubkey`: the agent then derives
    /// relay access from its owner's membership (NIP-AA virtual membership)
    /// rather than needing its own enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_tag: Option<String>,

    /// Broker key holding the secret key. Defaults to `nsec/<agent-name>`.
    ///
    /// Set it to put ONE identity on SEVERAL RELAYS. `buzz-acp` takes a scalar
    /// `BUZZ_RELAY_URL`, so the same agent in two communities is genuinely two
    /// processes and therefore two specs — but they are one identity, and the
    /// secret key should exist in exactly one place. Without this the key name
    /// follows the file name, and you would store the same private key twice
    /// under two names, where one copy inevitably goes stale on rotation.
    ///
    /// ```toml
    /// # uni.toml
    /// [identity]
    /// pubkey = "8f3c…"
    /// relay_url = "wss://home.example"
    ///
    /// # uni-other.toml — same pubkey, same key, different relay
    /// [identity]
    /// pubkey = "8f3c…"
    /// relay_url = "wss://other.example"
    /// credential = "nsec/uni"
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl Identity {
    /// The broker key holding this agent's secret key.
    pub fn credential_key(&self, agent: &str) -> String {
        self.credential.clone().unwrap_or_else(|| format!("nsec/{agent}"))
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Harness {
    /// Catalog id (`claude`, `codex`, `goose`, …). Resolved to a command and an
    /// image by the harness catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Escape hatch for a harness the catalog does not know: an explicit
    /// command, which requires an explicit image that contains it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Where this harness's MODEL credential comes from. Default `broker`.
    ///
    /// Not every harness authenticates with an environment variable. Codex's
    /// subscription auth is a JSON file with no env-var form at all; Claude and
    /// grok can be logged in interactively inside the container, where the
    /// credential lands in the state volume and never passes through hive.
    ///
    /// Without this hive would demand a `harness/<id>` broker key in every case
    /// and hold the agent forever waiting for a credential that is never going
    /// to exist — including, awkwardly, holding it so hard you cannot start the
    /// container to log in.
    #[serde(default)]
    pub auth: HarnessAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HarnessAuth {
    /// A `harness/<id>` key in the broker, delivered as an environment variable.
    #[default]
    Broker,
    /// A `[[file]]` entry supplies it — codex's `auth.json`. hive still checks
    /// that file's credential exists, so a missing one is caught.
    File,
    /// You log in inside the container (`hive shell --scratch <agent>`), and the
    /// credential lives in the state volume. hive requires nothing and cannot
    /// verify it — the agent will start and fail on its first turn if you have
    /// not logged in yet, which is the price of the flow.
    Interactive,
}

/// Whether an agent container connects to the relay itself, or is only a
/// sandbox something else drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// The container runs `buzz-acp` and holds the relay connection. Default,
    /// and the only mode that survives the desktop being closed.
    #[default]
    Relay,
    /// The container is a sandbox only; `hive-acp` execs the harness in from
    /// outside. Nothing in here talks to a relay.
    Environment,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AgentConfig {
    /// Whether this container holds its own relay connection.
    ///
    /// Default `relay`: the container runs `buzz-acp`, connects to the relay
    /// itself, and outlives any desktop. That is the standalone agent.
    ///
    /// `environment` is for the other topology — hive occupying Buzz's
    /// *harness* seam rather than its backend seam. There `buzz-acp` runs
    /// wherever the desktop runs and holds the identity, and `hive-acp` execs
    /// the harness into this container from outside. The container is then only
    /// a sandbox and must NOT run `buzz-acp` itself: it has no nsec, so it
    /// would crash-loop, and `docker exec` into a crash-looping container
    /// fails intermittently rather than cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AgentMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Harness-specific model id. NOT portable between harnesses: Claude
    /// advertises bare aliases (`opus`) and rejects `opus[1m]`, while Codex
    /// advertises bracketed ids (`gpt-5.6-sol[high]`) where the suffix is
    /// reasoning depth. Normalisation is therefore per-harness, in core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Who may trigger the agent: `owner-only` | `allowlist` | `anyone` | `nobody`.
    /// Gates *triggering*, not *content* — thread history authored by anyone is
    /// still pulled into the model's context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub respond_to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub respond_to_allowlist: Vec<String>,
    /// Maps to `BUZZ_ACP_IDLE_TIMEOUT`. Note: no `_SECONDS` suffix, and the
    /// older `BUZZ_ACP_TURN_TIMEOUT` name is deprecated upstream — it warns at
    /// startup and is easy to set for months without noticing it does nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_turn_duration: Option<u64>,
    /// Maps to `BUZZ_ACP_AGENTS` — the size of the in-process harness pool, so
    /// one slot per concurrent *channel*, not per subagent. Container count
    /// tracks agents × relays; this tracks conversations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// Publish NIP-AO observer frames so the desktop can watch the agent work.
    /// The harness defaults this OFF, which makes a remote agent function
    /// perfectly while appearing to do nothing — a local agent is observed over
    /// stdio, a container has no stdio to observe. Default on here.
    #[serde(default = "default_true")]
    pub observer: bool,
}

fn default_true() -> bool {
    true
}

// Hand-written rather than derived. `#[serde(default = "…")]` on a field only
// applies when the containing table EXISTS and omits it; when the whole
// `[agent]` section is absent serde calls `Default::default()`, and a derived
// impl would give `observer: false` — producing exactly the silently-invisible
// agent this field exists to prevent. Caught by a test, not by review.
impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            // None, not Some(Relay): an explicit value here would be written
            // back out on every serialize, putting `mode = "relay"` into specs
            // that never asked for it.
            mode: None,
            system_prompt: None,
            model: None,
            respond_to: None,
            respond_to_allowlist: Vec::new(),
            idle_timeout: None,
            max_turn_duration: None,
            parallelism: None,
            observer: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Resources {
    pub memory: String,
    pub cpus: f64,
    pub pids: i64,
}

impl Default for Resources {
    fn default() -> Self {
        // Deliberately roomier than one harness needs: an agent may shell out
        // to another harness (a Claude agent invoking codex), which puts a
        // second model process under the same cap.
        Self { memory: "3g".into(), cpus: 2.0, pids: 512 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProfile {
    /// Public internet on :443, the relay, and the broker socket. Nothing on
    /// the local network, no other agent, no other host port.
    #[default]
    Standard,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct Network {
    #[serde(default)]
    pub profile: NetworkProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpTransport {
    /// Remote MCP over HTTP. Credentials ride headers, supplied per-connection
    /// by the broker rather than written into the container.
    Http,
    /// Local MCP subprocess inside the container.
    Stdio,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Mcp {
    pub name: String,
    pub transport: McpTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// A *broker key* (e.g. `mcp/parachute`), never a literal secret. The
    /// broker resolves it at connection time; the value never lands in the
    /// container's environment or filesystem, so `docker inspect` cannot
    /// reveal it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl AgentSpec {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Stable hash of the spec, stamped onto the container as a label so the
    /// reconciler can tell "matches desired" from "needs replacing" without
    /// diffing container config field by field.
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        // Serialisation is deterministic: BTreeMap for env, Vec order preserved.
        let canonical = self.to_toml().unwrap_or_default();
        hex::encode(&Sha256::digest(canonical.as_bytes())[..16])
    }

    pub fn validate(&self) -> ValidationReport {
        validate::validate(self)
    }
}
