import { hasRole, type User } from "../api";
import { PageHeader } from "../ui";

export default function Help({ user }: { user: User }) {
  return (
    <div className="page help">
      <PageHeader title="Help" subtitle="How to use Logstash Explorer." />
      <nav className="toc">
        <a href="#workspace">Workspace</a>
        <a href="#inputs">Input data</a>
        <a href="#library">Parser library</a>
        <a href="#fields">Input fields</a>
        <a href="#config">Configuration</a>
        <a href="#projects">Projects & sharing</a>
        <a href="#syslog">Syslog output</a>
        <a href="#agent">Autonomous agent</a>
        <a href="#mcp">MCP clients</a>
        <a href="#security">Account security</a>
        {hasRole(user, "admin") && <a href="#admin">Administration</a>}
      </nav>

      <section id="workspace" className="card">
        <h2>Workspace</h2>
        <p>The main screen is split into three synchronized panels:</p>
        <ul>
          <li>
            <strong>Left — source logs</strong>: the raw events fed to Logstash (one line = one event, or JSON lines).
          </li>
          <li>
            <strong>Center — logstash.conf</strong>: your configuration. <code>filter</code> sections are executed; the{" "}
            <code>input</code> is replaced by the test harness (stdin); among the <code>output</code> sections, only{" "}
            <code>syslog</code> outputs are executed (towards a local capture), the others are ignored. JSON events are
            always displayed.
          </li>
          <li>
            <strong>Right — output</strong>: the events actually produced by Logstash, the execution logs and the agent
            timeline.
          </li>
        </ul>
        <p>
          Run with <kbd>Ctrl</kbd>+<kbd>Enter</kbd> or the “Run” button. The “Auto-run” option re-runs Logstash after each
          change (every run starts an ephemeral instance: allow a few seconds). Syntax errors are underlined directly in the
          editor.
        </p>
      </section>

      <section id="inputs" className="card">
        <h2>Input data</h2>
        <ul>
          <li>Type or paste into the left panel.</li>
          <li>Drag and drop or the “File…” button: .log, .txt, .csv (text), .json (object or array), .jsonl / .ndjson.</li>
          <li>
            <strong>Windows .evtx logs</strong>: automatically converted to JSON on the server (one event per record); the
            format switches to “JSON lines”.
          </li>
          <li>
            In JSON lines mode, fields are already decoded at the root of the event: no need to add a <code>json</code>{" "}
            filter.
          </li>
        </ul>
      </section>

      <section id="library" className="card">
        <h2>Parser library</h2>
        <ul>
          <li>
            Ready-made filters for the formats most seen in companies: Windows (Security, Sysmon, PowerShell, any EVTX
            channel, NXLog), web servers and proxies (Apache/Nginx, IIS, Squid, HAProxy), network and security devices
            (Cisco ASA, FortiGate, Palo Alto, Check Point, Stormshield, CEF, LEEF), Linux (syslog RFC 3164/5424,
            auth.log, auditd), generic JSON / key=value / CSV, and industrial protocols (Zeek Modbus, DNP3, S7comm, OT
            alerts in CEF).
          </li>
          <li>
            As soon as source logs are loaded, the format is detected: a banner offers the matching parser. The
            “Library” button lists every parser, matching ones first, with their filter, sample and produced fields.
          </li>
          <li>
            Every filter maps to ECS field names and works with the pipeline's ECS compatibility on or off. Samples are
            synthetic: check the result on your own logs and adapt the filter.
          </li>
          <li>The AI agent is given the matching parser as a starting point when it recognises your sample.</li>
        </ul>
      </section>

      <section id="fields" className="card">
        <h2>Input fields</h2>
        <p>
          Some pipelines rely on what the input adds to each event — typically the source file path, from which a host or
          an application name is extracted. Declare these fields in the “Input fields” tab of the left panel (e.g.{" "}
          <code>[log][file][path]</code> = <code>/var/log/apache2/srv-web01/access.log</code>): the test harness sets them
          on every event before your filters, exactly like the <code>file</code> input. With ECS compatibility disabled,
          the file input writes <code>path</code> instead. Input fields are saved with the project and given to the agent.
        </p>
      </section>

      <section id="config" className="card">
        <h2>Configuration and restrictions</h2>
        <p>For security reasons, Logstash runs in an isolated sandbox (no network, no privileges). The following are rejected:</p>
        <ul>
          <li>
            the <code>ruby</code> and <code>exec</code> plugins and every network or database plugin;
          </li>
          <li>
            <code>{"${VAR}"}</code> references (environment variables / keystore);
          </li>
          <li>
            file access options (<code>patterns_dir</code>, <code>dictionary_path</code>, <code>path</code>…).
          </li>
        </ul>
        <p>
          Allowed plugins: grok, dissect, kv, csv, json, xml, date, mutate, drop, split, clone, fingerprint, geoip,
          useragent, cidr, urldecode, de_dot, prune, truncate, uuid, syslog_pri, translate (inline dictionary), aggregate,
          throttle, metrics, json_encode, bytes, age.
        </p>
        <p>Saved configurations (and their samples) are encrypted at rest.</p>
      </section>

      <section id="projects" className="card">
        <h2>Projects, duplication and sharing</h2>
        <ul>
          <li>
            A project stores the configuration, sample logs, instructions and expected output (encrypted at rest). Its
            address (<code>/?project=…</code>) can be opened in several tabs or sent to a colleague who has access.
          </li>
          <li>
            <strong>Duplicate</strong> creates a personal copy (including your unsaved changes), even from a project shared
            read-only.
          </li>
          <li>
            <strong>Share</strong> (owner only): <em>Read</em> = open, run, duplicate; <em>Write</em> = save as well. Only
            the owner renames, shares or deletes.
          </li>
          <li>
            <strong>Group sharing</strong>: with an LDAPS/SSO account, share with a directory group you belong to (your
            team). All its members get access; the highest right between personal and group shares applies. Your groups are
            listed in your profile.
          </li>
          <li>
            Concurrent editing: every save increments a version. If a colleague saved in the meantime, a banner offers to
            reload, save a copy or overwrite (an audited action). A banner also warns you while editing as soon as a new
            version is published.
          </li>
          <li>
            Concurrent sessions: several colleagues and several tabs work in parallel. Each person may have 2 simultaneous
            Logstash runs (manual runs and agent sessions combined).
          </li>
        </ul>
      </section>

      <section id="syslog" className="card">
        <h2>Checking a syslog output (rsyslog)</h2>
        <ol>
          <li>
            Click <strong>+ Syslog output</strong> above the editor, or paste your production{" "}
            <code>output {"{ syslog { … } }"}</code> block as is.
          </li>
          <li>
            On run, Logstash really executes this block. Only <code>host</code>, <code>port</code>,{" "}
            <code>protocol</code> and the TLS options are redirected to a local capture: the captured bytes are exactly
            those that would reach rsyslog.
          </li>
          <li>
            The <strong>Syslog</strong> tab shows each raw frame (␊ = end of frame), its decoding according to rsyslog
            properties (facility, severity, hostname, app-name, msgid, structured-data, msg) and RFC 5424 / 3164 anomalies.
          </li>
        </ol>
        <p>Pitfalls detected automatically:</p>
        <ul>
          <li>
            <code>facility =&gt; "local0"</code> to <code>"local7"</code>, <code>ftp</code>, <code>ntp</code>…: the plugin
            encodes them with the wrong number (local0 → 14 “alert” instead of 16). Suggested workaround:{" "}
            <code>use_labels =&gt; false</code> + a numeric <code>priority</code>.
          </li>
          <li>Unknown facility/severity labels (silent fallback to user-level/notice).</li>
          <li>
            Unresolved or object hostname/app-name field (e.g. <code>%{"{host}"}</code> with ECS v8 → use{" "}
            <code>%{"{[host][hostname]}"}</code>).
          </li>
          <li>
            Malformed structured-data (in a Logstash config, <code>\"</code> is not an escape: use single quotes around the
            value).
          </li>
          <li>RFC 3164 timestamp without time zone (Logstash writes UTC), messages too long for rsyslog (8 KB by default).</li>
        </ul>
      </section>

      <section id="agent" className="card">
        <h2>Autonomous agent {hasRole(user, "advanced") ? "" : "(“Advanced user” role required)"}</h2>
        <ol>
          <li>Load representative sample logs in the left panel.</li>
          <li>
            Open the <strong>AI agent</strong> tab and describe the business need, for example: “Write a grok to extract the
            client IP, parse the Apache timestamp and ignore internal requests”.
          </li>
          <li>
            Optional: provide the expected output (JSON or JSON lines). Only the listed fields are compared;{" "}
            <code>"*"</code> means “present, any value”.
          </li>
          <li>
            The agent writes a draft, runs it, reads Logstash errors and <code>_grokparsefailure</code>,{" "}
            <code>_dateparsefailure</code>… tags, compares with the expected output, then fixes it in a loop until it
            validates or the maximum number of iterations is reached.
          </li>
          <li>Each proposal appears in the “Agent” tab on the right and can be re-applied to the editor.</li>
        </ol>
        <p className="muted">
          Logs sent to the agent are transmitted to the LLM provider configured by the administrator (local Ollama or
          OpenAI API). Do not use sensitive data with an external provider without approval.
        </p>
      </section>

      <section id="mcp" className="card">
        <h2>MCP clients (Claude Code, Claude Desktop, VS Code…)</h2>
        <ul>
          <li>
            In “Profile &amp; MCP”, generate a dedicated token and copy the ready-made configuration for your client. The
            assistant acts as you: it only reaches your projects and those shared with you, with your role.
          </li>
          <li>
            A <em>read-only</em> token can list and open projects, run configurations and use the parser library; a{" "}
            <em>read &amp; write</em> token can also create and save projects and run the agent. Deletion, sharing and
            administration are never exposed.
          </li>
          <li>Every MCP call is recorded in the audit trail; tokens can be revoked at any time.</li>
        </ul>
      </section>

      <section id="security" className="card">
        <h2>Account security</h2>
        <ul>
          <li>Enable two-factor authentication (TOTP app and/or FIDO2 security key) from your profile.</li>
          <li>After 5 failed logins, the account is locked for 15 minutes.</li>
          <li>Changing your password closes all your other sessions.</li>
          <li>
            API tokens are displayed only once, always expire and are used with the{" "}
            <code>Authorization: Bearer lsx_…</code> header.
          </li>
        </ul>
      </section>

      {hasRole(user, "admin") && (
        <section id="admin" className="card">
          <h2>Administration</h2>
          <h3>Roles</h3>
          <ul>
            <li>
              <strong>User</strong>: run and save configurations.
            </li>
            <li>
              <strong>Advanced user</strong>: + autonomous AI agent.
            </li>
            <li>
              <strong>Administrator</strong>: + account management, settings, PKI and audit.
            </li>
          </ul>
          <h3>Accounts</h3>
          <ul>
            <li>
              The initial <code>admin</code> account must change its password at first login.
            </li>
            <li>New accounts receive a temporary password, displayed once, to be changed at first login.</li>
            <li>Service accounts have no password: they use revocable API tokens.</li>
            <li>Accounts inactive for 90 days (except administrators and service accounts) are disabled automatically.</li>
          </ul>
          <h3>SSO (OIDC) and LDAPS</h3>
          <ul>
            <li>Configured in “Directory &amp; SSO”, with connection tests (OIDC discovery, LDAPS bind and user lookup).</li>
            <li>With auto-provisioning disabled, new accounts arrive “pending” and are approved from the overview.</li>
            <li>Directory groups are mapped to roles in “Directory &amp; SSO”.</li>
          </ul>
          <h3>Logs, audit and backups</h3>
          <ul>
            <li>Every critical action (logins, rights, exports, configuration) is recorded with IP and user.</li>
            <li>Masking of personal data in logs is controlled in “Logs &amp; syslog”.</li>
            <li>
              Logs and the audit trail can be forwarded to a remote syslog server (UDP, TCP or TLS with optional client
              certificate) from “Logs &amp; syslog”; use “Send a test message” to check the connection.
            </li>
            <li>
              An encrypted database backup is produced every night in the <code>backups</code> volume (decryption:{" "}
              <code>python -m app.cli decrypt-backup</code>).
            </li>
          </ul>
        </section>
      )}
    </div>
  );
}
