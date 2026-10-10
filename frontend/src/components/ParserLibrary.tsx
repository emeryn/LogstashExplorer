import { useEffect, useMemo, useState } from "react";

import { get, type Parser, type ParserCategory, type ParserSummary } from "../api";
import { CopyButton, Empty, Icon, Modal, PageHeader, RichText, type IconName } from "../ui";

interface Catalog {
  categories: { id: ParserCategory; label: string }[];
  parsers: ParserSummary[];
}

type OnUse = (parser: Parser, withSample: boolean) => void;

const CATEGORY_ICON: Record<ParserCategory, IconName> = {
  windows: "monitor",
  cloud: "cloud",
  web: "network",
  network: "shield",
  system: "terminal",
  apps: "database",
  industrial: "settings",
};

function Browser({ onUse, suggested = [] }: { onUse: OnUse; suggested?: ParserSummary[] }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [category, setCategory] = useState<ParserCategory | "all" | "suggested">(suggested.length ? "suggested" : "all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(suggested[0]?.id ?? null);
  const [selected, setSelected] = useState<Parser | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    get<Catalog>("/api/parsers")
      .then(setCatalog)
      .catch(() => setError("The parser library could not be loaded."));
  }, []);

  const list = useMemo(() => {
    if (!catalog) return [];
    const q = query.trim().toLowerCase();
    const base =
      category === "suggested"
        ? suggested
        : catalog.parsers.filter((p) => category === "all" || p.category === category);
    return base.filter(
      (p) =>
        !q ||
        p.name.toLowerCase().includes(q) ||
        p.vendor.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q),
    );
  }, [catalog, category, query, suggested]);

  useEffect(() => {
    if (!selectedId && list.length) setSelectedId(list[0].id);
  }, [list, selectedId]);

  useEffect(() => {
    if (!selectedId) return setSelected(null);
    let alive = true;
    get<Parser>(`/api/parsers/${selectedId}`)
      .then((p) => alive && setSelected(p))
      .catch(() => alive && setSelected(null));
    return () => {
      alive = false;
    };
  }, [selectedId]);

  if (error) return <div className="alert error">{error}</div>;
  if (!catalog) return <div className="center muted">Loading…</div>;
  const count = (c: ParserCategory) => catalog.parsers.filter((p) => p.category === c).length;

  return (
    <>
      <div className="library">
        <nav className="library-cats">
          {suggested.length > 0 && (
            <button className={category === "suggested" ? "active" : ""} onClick={() => setCategory("suggested")}>
              <Icon name="wand" /> <span className="cat-label">Matches your sample</span> <span className="badge accent">{suggested.length}</span>
            </button>
          )}
          <button className={category === "all" ? "active" : ""} onClick={() => setCategory("all")}>
            <Icon name="list" /> <span className="cat-label">All parsers</span> <span className="badge">{catalog.parsers.length}</span>
          </button>
          {catalog.categories.map((c) => (
            <button key={c.id} className={category === c.id ? "active" : ""} onClick={() => setCategory(c.id)}>
              <Icon name={CATEGORY_ICON[c.id]} />
              <span className="cat-label">{c.label}</span> <span className="badge">{count(c.id)}</span>
            </button>
          ))}
        </nav>
        <div className="library-list">
          <div className="toolbar-search">
            <Icon name="search" />
            <input placeholder="Search name, vendor, format…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          {list.map((p) => (
            <button
              key={p.id}
              className={`parser-item ${p.id === selectedId ? "active" : ""}`}
              onClick={() => setSelectedId(p.id)}
            >
              <span className="row tight" style={{ justifyContent: "space-between" }}>
                <span className="name">{p.name}</span>
                {p.score !== undefined && <span className="badge accent">{Math.round(p.score * 100)}%</span>}
              </span>
              <span className="vendor">{p.vendor}</span>
            </button>
          ))}
          {!list.length && <Empty icon="search">No parser matches.</Empty>}
        </div>
        <div className="library-detail">
          {selected ? (
            <div className="stack">
              <div>
                <div className="row">
                  <span className="badge">{selected.category_label}</span>
                  <span className="badge info">{selected.input_format === "json" ? "JSON lines input" : "Line input"}</span>
                </div>
                <h2 style={{ marginTop: 10, fontSize: 18 }}>{selected.name}</h2>
                <div className="muted small">{selected.vendor}</div>
              </div>
              <p>
                <RichText text={selected.description} />
              </p>
              {selected.notes && (
                <div className="alert info">
                  <RichText text={selected.notes} />
                </div>
              )}
              <div>
                <h3>Produced fields</h3>
                <div className="field-chips">
                  {selected.fields.map((f) => (
                    <code key={f}>{f}</code>
                  ))}
                </div>
              </div>
              <div>
                <div className="row">
                  <h3 style={{ marginRight: "auto" }}>Filter</h3>
                  <CopyButton text={selected.filter} />
                </div>
                <pre>{selected.filter}</pre>
              </div>
              {Object.keys(selected.input_fields).length > 0 && (
                <div>
                  <h3>Input fields used by this parser</h3>
                  <table className="table dense">
                    <tbody>
                      {Object.entries(selected.input_fields).map(([k, v]) => (
                        <tr key={k}>
                          <td>
                            <code>{k}</code>
                          </td>
                          <td className="mono small">{v}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div>
                <h3>Sample ({selected.sample.split("\n").length} lines, synthetic)</h3>
                <pre>{selected.sample}</pre>
              </div>
            </div>
          ) : (
            <Empty icon="library">Select a parser to see its filter and sample.</Empty>
          )}
        </div>
      </div>
      <div className="library-foot">
        <span className="muted small" style={{ marginRight: "auto", alignSelf: "center" }}>
          Every parser is checked against its sample in a real Logstash, with and without ECS compatibility.
        </span>
        <button disabled={!selected} onClick={() => selected && onUse(selected, true)}>
          <Icon name="file" /> Use filter + sample
        </button>
        <button className="primary" disabled={!selected} onClick={() => selected && onUse(selected, false)}>
          <Icon name="check" /> Use this filter
        </button>
      </div>
    </>
  );
}

/** Full page (sidebar entry). */
export default function Library({ onUse }: { onUse: OnUse }) {
  return (
    <div className="page" style={{ maxWidth: "none", height: "100%", display: "flex", flexDirection: "column" }}>
      <PageHeader
        title="Parser library"
        subtitle="Ready-made Logstash filters for the formats most seen in companies — Windows, cloud & SaaS, web servers, firewalls and IDS, Linux and legacy Unix, databases and industrial protocols."
      />
      <div className="card" style={{ padding: 0, flex: 1, display: "flex", flexDirection: "column", minHeight: 520, overflow: "hidden" }}>
        <Browser onUse={onUse} />
      </div>
    </div>
  );
}

/** Dialog opened from the workspace, with the formats detected in the current sample first. */
export function ParserLibraryDialog({
  onUse,
  onClose,
  suggested,
}: {
  onUse: OnUse;
  onClose: () => void;
  suggested: ParserSummary[];
}) {
  return (
    <Modal title="Parser library" onClose={onClose} wide>
      <div className="modal-head" style={{ padding: "16px 18px 0", marginBottom: 12 }}>
        <Icon name="library" />
        <h2>Parser library</h2>
        <button className="ghost icon-only close" onClick={onClose} aria-label="Close">
          <Icon name="x" />
        </button>
      </div>
      <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", borderTop: "1px solid var(--border)" }}>
        <Browser onUse={onUse} suggested={suggested} />
      </div>
    </Modal>
  );
}
