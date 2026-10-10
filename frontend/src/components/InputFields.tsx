import type { InputFields } from "../api";
import { Icon } from "../ui";

// Same rules as the backend / runner (app.core.input_fields).
const NAME = /^(?:\[[A-Za-z0-9_@.-]{1,64}\]){1,6}$|^[A-Za-z0-9_@.-]{1,64}$/;

export function fieldError(name: string, value: string): string | null {
  if (!name) return "name required";
  if (!NAME.test(name)) return "use a field reference such as [log][file][path]";
  if (/["\r\n]/.test(value) || value.endsWith("\\") || value.includes("%{")) {
    return 'no double quote, newline, trailing "\\" or %{…}';
  }
  return null;
}

export type FieldRow = { name: string; value: string };

export const toRows = (fields: InputFields | null | undefined): FieldRow[] =>
  Object.entries(fields || {}).map(([name, value]) => ({ name, value }));

/** Valid rows only, as sent to the API. */
export const toFields = (rows: FieldRow[]): InputFields =>
  Object.fromEntries(rows.filter((r) => r.name && !fieldError(r.name, r.value)).map((r) => [r.name, r.value]));

export default function InputFieldsEditor({
  rows,
  onChange,
  ecs,
}: {
  rows: FieldRow[];
  onChange: (rows: FieldRow[]) => void;
  ecs: string;
}) {
  const pathField = ecs === "disabled" ? "path" : "[log][file][path]";
  const set = (i: number, patch: Partial<FieldRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const add = (row: FieldRow) => onChange([...rows, row]);
  const hasPath = rows.some((r) => r.name === pathField);

  return (
    <div className="stack" style={{ padding: 14, overflow: "auto" }}>
      <p className="muted small" style={{ margin: 0 }}>
        Fields a real input would add to every event before your filters — e.g. the source file path set by the{" "}
        <code>file</code> input, to extract a host or application name from it with grok. They are injected by the test
        harness, saved with the project and given to the AI agent.
      </p>
      {rows.map((r, i) => {
        const err = r.name || r.value ? fieldError(r.name, r.value) : null;
        return (
          <div key={i} className="stack" style={{ gap: 4 }}>
            <div className="field-row">
                <input
                  aria-label="Field"
                  placeholder="[log][file][path]"
                  value={r.name}
                  onChange={(e) => set(i, { name: e.target.value.trim() })}
                />
                <input
                  aria-label="Value"
                  placeholder="/var/log/apache2/srv-web01/access.log"
                  value={r.value}
                  onChange={(e) => set(i, { value: e.target.value })}
                />
                <button
                  className="ghost icon-only"
                  aria-label="Remove"
                  onClick={() => onChange(rows.filter((_, j) => j !== i))}
                >
                  <Icon name="trash" />
                </button>
            </div>
            {err && <span className="error-text small">{err}</span>}
          </div>
        );
      })}
      <div className="row">
        {!hasPath && (
          <button
            className="small"
            onClick={() => add({ name: pathField, value: "/var/log/app/server01/app.log" })}
            title={`The file input sets ${pathField} (pipeline ECS mode: ${ecs})`}
          >
            <Icon name="file" /> File path
          </button>
        )}
        <button className="small" onClick={() => add({ name: "", value: "" })} disabled={rows.length >= 20}>
          <Icon name="plus" /> Custom field
        </button>
      </div>
      <div className="muted small">
        The pipeline runs with ECS compatibility <code>{ecs}</code>: the file input would set <code>{pathField}</code>.
      </div>
    </div>
  );
}
