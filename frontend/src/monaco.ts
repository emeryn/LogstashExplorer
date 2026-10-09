// Local Monaco setup: bundled editor + workers (no CDN), Logstash syntax highlighting.
import { loader } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import EditorWorker from "monaco-editor/editor/editor.worker.js?worker";
import JsonWorker from "monaco-editor/language/json/json.worker.js?worker";

// Bundled workers, served from 'self' (CSP worker-src 'self'). Only the JSON language is used.
self.MonacoEnvironment = {
  getWorker(_workerId: string, label: string) {
    return label === "json" ? new JsonWorker() : new EditorWorker();
  },
};

loader.config({ monaco });

monaco.languages.register({ id: "logstash", extensions: [".conf"] });
monaco.languages.setMonarchTokensProvider("logstash", {
  keywords: ["input", "filter", "output", "if", "else", "and", "or", "not", "in", "nand", "xor"],
  plugins: [
    "grok", "dissect", "kv", "csv", "json", "xml", "date", "mutate", "drop", "split", "clone", "fingerprint",
    "geoip", "useragent", "cidr", "urldecode", "de_dot", "prune", "truncate", "uuid", "syslog_pri",
    "translate", "aggregate", "throttle", "metrics", "json_encode", "bytes", "age",
  ],
  tokenizer: {
    root: [
      [/#.*$/, "comment"],
      [/=~|!~/, { token: "operator", next: "@regexStart" }],
      [/"/, { token: "string.quote", next: "@dstring" }],
      [/'/, { token: "string.quote", next: "@sstring" }],
      [/\[[^\]\s]+\]/, "variable"],
      [/=>|==|!=|<=|>=|<|>/, "operator"],
      [/\b\d+(\.\d+)?\b/, "number"],
      [/\b(true|false)\b/, "constant"],
      [/[a-zA-Z_][\w-]*/, { cases: { "@keywords": "keyword", "@plugins": "type", "@default": "identifier" } }],
      [/[{}()[\]]/, "@brackets"],
    ],
    regexStart: [
      [/\s+/, ""],
      [/\//, { token: "regexp", next: "@regex" }],
      [/./, { token: "", next: "@pop" }],
    ],
    regex: [
      [/\\./, "regexp.escape"],
      [/\//, { token: "regexp", next: "@popall" }],
      [/[^\\/]+/, "regexp"],
    ],
    dstring: [
      [/%\{[^}]+\}/, "string.escape"],
      [/[^\\"%]+/, "string"],
      [/\\./, "string.escape"],
      [/"/, { token: "string.quote", next: "@pop" }],
      [/./, "string"],
    ],
    sstring: [
      [/%\{[^}]+\}/, "string.escape"],
      [/[^\\'%]+/, "string"],
      [/\\./, "string.escape"],
      [/'/, { token: "string.quote", next: "@pop" }],
      [/./, "string"],
    ],
  },
} as monaco.languages.IMonarchLanguage);
monaco.languages.setLanguageConfiguration("logstash", {
  comments: { lineComment: "#" },
  brackets: [["{", "}"], ["[", "]"], ["(", ")"]],
  autoClosingPairs: [
    { open: "{", close: "}" }, { open: "[", close: "]" }, { open: "(", close: ")" },
    { open: '"', close: '"' }, { open: "'", close: "'" },
  ],
});

export { monaco };
