import { useEffect, useState } from "react";

import type { User } from "../../api";
import { Icon, PageHeader, type IconName } from "../../ui";
import AiConfig from "./AiConfig";
import Audit from "./Audit";
import Directory from "./Directory";
import Logging from "./Logging";
import Mcp from "./Mcp";
import Overview from "./Overview";
import Pki from "./Pki";
import Users from "./Users";

export type Section = "overview" | "users" | "directory" | "ai" | "logging" | "mcp" | "pki" | "audit";
const SECTIONS: [Section, IconName, string][] = [
  ["overview", "activity", "Overview"],
  ["users", "users", "Users"],
  ["directory", "network", "Directory & SSO"],
  ["ai", "sparkles", "AI agent"],
  ["logging", "list", "Logs & syslog"],
  ["mcp", "plug", "MCP & tokens"],
  ["pki", "lock", "PKI"],
  ["audit", "shield", "Audit"],
];

const fromPath = (): Section => {
  const s = location.pathname.split("/")[2] as Section;
  return SECTIONS.some(([id]) => id === s) ? s : "overview";
};

export default function Admin({ currentUser }: { currentUser: User }) {
  const [section, setSection] = useState<Section>(fromPath);

  useEffect(() => {
    const onPop = () => setSection(fromPath());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const go = (s: Section) => {
    const path = s === "overview" ? "/admin" : `/admin/${s}`;
    if (location.pathname !== path) history.pushState(null, "", path);
    setSection(s);
  };

  return (
    <div className="page">
      <PageHeader title="Administration" subtitle="Accounts, sign-in, integrations and audit." />
      <nav className="subnav">
        {SECTIONS.map(([id, icon, label]) => (
          <button key={id} className={section === id ? "active" : ""} onClick={() => go(id)}>
            <Icon name={icon} /> {label}
          </button>
        ))}
      </nav>
      {section === "overview" && <Overview onNavigate={go} />}
      {section === "users" && <Users currentUser={currentUser} />}
      {section === "directory" && <Directory />}
      {section === "ai" && <AiConfig />}
      {section === "logging" && <Logging />}
      {section === "mcp" && <Mcp />}
      {section === "pki" && <Pki />}
      {section === "audit" && <Audit />}
    </div>
  );
}
