import { useCallback, useEffect, useState } from "react";

import { ApiError, get, hasRole, post, type MeResponse, type Parser, type User } from "./api";
import Library from "./components/ParserLibrary";
import Admin from "./pages/admin/Admin";
import { ChangePassword, Login, MfaChallenge } from "./pages/Auth";
import Help from "./pages/Help";
import Profile from "./pages/Profile";
import Workspace from "./pages/Workspace";
import { useTheme, type ThemePref } from "./theme";
import { Avatar, Icon, type IconName } from "./ui";

type Page = "workspace" | "library" | "profile" | "admin" | "help";
const PATHS: Record<Page, string> = {
  workspace: "/",
  library: "/library",
  profile: "/profile",
  admin: "/admin",
  help: "/help",
};
const THEME_NEXT: Record<ThemePref, ThemePref> = { system: "light", light: "dark", dark: "system" };
const THEME_ICON: Record<ThemePref, IconName> = { system: "monitor", light: "sun", dark: "moon" };

const pageFromPath = (path: string): Page =>
  (Object.entries(PATHS).find(([, p]) => p === path || (p !== "/" && path.startsWith(p + "/")))?.[0] as Page) ||
  "workspace";

const COLLAPSE_KEY = "lsx.sidebar.collapsed";
const readCollapsed = () => {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
};

export default function App() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState<Page>(pageFromPath(location.pathname));
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [pendingParser, setPendingParser] = useState<{ parser: Parser; withSample: boolean } | null>(null);
  const [pendingUsers, setPendingUsers] = useState(0);
  const { pref, setPref } = useTheme();

  const refresh = useCallback(async () => {
    try {
      setMe(await get<MeResponse>("/api/auth/me"));
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 401) console.error(e);
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const onUnauthorized = () => setMe(null);
    const onPop = () => setPage(pageFromPath(location.pathname));
    window.addEventListener("lsx:unauthorized", onUnauthorized);
    window.addEventListener("popstate", onPop);
    return () => {
      window.removeEventListener("lsx:unauthorized", onUnauthorized);
      window.removeEventListener("popstate", onPop);
    };
  }, [refresh]);

  const isAdmin = !!me && !me.mfa_pending && hasRole(me.user, "admin");
  useEffect(() => {
    if (!isAdmin) return;
    const load = () =>
      get<User[]>("/api/admin/users")
        .then((users) => setPendingUsers(users.filter((u) => u.status === "pending").length))
        .catch(() => undefined);
    load();
    const t = setInterval(load, 60000);
    window.addEventListener("lsx:users-changed", load);
    return () => {
      clearInterval(t);
      window.removeEventListener("lsx:users-changed", load);
    };
  }, [isAdmin]);

  const navigate = (p: Page) => {
    if (location.pathname !== PATHS[p]) history.pushState(null, "", PATHS[p]);
    setPage(p);
  };

  const toggleCollapsed = () => {
    setCollapsed((c) => {
      try {
        localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1");
      } catch {
        /* per-browser convenience only */
      }
      return !c;
    });
  };

  const logout = async () => {
    await post("/api/auth/logout").catch(() => undefined);
    setMe(null);
  };

  if (loading) {
    return (
      <div className="center muted">
        <span className="spinner" />
      </div>
    );
  }
  if (!me) return <Login onDone={refresh} />;
  if (me.mfa_pending) return <MfaChallenge methods={me.mfa_methods} onDone={refresh} onCancel={logout} />;
  if (me.user.must_change_password) return <ChangePassword forced onDone={refresh} onCancel={logout} />;

  const user: User = me.user;
  const item = (p: Page, icon: IconName, label: string, count?: number) => (
    <button className={page === p ? "active" : ""} onClick={() => navigate(p)} title={collapsed ? label : undefined}>
      <Icon name={icon} />
      <span className="label">{label}</span>
      {!!count && <span className="badge warn count">{count}</span>}
    </button>
  );

  return (
    <div className={`app ${collapsed ? "collapsed" : ""}`}>
      <aside className="sidebar">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={26} height={26} />
          <span>Logstash Explorer</span>
        </div>
        <nav className="nav">
          <div className="nav-label">Build</div>
          {item("workspace", "workspace", "Workspace")}
          {item("library", "library", "Parser library")}
          <div className="nav-label">Account</div>
          {item("profile", "user", "Profile & MCP")}
          {hasRole(user, "admin") && item("admin", "shield", "Administration", pendingUsers)}
          {item("help", "help", "Help")}
        </nav>
        <div className="sidebar-foot">
          <button onClick={() => setPref(THEME_NEXT[pref])} title={`Theme: ${pref} (click to change)`}>
            <Icon name={THEME_ICON[pref]} />
            <span className="label">Theme: {pref}</span>
          </button>
          <button onClick={toggleCollapsed} title={collapsed ? "Expand the sidebar" : "Collapse the sidebar"}>
            <Icon name={collapsed ? "expand" : "collapse"} />
            <span className="label">Collapse</span>
          </button>
          <div className="who" title={`${user.username} · ${user.auth_source}`}>
            <Avatar name={user.display_name || user.username} />
            <div className="who-text">
              <strong className="ellipsis">{user.display_name || user.username}</strong>
              <span className="muted small">{user.role}</span>
            </div>
            <button className="ghost icon-only small" onClick={logout} title="Sign out" aria-label="Sign out">
              <Icon name="logout" />
            </button>
          </div>
        </div>
      </aside>
      <main className="content">
        {page === "workspace" && (
          <Workspace user={user} pendingParser={pendingParser} onParserConsumed={() => setPendingParser(null)} />
        )}
        {page === "library" && (
          <Library
            onUse={(parser, withSample) => {
              setPendingParser({ parser, withSample });
              navigate("workspace");
            }}
          />
        )}
        {page === "profile" && <Profile user={user} onChanged={refresh} />}
        {page === "admin" && hasRole(user, "admin") && <Admin currentUser={user} />}
        {page === "help" && <Help user={user} />}
      </main>
    </div>
  );
}
