import { useCallback, useEffect, useState } from "react";

import { ApiError, get, hasRole, post, type MeResponse, type User } from "./api";
import Admin from "./pages/Admin";
import { ChangePassword, Login, MfaChallenge } from "./pages/Auth";
import Help from "./pages/Help";
import Profile from "./pages/Profile";
import Workspace from "./pages/Workspace";

type Page = "workspace" | "profile" | "admin" | "help";
const PATHS: Record<Page, string> = { workspace: "/", profile: "/profile", admin: "/admin", help: "/help" };

const pageFromPath = (path: string): Page =>
  (Object.entries(PATHS).find(([, p]) => p === path)?.[0] as Page) || "workspace";

export default function App() {
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState<Page>(pageFromPath(location.pathname));

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

  const navigate = (p: Page) => {
    history.pushState(null, "", PATHS[p]);
    setPage(p);
  };

  const logout = async () => {
    await post("/api/auth/logout").catch(() => undefined);
    setMe(null);
  };

  if (loading) return <div className="center muted">Loading…</div>;
  if (!me) return <Login onDone={refresh} />;
  if (me.mfa_pending) return <MfaChallenge methods={me.mfa_methods} onDone={refresh} onCancel={logout} />;
  if (me.user.must_change_password) return <ChangePassword forced onDone={refresh} onCancel={logout} />;

  const user: User = me.user;
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={22} height={22} />
          <span>Logstash Explorer</span>
        </div>
        <nav>
          <button className={page === "workspace" ? "active" : ""} onClick={() => navigate("workspace")}>
            Workspace
          </button>
          <button className={page === "profile" ? "active" : ""} onClick={() => navigate("profile")}>
            Profile
          </button>
          {hasRole(user, "admin") && (
            <button className={page === "admin" ? "active" : ""} onClick={() => navigate("admin")}>
              Administration
            </button>
          )}
          <button className={page === "help" ? "active" : ""} onClick={() => navigate("help")}>
            Help
          </button>
        </nav>
        <div className="who">
          <span title={user.auth_source}>
            {user.display_name || user.username} · <em>{user.role}</em>
          </span>
          <button className="ghost" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="content">
        {page === "workspace" && <Workspace user={user} />}
        {page === "profile" && <Profile user={user} onChanged={refresh} />}
        {page === "admin" && hasRole(user, "admin") && <Admin currentUser={user} />}
        {page === "help" && <Help user={user} />}
      </main>
    </div>
  );
}
