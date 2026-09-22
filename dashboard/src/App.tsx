import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { EmptyState } from "./components/EmptyState";
import { Layout } from "./components/Layout";
import { AdminHub } from "./pages/AdminHub";
import { CampaignDetail } from "./pages/CampaignDetail";
import { Campaigns } from "./pages/Campaigns";
import { CheckDetail } from "./pages/CheckDetail";
import { Downloads } from "./pages/Downloads";
import { Findings } from "./pages/Findings";
import { HostDetail } from "./pages/HostDetail";
import { Locations } from "./pages/Locations";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { ReportDetail } from "./pages/ReportDetail";
import { Setup } from "./pages/Setup";
import { Telemetry } from "./pages/Telemetry";
import { Treatment } from "./pages/Treatment";
import type { RouteKey } from "./routes";
import type { AuthUser } from "./types";

type Phase = "loading" | "setup" | "login" | "ready";

export function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [route, setRoute] = useState<RouteKey>("overview");

  const [campaignId, setCampaignId] = useState<number | null>(null);
  const [locationId, setLocationId] = useState<number | null>(null);
  const [hostId, setHostId] = useState<number | null>(null);
  const [reportId, setReportId] = useState<number | null>(null);
  const [checkId, setCheckId] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .authStatus()
      .then((status) => {
        if (!alive) return;
        if (!status.initialized) setPhase("setup");
        else if (status.user) {
          setUser(status.user);
          setPhase("ready");
        } else setPhase("login");
      })
      .catch(() => alive && setPhase("login"));
    return () => {
      alive = false;
    };
  }, []);

  const resetSelection = useCallback(() => {
    setLocationId(null);
    setHostId(null);
    setReportId(null);
    setCheckId(null);
  }, []);

  const navigate = useCallback(
    (next: RouteKey) => {
      setRoute(next);
      setCampaignId(null);
      resetSelection();
    },
    [resetSelection],
  );

  /** Chart drill-down: publish the exact canonical query and open Findings. */
  const drilldown = useCallback(
    (query: string) => {
      const url = query ? `${window.location.pathname}?${query}` : window.location.pathname;
      window.history.pushState({}, "", url);
      window.dispatchEvent(new PopStateEvent("popstate"));
      setRoute("findings");
      setCampaignId(null);
      resetSelection();
    },
    [resetSelection],
  );

  const authed = useCallback((next: AuthUser) => {
    setUser(next);
    setPhase("ready");
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
      setPhase("login");
    }
  }, []);

  if (phase === "loading") return <p className="p-8" role="status">Loading…</p>;
  if (phase === "setup") {
    return (
      <div className="mx-auto max-w-md p-8">
        <Setup onAuthed={authed} />
      </div>
    );
  }
  if (phase === "login" || !user) {
    return (
      <div className="mx-auto max-w-md p-8">
        <Login onAuthed={authed} />
      </div>
    );
  }

  function workspace() {
    if (route === "overview") return <Overview />;
    if (route === "findings") return <Findings />;
    if (route === "treatment") return <Treatment />;
    if (route === "telemetry") return <Telemetry />;
    if (route === "admin") return <AdminHub role={user!.role} />;
    if (route === "standards") {
      return <EmptyState title="Standards mapping" detail="Open a campaign to view CIS/NIST/ISO coverage for its findings." />;
    }

    if (route === "locations") {
      if (hostId !== null) return <HostDetail hostId={hostId} onBack={() => setHostId(null)} />;
      if (campaignId === null) return <Campaigns onOpen={setCampaignId} />;
      return (
        <Locations
          campaignId={campaignId}
          onOpenHost={setHostId}
          onOpenDownloads={(id) => setLocationId(id)}
        />
      );
    }

    // route === "campaigns"
    if (checkId !== null) {
      return (
        <CheckDetail checkId={checkId} onBack={() => setCheckId(null)} onOpenReport={(id) => setReportId(id)} />
      );
    }
    if (reportId !== null) {
      return (
        <ReportDetail reportId={reportId} onBack={() => setReportId(null)} onOpenCheck={(id) => setCheckId(id)} />
      );
    }
    if (hostId !== null) return <HostDetail hostId={hostId} onBack={() => setHostId(null)} />;
    if (campaignId !== null && locationId !== null) {
      return <Downloads campaignId={campaignId} locationId={locationId} onBack={() => setLocationId(null)} />;
    }
    if (campaignId !== null) {
      return (
        <CampaignDetail
          campaignId={campaignId}
          onBack={() => setCampaignId(null)}
          onOpenHost={setHostId}
          onOpenDownloads={(id) => setLocationId(id)}
          onDrilldown={drilldown}
        />
      );
    }
    return <Campaigns onOpen={setCampaignId} />;
  }

  return (
    <Layout user={user} route={route} onNavigate={navigate} onLogout={logout}>
      {workspace()}
    </Layout>
  );
}
