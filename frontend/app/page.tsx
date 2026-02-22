"use client";

import { FormEvent, useMemo, useState } from "react";

type ServiceInfo = {
  port: number;
  service: string;
  version?: string | null;
};

type ExposedFile = {
  path: string;
  size?: number | null;
};

type AssetDocument = {
  engagement_id: string;
  asset_type: "host" | "web_app" | "subdomain";
  ip?: string | null;
  url?: string | null;
  open_ports: number[];
  services: ServiceInfo[];
  endpoints: string[];
  exposed_files: ExposedFile[];
  shodan_vulns: string[];
  attack_surface_score: number;
  score_reasoning?: string | null;
};

type AssetsResponse = {
  engagement_id: string;
  count: number;
  assets: AssetDocument[];
};

const DEFAULT_API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
const DEFAULT_ENGAGEMENT_ID = process.env.NEXT_PUBLIC_ENGAGEMENT_ID || "";

function scoreColor(score: number): string {
  if (score >= 0.8) return "text-red-300";
  if (score >= 0.6) return "text-orange-300";
  if (score >= 0.3) return "text-yellow-300";
  return "text-emerald-300";
}

export default function Home() {
  const [engagementId, setEngagementId] = useState(DEFAULT_ENGAGEMENT_ID);
  const [apiBase, setApiBase] = useState(DEFAULT_API_BASE);
  const [minScore, setMinScore] = useState(0);
  const [assets, setAssets] = useState<AssetDocument[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const topRisk = useMemo(
    () => (assets.length ? Math.max(...assets.map((asset) => asset.attack_surface_score)) : 0),
    [assets],
  );

  async function onLoadAssets(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!engagementId.trim()) {
      setError("Enter an engagement ID.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const endpoint = `${apiBase.replace(/\/$/, "")}/api/assets?engagement_id=${encodeURIComponent(engagementId.trim())}&min_score=${minScore.toFixed(2)}`;
      const response = await fetch(endpoint);
      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`);
      }
      const data: AssetsResponse = await response.json();
      setAssets(data.assets || []);
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "Unknown error";
      setError(`Could not load assets: ${message}`);
      setAssets([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-6 px-6 py-10">
      <header className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">
        <h1 className="text-4xl font-bold tracking-tight text-zinc-100">artaas</h1>
        <p className="mt-2 text-sm text-zinc-400">
          reconnaissance dashboard · scored assets from db.assets
        </p>
      </header>

      <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
        <form onSubmit={onLoadAssets} className="grid gap-4 md:grid-cols-4">
          <label className="flex flex-col gap-2 text-xs uppercase tracking-widest text-zinc-500">
            API Base
            <input
              value={apiBase}
              onChange={(event) => setApiBase(event.target.value)}
              className="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
              placeholder="http://localhost:8000"
            />
          </label>
          <label className="flex flex-col gap-2 text-xs uppercase tracking-widest text-zinc-500">
            Engagement ID
            <input
              value={engagementId}
              onChange={(event) => setEngagementId(event.target.value)}
              className="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
              placeholder="abc123"
            />
          </label>
          <label className="flex flex-col gap-2 text-xs uppercase tracking-widest text-zinc-500">
            Min Score
            <input
              type="number"
              value={minScore}
              step={0.05}
              min={0}
              max={1}
              onChange={(event) => setMinScore(Number(event.target.value))}
              className="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            />
          </label>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-md border border-zinc-600 bg-zinc-100 px-4 py-2 text-sm font-semibold text-zinc-900 transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? "Loading..." : "Load Assets"}
            </button>
          </div>
        </form>

        {error && (
          <p className="mt-4 rounded-md border border-red-500/30 bg-red-950/40 px-3 py-2 text-sm text-red-200">
            {error}
          </p>
        )}
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
          <p className="text-xs uppercase tracking-widest text-zinc-500">Assets</p>
          <p className="mt-2 text-3xl font-semibold text-zinc-100">{assets.length}</p>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
          <p className="text-xs uppercase tracking-widest text-zinc-500">Top Risk Score</p>
          <p className={`mt-2 text-3xl font-semibold ${scoreColor(topRisk)}`}>{topRisk.toFixed(2)}</p>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
          <p className="text-xs uppercase tracking-widest text-zinc-500">High Risk Assets (&gt;= 0.6)</p>
          <p className="mt-2 text-3xl font-semibold text-zinc-100">
            {assets.filter((asset) => asset.attack_surface_score >= 0.6).length}
          </p>
        </div>
      </section>

      <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
        <h2 className="text-lg font-semibold text-zinc-100">Scored Assets</h2>
        <div className="mt-4 grid gap-3">
          {assets.length === 0 && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-4 py-6 text-center text-sm text-zinc-500">
              No assets loaded yet.
            </div>
          )}
          {assets.map((asset, index) => (
            <article
              key={`${asset.engagement_id}-${asset.ip || asset.url || index}`}
              className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-mono text-xs text-zinc-400">
                  {asset.url || asset.ip || "unknown-target"}
                </p>
                <p className={`text-sm font-semibold ${scoreColor(asset.attack_surface_score)}`}>
                  {asset.attack_surface_score.toFixed(2)}
                </p>
              </div>
              <p className="mt-2 text-sm text-zinc-300">
                {asset.asset_type} · ports {asset.open_ports.length} · endpoints {asset.endpoints.length} · exposed files{" "}
                {asset.exposed_files.length} · shodan vulns {asset.shodan_vulns.length}
              </p>
              {asset.score_reasoning && (
                <p className="mt-2 text-xs text-zinc-500">{asset.score_reasoning}</p>
              )}
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
