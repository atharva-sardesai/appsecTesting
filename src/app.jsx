import React, { useMemo, useRef, useState } from "react";
import { Download, Upload, FileSpreadsheet, Sparkles, ClipboardList, Github } from "lucide-react";

const API = import.meta.env.VITE_API_URL;

/* ------------------------- mapping + helpers ------------------------- */

// Backend → UI mapping
function normalizeRows(rows, owner = "") {
  return (rows || []).map((r) => ({
    ...r,
    // Force Summary to show AI brief
    Description_Short: r.AI_Brief || r.Brief_Description || "",
    // Keep remediation links as chips
    Remediation_Steps: r.Remediation_Links || "",
    // Keep owner overlay
    Owner_Suggested: owner || r.Owner_Suggested || "",
  }));
}


// Super-minimal CSV parser (no quoted cells handling)
function parseCSV(content) {
  const lines = content.trim().split(/\r?\n/);
  if (!lines.length) return [];
  const headers = lines[0].split(",").map((h) => h.trim());
  return lines.slice(1).map((line) => {
    const cells = line.split(",").map((c) => c.trim());
    const obj = {};
    headers.forEach((h, i) => (obj[h] = cells[i] ?? ""));
    return obj;
  });
}

// Export to Excel (SheetJS via CDN)
async function exportToXLSX(rows, filename = "enriched_cves.xlsx") {
  if (!window.XLSX) {
    await new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = "https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js";
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }
  const ws = window.XLSX.utils.json_to_sheet(rows);
  const wb = window.XLSX.utils.book_new();
  window.XLSX.utils.book_append_sheet(wb, ws, "Enriched_CVEs");
  const wbout = window.XLSX.write(wb, { bookType: "xlsx", type: "array" });
  const blob = new Blob([wbout], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/* ------------------------------ UI atoms ----------------------------- */

const Button = ({ className = "", children, ...props }) => (
  <button
    className={`inline-flex items-center gap-2 rounded-2xl px-4 py-2 text-sm font-medium shadow-sm hover:shadow transition active:scale-[.99] ${className}`}
    {...props}
  >
    {children}
  </button>
);

const Card = ({ className = "", children }) => (
  <div className={`rounded-3xl bg-white/90 dark:bg-zinc-900/80 shadow-xl ring-1 ring-black/5 backdrop-blur p-6 ${className}`}>{children}</div>
);

const Input = ({ className = "", ...props }) => (
  <input
    className={`w-full rounded-xl border border-zinc-300 dark:border-zinc-700 bg-white/70 dark:bg-zinc-900/50 px-3 py-2 text-sm shadow-inner focus:outline-none focus:ring-2 focus:ring-indigo-400 ${className}`}
    {...props}
  />
);

const Textarea = ({ className = "", ...props }) => (
  <textarea
    className={`w-full rounded-xl border border-zinc-300 dark:border-zinc-700 bg-white/70 dark:bg-zinc-900/50 px-3 py-2 text-sm shadow-inner focus:outline-none focus:ring-2 focus:ring-indigo-400 ${className}`}
    {...props}
  />
);

const Tag = ({ children, tone = "gray" }) => (
  <span
    className={
      `inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ` +
      (tone === "green"
        ? "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-200 dark:ring-emerald-800"
        : tone === "red"
        ? "bg-rose-50 text-rose-700 ring-rose-200 dark:bg-rose-900/30 dark:text-rose-200 dark:ring-rose-800"
        : tone === "amber"
        ? "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-900/30 dark:text-amber-200 dark:ring-amber-800"
        : "bg-zinc-50 text-zinc-700 ring-zinc-200 dark:bg-zinc-800/40 dark:text-zinc-200 dark:ring-zinc-700")
    }
  >
    {children}
  </span>
);

/* ---------------------------- Main component ---------------------------- */

export default function App() {
  const [text, setText] = useState("CVE-2021-44228\nCVE-2023-4863\nCVE-2024-3094");
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [owner, setOwner] = useState("");
  const fileRef = useRef(null);

  const priorityColor = (p) => (p >= 0.8 ? "red" : p >= 0.5 ? "amber" : "green");

  const enrich = async () => {
    setLoading(true);
    try {
      const cves = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);

      if (!cves.length) {
        alert("Please paste at least one CVE (e.g., CVE-2021-44228).");
        return;
      }
      if (!API) {
        alert("VITE_API_URL is not set.");
        return;
      }

      const res = await fetch(`${API}/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cves }),
      });

      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(`Backend error ${res.status}: ${t || res.statusText}`);
      }

      const data = await res.json();
      console.log("API row sample:", data?.rows?.[0]); // debug: ensure Brief_Description exists
      const enriched = normalizeRows(data.rows, owner);
      setRows(enriched);
    } catch (e) {
      console.error(e);
      alert(e.message || "Failed to enrich CVEs");
    } finally {
      setLoading(false);
    }
  };

  const onUploadCSV = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const txt = await file.text();
      const parsed = parseCSV(txt); // needs a 'CVE_ID' column
      const cves = Array.from(new Set(parsed.map((r) => (r.CVE_ID || "").trim()).filter(Boolean)));

      if (!cves.length) {
        alert("No CVE_ID values found in CSV.");
        return;
      }
      if (!API) {
        alert("VITE_API_URL is not set.");
        return;
      }

      const res = await fetch(`${API}/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cves }),
      });

      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(`Backend error ${res.status}: ${t || res.statusText}`);
      }

      const data = await res.json();
      const enriched = normalizeRows(data.rows, owner);
      setRows(enriched);
    } catch (e) {
      console.error(e);
      alert(e.message || "Failed to enrich CVEs from CSV");
    } finally {
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const totalHigh = useMemo(() => rows.filter((r) => r.Priority_Score >= 0.8).length, [rows]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-zinc-950 via-zinc-950 to-black text-zinc-100">
      <div className="mx-auto max-w-7xl px-4 py-10">
        {/* Hero */}
        <div className="mb-8 flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl md:text-4xl font-semibold tracking-tight flex items-center gap-3">
              <Sparkles className="h-7 w-7 text-indigo-600" /> AppSec CVE Enricher
            </h1>
            <p className="mt-2 text-sm text-zinc-500">
              Paste CVEs or upload a CSV. We fetch CVSS/EPSS/KEV, generate an AI brief, and give remediation links.
            </p>
            <p className="mt-1 text-xs text-zinc-600">API: {API || "— VITE_API_URL not set —"}</p>
          </div>
          <div className="flex items-center gap-3">
            <Button className="bg-indigo-600 text-white hover:bg-indigo-700" onClick={() => exportToXLSX(rows)}>
              <Download className="h-4 w-4" /> Export Excel
            </Button>
            <Button
              className="bg-white text-zinc-800 ring-1 ring-zinc-200 hover:bg-zinc-50 dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-700"
              onClick={() => fileRef.current?.click()}
            >
              <Upload className="h-4 w-4" /> Upload CSV
              <input ref={fileRef} type="file" accept=".csv" className="hidden" onChange={onUploadCSV} />
            </Button>
          </div>
        </div>

        {/* Input Card */}
        <Card className="mb-8">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="md:col-span-2">
              <label className="text-sm font-medium text-zinc-200">CVE IDs (one per line)</label>
              <Textarea rows={6} value={text} onChange={(e) => setText(e.target.value)} placeholder="CVE-YYYY-NNNN" />
            </div>
            <div className="md:col-span-1">
              <label className="text-sm font-medium text-zinc-200">Default Owner (optional)</label>
              <Input placeholder="team@company.com" value={owner} onChange={(e) => setOwner(e.target.value)} />
              <div className="mt-4 flex gap-3">
                <Button className="bg-indigo-600 text-white hover:bg-indigo-700" onClick={enrich} disabled={loading}>
                  <ClipboardList className="h-4 w-4" /> {loading ? "Enriching…" : "Enrich CVEs"}
                </Button>
                <Button
                  className="bg-white text-zinc-800 ring-1 ring-zinc-200 hover:bg-zinc-50 dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-700"
                  onClick={() => {
                    setRows([]);
                    setText("");
                  }}
                >
                  Clear
                </Button>
              </div>
              <p className="mt-3 text-xs text-zinc-400">
                CSV needs a <code>CVE_ID</code> column.
              </p>
            </div>
          </div>
        </Card>

        {/* Summary bar */}
        {rows.length > 0 && (
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Tag tone="gray">Total: {rows.length}</Tag>
            <Tag tone="red">High Priority ≥ 0.8: {totalHigh}</Tag>
            <Tag tone="amber">
              Medium 0.5–0.79: {rows.filter((r) => r.Priority_Score >= 0.5 && r.Priority_Score < 0.8).length}
            </Tag>
            <Tag tone="green">Low &lt; 0.5: {rows.filter((r) => r.Priority_Score < 0.5).length}</Tag>
          </div>
        )}

        {/* Table */}
        {rows.length > 0 && (
          <Card>
            <div className="overflow-auto">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-white/90 dark:bg-zinc-900/80 backdrop-blur">
                  <tr className="border-b border-zinc-200 dark:border-zinc-800">
                    {[
                      "Priority",
                      "CVE",
                      "CVSS",
                      "EPSS",
                      "KEV",
                      "Product",
                      "Version",
                      "Asset",
                      "AI Brief",
                      "Impact",
                      "Affected",
                      "Remediation",
                      "Patch",
                      "Refs",
                    ].map((h) => (
                      <th key={h} className="px-3 py-2 font-semibold text-zinc-200 whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr
                      key={r.CVE_ID + (r.Detected_On_Asset || "")}
                      className="border-b border-zinc-100/70 dark:border-zinc-800/70 align-top"
                    >
                      {/* Priority */}
                      <td className="px-3 py-3">
                        <Tag tone={priorityColor(r.Priority_Score)}>{r.Priority_Score}</Tag>
                      </td>
                      {/* CVE */}
                      <td className="px-3 py-3 font-medium">{r.CVE_ID}</td>
                      {/* CVSS */}
                      <td className="px-3 py-3">{r.CVSS_Base}</td>
                      {/* EPSS */}
                      <td className="px-3 py-3">{r.EPSS}</td>
                      {/* KEV */}
                      <td className="px-3 py-3">{r.Exploited_in_Wild}</td>
                      {/* Product */}
                      <td className="px-3 py-3 whitespace-nowrap">{r.Affected_Product || "—"}</td>
                      {/* Version */}
                      <td className="px-3 py-3">{r.Version || "—"}</td>
                      {/* Asset */}
                      <td className="px-3 py-3">{r.Detected_On_Asset || "—"}</td>
                      {/* AI Brief */}
                      <td className="px-3 py-3 max-w-[28rem]">
                        <div className="flex items-start gap-2">
                          {r.LLM_Used ? (
                            <span className="mt-0.5 inline-flex items-center rounded-full bg-indigo-500/10 text-indigo-300 px-2 py-0.5 text-[10px] ring-1 ring-indigo-500/30">
                              AI
                            </span>
                          ) : (
                            <span className="mt-0.5 inline-flex items-center rounded-full bg-zinc-500/10 text-zinc-300 px-2 py-0.5 text-[10px] ring-1 ring-zinc-500/30">
                              NVD
                            </span>
                          )}
                          <p className="leading-5 text-zinc-300">
                            {r.AI_Brief || r.Brief_Description || r.Description_Short || "—"}
                          </p>
                        </div>
                      </td>

                      {/* Impact */}
                      <td className="px-3 py-3 max-w-[22rem]">
                        <p className="leading-5 text-zinc-300">{r.AI_Impact || "—"}</p>
                      </td>

                      {/* Affected */}
                      <td className="px-3 py-3 max-w-[20rem]">
                        <p className="leading-5 text-zinc-300">{r.AI_Affected || "—"}</p>
                      </td>

                      {/* Remediation (AI bullets, not the links) */}
                      <td className="px-3 py-3 max-w-[28rem]">
                        <p className="leading-5 text-zinc-300">{r.AI_Remediation || "—"}</p>
                      </td>

                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* Footer */}
        <div className="mt-8 flex flex-wrap items-center justify-between gap-3 text-xs text-zinc-500 dark:text-zinc-400">
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="h-4 w-4" />
            Export creates a single-sheet Excel with all columns, ready for ServiceNow/Jira.
          </div>
          <div className="flex items-center gap-2">
            <Github className="h-4 w-4" />
            OpenAPI-backed enrichment. Make sure OPENAI_API_KEY is set on the backend.
          </div>
        </div>
      </div>

      {/* Tailwind base (for single-file demo) */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;800&display=swap');
        :root { color-scheme: light dark; }
        * { font-family: Inter, ui-sans-serif, system-ui; }
        .line-clamp-4 { display: -webkit-box; -webkit-line-clamp: 4; -webkit-box-orient: vertical; overflow: hidden; }
      `}</style>
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" />
    </div>
  );
}
