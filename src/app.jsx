import React, { useMemo, useRef, useState } from "react";
import { Download, Upload, FileSpreadsheet, Sparkles, ClipboardList, Github } from "lucide-react";
const API = import.meta.env.VITE_API_URL;

// Backend → UI mapping (Brief_Description, Remediation_Links → table fields)
function normalizeRows(rows, owner = "") {
  return (rows || []).map(r => ({
    ...r,
    Description_Short: r.Brief_Description || r.Description_Short || "",
    Remediation_Steps: r.Remediation_Links || r.Remediation_Steps || "",
    Owner_Suggested: owner || r.Owner_Suggested || "",
  }));
}


// === Minimal shadcn-like components (inline for single-file demo) ===
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

// === Utility: simple CSV parse (no quotes/escapes complexity for MVP) ===
function parseCSV(content) {
  const lines = content.trim().split(/\r?\n/);
  const headers = lines[0].split(",").map((h) => h.trim());
  return lines.slice(1).map((line) => {
    const cells = line.split(",").map((c) => c.trim());
    const obj = {};
    headers.forEach((h, i) => (obj[h] = cells[i] ?? ""));
    return obj;
  });
}

// === Utility: download as Excel using a minimal SheetJS build from CDN (runtime imported) ===
async function exportToXLSX(rows, filename = "enriched_cves.xlsx") {
  // Lazy-load SheetJS from CDN
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

// === Mock enrichment (replace with backend calls later) ===
function mockEnrich(cve, { product = "", version = "", asset = "" } = {}) {
  const KB = {
    "CVE-2021-44228": {
      summary: "Apache Log4j2 JNDI RCE (Log4Shell)",
      cvss: 10.0,
      epss: 0.9754,
      kev: true,
      remediation:
        "Update to Log4j >= 2.17.1 (Java 8+) or vendor-provided fixed version. Remove JndiLookup class, set log4j2.formatMsgNoLookups=true as an interim control.",
      patch: "https://logging.apache.org/log4j/2.x/security.html",
      refs: [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://www.cisa.gov/known-exploited-vulnerabilities",
      ],
    },
    "CVE-2023-4863": {
      summary: "WebP heap buffer overflow (libwebp)",
      cvss: 8.8,
      epss: 0.5512,
      kev: true,
      remediation: "Upgrade Chromium/Chrome and all libwebp consumers to patched versions; rebuild images with updated libwebp.",
      patch: "https://chromereleases.googleblog.com/",
      refs: [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
        "https://conda-forge.org/blog/2023-09-14-libwebp/",
      ],
    },
    "CVE-2024-3094": {
      summary: "xz-utils backdoor (liblzma) – SSH auth bypass risk",
      cvss: 9.8,
      epss: 0.3123,
      kev: true,
      remediation: "Downgrade to xz 5.4.x or upgrade to vendor-fixed builds; verify OpenSSH not linked to compromised liblzma; rebuild from trusted source.",
      patch: "https://www.cisa.gov/news-events/alerts/2024/03/",
      refs: [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        "https://www.openwall.com/lists/oss-security/2024/03/29/",
      ],
    },
  };

  const d = KB[cve] || {
    summary: "No cached summary. Will fetch on server in full build.",
    cvss: "",
    epss: "",
    kev: false,
    remediation: "Check vendor advisory; patch to fixed version. If unavailable, add compensating controls (WAF, RBAC tightening, monitoring).",
    patch: "",
    refs: ["https://nvd.nist.gov/"],
  };

  const score = (Number(d.cvss || 0) / 10) * 0.5 + (Number(d.epss || 0)) * 0.4 + (d.kev ? 0.5 : 0);
  return {
    CVE_ID: cve,
    CVSS_Base: d.cvss,
    EPSS: d.epss,
    Exploited_in_Wild: d.kev ? "Yes" : "No",
    Affected_Product: product,
    Version: version,
    Detected_On_Asset: asset,
    Description_Short: d.summary,
    Remediation_Steps: d.remediation,
    Patch_URL: d.patch,
    Workaround: d.kev ? "If patching delayed, restrict exposure; add virtual patching; monitor for IOCs." : "",
    References: d.refs.join(" | "),
    Owner_Suggested: "",
    Priority_Score: Number(score.toFixed(3)),
    Suggested_Ticket_Title: `[${cve}] Remediate on ${asset || "target asset"}`,
    Suggested_Ticket_Body:
      `CVE: ${cve}\nCVSS: ${d.cvss} | EPSS: ${d.epss} | KEV: ${d.kev ? "Yes" : "No"}\nSummary: ${d.summary}\nRemediation: ${d.remediation}\nPatch: ${d.patch}\nRefs: ${d.refs.join(", ")}`,
  };
}

// === Pretty tags ===
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

// === Main Component ===
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
      alert("VITE_API_URL is not set in your Netlify env.");
      return;
    }

    const res = await fetch(`${API}/enrich`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // If you enabled API key on server, uncomment:
        // "X-API-Key": import.meta.env.VITE_API_KEY || ""
      },
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
    const parsed = parseCSV(txt); // expects a header named CVE_ID
    const cves = Array.from(
      new Set(parsed.map((r) => (r.CVE_ID || "").trim()).filter(Boolean))
    );

    if (!cves.length) {
      alert("No CVE_ID values found in the CSV (need a 'CVE_ID' column).");
      return;
    }
    if (!API) {
      alert("VITE_API_URL is not set in your Netlify env.");
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
    if (fileRef.current) fileRef.current.value = ""; // allow re-upload same file
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
            <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
              Paste CVEs or upload a CSV from Veracode. Get remediation guidance, EPSS/KEV flags, and export to Excel.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button className="bg-indigo-600 text-white hover:bg-indigo-700" onClick={() => exportToXLSX(rows)}>
              <Download className="h-4 w-4" /> Export Excel
            </Button>
            <Button className="bg-white text-zinc-800 ring-1 ring-zinc-200 hover:bg-zinc-50 dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-700" onClick={() => fileRef.current?.click()}>
              <Upload className="h-4 w-4" /> Upload CSV
              <input ref={fileRef} type="file" accept=".csv" className="hidden" onChange={onUploadCSV} />
            </Button>
          </div>
        </div>

        {/* Input Card */}
        <Card className="mb-8">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="md:col-span-2">
              <label className="text-sm font-medium text-zinc-700 dark:text-zinc-200">CVE IDs (one per line)</label>
              <Textarea rows={6} value={text} onChange={(e) => setText(e.target.value)} placeholder="CVE-YYYY-NNNN" />
            </div>
            <div className="md:col-span-1">
              <label className="text-sm font-medium text-zinc-700 dark:text-zinc-200">Default Owner (optional)</label>
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
              <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400">
                Tip: CSV headers supported: <code>CVE_ID, Asset, ProductOrLib, Version</code>
              </p>
            </div>
          </div>
        </Card>

        {/* Summary */}
        {rows.length > 0 && (
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Tag tone="gray">Total: {rows.length}</Tag>
            <Tag tone="red">High Priority ≥ 0.8: {totalHigh}</Tag>
            <Tag tone="amber">Medium 0.5–0.79: {rows.filter((r) => r.Priority_Score >= 0.5 && r.Priority_Score < 0.8).length}</Tag>
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
                      "Summary",
                      "Remediation",
                      "Patch",
                      "Refs",
                    ].map((h) => (
                      <th key={h} className="px-3 py-2 font-semibold text-zinc-700 dark:text-zinc-200 whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.CVE_ID + r.Asset} className="border-b border-zinc-100/70 dark:border-zinc-800/70 align-top">
                      <td className="px-3 py-3"><Tag tone={priorityColor(r.Priority_Score)}>{r.Priority_Score}</Tag></td>
                      <td className="px-3 py-3 font-medium">{r.CVE_ID}</td>
                      <td className="px-3 py-3">{r.CVSS_Base}</td>
                      <td className="px-3 py-3">{r.EPSS}</td>
                      <td className="px-3 py-3">{r.Exploited_in_Wild}</td>
                      <td className="px-3 py-3 whitespace-nowrap">{r.Affected_Product}</td>
                      <td className="px-3 py-3">{r.Version}</td>
                      <td className="px-3 py-3">{r.Detected_On_Asset}</td>
                      <td className="px-3 py-3 max-w-[28rem]"><p className="line-clamp-4 leading-5 text-zinc-700 dark:text-zinc-300">{r.Description_Short}</p></td>
                      <td className="px-3 py-3 max-w-[32rem]"><p className="line-clamp-4 leading-5 text-zinc-700 dark:text-zinc-300">{r.Remediation_Steps}</p></td>
                      <td className="px-3 py-3">
                        {r.Patch_URL ? (
                          <a href={r.Patch_URL} target="_blank" className="text-indigo-600 hover:underline">Patch</a>
                        ) : (
                          <span className="text-zinc-400">—</span>
                        )}
                      </td>
                      <td className="px-3 py-3 max-w-[22rem]">
                        {r.References?.split(" | ").slice(0,3).map((u) => (
                          <div key={u}>
                            <a href={u} target="_blank" className="text-indigo-600 hover:underline break-all">{u}</a>
                          </div>
                        ))}
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
            Hook up a backend later to call NVD/EPSS/KEV for live data.
          </div>
        </div>
      </div>

      {/* Tailwind base (only for this single-file demo) */}
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
