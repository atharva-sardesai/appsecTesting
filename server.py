from fastapi import FastAPI
from pydantic import BaseModel
import requests

app = FastAPI()

class Item(BaseModel):
    cve_id: str
    product: str | None = None
    version: str | None = None
    asset: str | None = None

class EnrichReq(BaseModel):
    items: list[Item]

def get_nvd(cve):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    try:
        j = requests.get(url, timeout=20).json()
        vulns = j.get("vulnerabilities", [])
        if not vulns: return {}
        c = vulns[0]["cve"]
        desc = (c.get("descriptions",[{}])[0].get("value",""))[:600]
        metrics = c.get("metrics", {})
        cvss = ""
        for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if k in metrics:
                cvss = metrics[k][0]["cvssData"]["baseScore"]
                break
        refs = [r.get("url","") for r in c.get("references",[])]
        patch = next((u for u in refs if any(w in u for w in ["advis", "patch", "security"])), "")
        return {"summary": desc, "cvss": cvss, "refs": refs, "patch": patch}
    except Exception:
        return {}

def get_epss(cve):
    try:
        j = requests.get(f"https://api.first.org/data/v1/epss?cve={cve}", timeout=15).json()
        d = j.get("data", [])
        return float(d[0]["epss"]) if d else None
    except Exception:
        return None

_kev = None
def kev_set():
    global _kev
    if _kev is None:
        try:
            j = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20).json()
            _kev = {i["cveID"] for i in j.get("vulnerabilities", [])}
        except Exception:
            _kev = set()
    return _kev

@app.post("/enrich")
def enrich(req: EnrichReq):
    kev = kev_set()
    out = []
    for it in req.items:
        nvd = get_nvd(it.cve_id)
        epss = get_epss(it.cve_id)
        cvss = nvd.get("cvss") or 0
        epss_v = epss or 0
        kev_flag = it.cve_id in kev
        priority = round((float(cvss)/10)*0.5 + epss_v*0.4 + (0.5 if kev_flag else 0.0), 3)
        out.append({
            "CVE_ID": it.cve_id,
            "CVSS_Base": nvd.get("cvss",""),
            "EPSS": round(epss_v, 4) if epss else "",
            "Exploited_in_Wild": "Yes" if kev_flag else "No",
            "Affected_Product": it.product or "",
            "Version": it.version or "",
            "Detected_On_Asset": it.asset or "",
            "Description_Short": nvd.get("summary",""),
            "Remediation_Steps": "Apply vendor patch/update per advisory; if delayed, add compensating controls (WAF, restrict exposure, monitor).",
            "Patch_URL": nvd.get("patch",""),
            "Workaround": "Restrict access/virtual patching; enhanced monitoring" if kev_flag else "",
            "References": " | ".join((nvd.get("refs") or [])[:6]),
            "Owner_Suggested": "",
            "Priority_Score": priority,
            "Suggested_Ticket_Title": f"[{it.cve_id}] Remediate on {it.asset or 'target asset'}",
            "Suggested_Ticket_Body": f"CVE: {it.cve_id}\nCVSS: {nvd.get('cvss','')} | EPSS: {epss_v} | KEV: {'Yes' if kev_flag else 'No'}\nSummary: {nvd.get('summary','')}\nRemediation: Apply vendor patch/update.\nPatch: {nvd.get('patch','')}\nRefs: {' | '.join((nvd.get('refs') or [])[:6])}",
        })
    return {"rows": out}
