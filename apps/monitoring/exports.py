"""Export generation: TXT/JSON/CSV per entity + full snapshot ZIP. No secrets included."""
import csv
import io
import json
import os
import zipfile
from datetime import datetime

from django.conf import settings
from django.utils import timezone


def _export_dir(target):
    d = os.path.join(settings.BASE_DIR, "data", "exports", target.root_domain)
    os.makedirs(d, exist_ok=True)
    return d


def _filtered(qs, filters):
    f = filters or {}
    if f.get("active_only"):
        if hasattr(qs.model, "is_active"):
            qs = qs.filter(is_active=True)
        elif hasattr(qs.model, "state") and qs.model.__name__ == "Port":
            qs = qs.filter(state="open")
    if f.get("since"):
        try:
            since = datetime.fromisoformat(f["since"])
            qs = qs.filter(first_seen__gte=since)
        except ValueError:
            pass
    if f.get("source"):
        qs = qs.filter(source=f["source"]) if hasattr(qs.model, "source") else qs
    return qs


def collect(export_type, target, filters):
    from apps.assets.models import (APIEndpoint, CVE, HTTPService, IPAddress, JavaScriptAsset,
                                    Port, SecurityFinding, Subdomain, Technology, URLAsset)
    from apps.events.models import Event

    if export_type == "subdomains":
        qs = _filtered(Subdomain.objects.filter(target=target).order_by("hostname"), filters)
        return ("subdomains", ["hostname"], [(s.hostname,) for s in qs.iterator()])
    if export_type == "ips":
        qs = _filtered(IPAddress.objects.filter(target=target).order_by("ip"), filters)
        return ("ips", ["ip"], [(i.ip,) for i in qs.iterator()])
    if export_type == "ports":
        qs = Port.objects.filter(target=target, state="open").order_by("ip", "port")
        return ("open_ports", ["host", "port", "protocol"],
                [(p.ip, p.port, p.protocol) for p in qs.iterator()])
    if export_type == "http":
        qs = HTTPService.objects.filter(target=target).order_by("url")
        return ("http_urls", ["url"], [(h.url,) for h in qs.iterator()])
    if export_type == "urls":
        qs = URLAsset.objects.filter(target=target).order_by("canonical_url")
        return ("urls", ["url"], [(u.canonical_url,) for u in qs.iterator()])
    if export_type == "apis":
        qs = APIEndpoint.objects.filter(target=target).order_by("url")
        return ("api_endpoints", ["method", "url"], [(a.method, a.url) for a in qs.iterator()])
    if export_type == "javascript":
        qs = JavaScriptAsset.objects.filter(target=target).order_by("js_url")
        return ("javascript", ["url"], [(j.js_url,) for j in qs.iterator()])
    if export_type == "technologies":
        qs = Technology.objects.filter(target=target).order_by("product")
        return ("technologies", ["product", "version", "asset"],
                [(t.product, t.version, t.asset_value) for t in qs.iterator()])
    if export_type == "cves":
        qs = CVE.objects.filter(target=target).order_by("cve_id")
        return ("cves", ["cve_id"], [(c.cve_id,) for c in qs.iterator()])
    if export_type == "findings":
        qs = SecurityFinding.objects.filter(target=target).order_by("-first_seen")
        return ("findings", ["severity", "title", "asset"],
                [(f.severity, f.title, f.asset_value) for f in qs.iterator()])
    if export_type == "events":
        qs = Event.objects.filter(target=target).order_by("-created_at")
        return ("events", ["time", "type", "asset", "severity"],
                [(e.created_at.isoformat(), e.event_type, e.asset_value, e.severity) for e in qs.iterator()])
    raise ValueError(f"unknown export type {export_type}")


def render_txt(name, header, rows):
    lines = []
    for r in rows:
        lines.append(" | ".join(str(c) for c in r) if len(r) > 1 else str(r[0]))
    return "\n".join(lines) + ("\n" if lines else "")


def render_json(name, header, rows):
    return json.dumps([dict(zip(header, r)) for r in rows], indent=2)


def render_csv(name, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def build_snapshot(target, filters):
    """Full target snapshot ZIP. Returns (path, size, total_rows)."""
    stamp = timezone.now().strftime("%Y-%m-%d")
    d = _export_dir(target)
    path = os.path.join(d, f"{target.root_domain}-export-{stamp}.zip")
    total = 0
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for etype in ["subdomains", "ips", "ports", "http", "urls", "apis", "javascript",
                      "technologies", "cves", "findings"]:
            name, header, rows = collect(etype, target, filters)
            z.writestr(f"{target.root_domain}-export-{stamp}/{name}.txt", render_txt(name, header, rows))
            total += len(rows)
        name, header, rows = collect("events", target, filters)
        z.writestr(f"{target.root_domain}-export-{stamp}/events.json", render_json(name, header, rows))
        meta = {"target": target.root_domain, "exported_at": timezone.now().isoformat(),
                "baseline": target.baseline_status, "status": target.status}
        z.writestr(f"{target.root_domain}-export-{stamp}/metadata.json", json.dumps(meta, indent=2))
    return path, os.path.getsize(path), total


def run_export_job(job_id):
    from apps.monitoring.models import ExportJob

    try:
        job = ExportJob.objects.select_related("target").get(pk=job_id)
    except ExportJob.DoesNotExist:
        return {"status": "SKIPPED"}
    job.status = ExportJob.STATUS_PROCESSING
    job.save(update_fields=["status"])
    try:
        d = _export_dir(job.target)
        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        if job.export_type == "snapshot":
            path, size, total = build_snapshot(job.target, job.filters)
            job.file_path, job.file_size, job.row_count = path, size, total
        else:
            name, header, rows = collect(job.export_type, job.target, job.filters)
            fmt = job.format if job.format in ("txt", "json", "csv") else "txt"
            body = {"txt": render_txt, "json": render_json, "csv": render_csv}[fmt](name, header, rows)
            path = os.path.join(d, f"{name}-{stamp}.{fmt}")
            with open(path, "w") as f:
                f.write(body)
            job.file_path, job.file_size, job.row_count = path, os.path.getsize(path), len(rows)
        job.status = ExportJob.STATUS_COMPLETED
        job.finished_at = timezone.now()
        job.save()
        return {"status": "COMPLETED", "rows": job.row_count}
    except Exception as e:
        job.status = ExportJob.STATUS_FAILED
        job.error = str(e)[:1000]
        job.finished_at = timezone.now()
        job.save()
        return {"status": "FAILED", "error": str(e)[:300]}
