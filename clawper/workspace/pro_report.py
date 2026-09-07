"""
Professional engagement report generator.

Produces a polished, human-readable Markdown penetration-test / CTF report from
the final run state plus the artifacts harvested into the workspace. It is
entirely data-driven (no model call), so it works even when the agent itself
was interrupted or rate-limited.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from clawper.config import ClawperConfig

# --- artifact classification -------------------------------------------------

# (category label, ordered list of substrings matched case-insensitively)
_LOOT_CATEGORIES: List[Tuple[str, Tuple[str, ...]]] = [
    ("Kerberos tickets (ccache)", (".ccache",)),
    ("Certificates / PFX (PKINIT, code-signing)", (".pfx", ".pem", ".cer", ".crt", "cert")),
    ("Credential hashes (NT / Kerberos / DCC2)", (".hash", "hashes", "nt_hash", "dcc2", "krb", "kerberoast", "roast", "sssd", "secretsdump", "lsa", "secrets")),
    ("SAM / SYSTEM / registry hives", (".sav", "sam", "system", "security", "dpapi")),
    ("SSH keys & passphrases", ("id_rsa", "_key", ".key", "passphrase", "rootkey")),
    ("Cleartext credentials", ("pass", "creds", "cred", "login", "pw_", "logins.json", "key4.db")),
    ("AD / directory enumeration", ("users", "bloodhound", "domain", "dcsync", "trust", "policy")),
    ("Databases & backups", (".db", "backup", ".tgz", "dbbk", ".sql")),
    ("Web / app artifacts", (".html", "dashboard", "page", "fleet", "policies.json")),
]

# host tokens we understand, mapped to a friendly label
_HOST_TOKENS: List[Tuple[str, str]] = [
    ("web01", "web01"), ("file01", "FILE01"), ("client01", "CLIENT01"),
    ("client02", "CLIENT02"), ("client03", "CLIENT03"), ("client04", "CLIENT04"),
    ("sql01", "SQL01"), ("prov", "prov"), ("registry", "registry"),
    ("dc01", "DC"), ("_dc", "DC"), ("administrator", "Domain (Administrator)"),
]

_CYBER_SIG = "safeguards flagged"


def _fmt_ts(ts: Optional[float]) -> str:
    if not ts:
        return "n/a"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fmt_dur(seconds: float) -> str:
    seconds = int(seconds or 0)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


class ProfessionalReportBuilder:
    """Builds a professional Markdown report from run state + workspace loot."""

    def __init__(self, workspace_dir: Path, config: ClawperConfig):
        self.workspace_dir = Path(workspace_dir)
        self.config = config

    # -- artifact / host discovery -------------------------------------------

    def _loot_files(self) -> List[Path]:
        files: List[Path] = []
        for sub in ("loot", ""):
            d = self.workspace_dir / sub if sub else self.workspace_dir
            if d.exists():
                files.extend([p for p in d.rglob("*") if p.is_file()])
        # de-dup, keep interesting artifacts, drop our own report/state files
        skip = {"report.json", "clawper_state.json", "WRITEUP.md", "REPORT.md"}
        seen, out = set(), []
        for p in files:
            if p.name in skip or p.suffix == ".log":
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
        return out

    def _categorize(self, files: List[Path]) -> Dict[str, List[str]]:
        buckets: Dict[str, List[str]] = {}
        for p in files:
            low = p.name.lower()
            placed = False
            for label, subs in _LOOT_CATEGORIES:
                if any(s in low for s in subs):
                    buckets.setdefault(label, []).append(p.name)
                    placed = True
                    break
            if not placed:
                buckets.setdefault("Other artifacts", []).append(p.name)
        return buckets

    def _infer_hosts(self, files: List[Path], flags: List[Dict]) -> Dict[str, List[str]]:
        """Map host -> evidence artifacts that indicate access/compromise."""
        hosts: Dict[str, List[str]] = {}
        for p in files:
            low = p.name.lower()
            for token, label in _HOST_TOKENS:
                if token in low:
                    hosts.setdefault(label, [])
                    if p.name not in hosts[label]:
                        hosts[label].append(p.name)
        return hosts

    # -- narrative from history ----------------------------------------------

    def _timeline(self, history: List[Dict]) -> Tuple[List[Dict], int, int]:
        """Return (progress_iterations, errored_count, cyber_blocked_count)."""
        progress, errored, cyber = [], 0, 0
        for it in history:
            status = it.get("status", "completed")
            snippet = it.get("output_snippet", "") or ""
            err = it.get("error_message", "") or ""
            if status != "completed":
                errored += 1
                if _CYBER_SIG in snippet or _CYBER_SIG in err:
                    cyber += 1
                continue
            progress.append(it)
        return progress, errored, cyber

    # -- section builders -----------------------------------------------------

    def build(self, state: Dict[str, Any]) -> str:
        t = self.config.target
        flags = state.get("captured_flags", []) or []
        history = state.get("history", []) or []
        started = state.get("started_at")
        completed = state.get("completed_at") or time.time()
        duration = (completed - started) if (started and completed) else 0
        success = state.get("success", False)
        iterations = state.get("iterations_completed", 0)
        required = self.config.flags.required_count

        files = self._loot_files()
        buckets = self._categorize(files)
        hosts = self._infer_hosts(files, flags)
        progress_iters, errored, cyber = self._timeline(history)

        L: List[str] = []
        A = L.append

        # ---- Title & metadata
        A(f"# Penetration Test Report — {t.box_name or 'Target'}")
        A("")
        A(f"*Autonomous engagement executed by Clawper (Claude Code driver). Generated {_fmt_ts(completed)}.*")
        A("")
        A("| | |")
        A("|---|---|")
        A(f"| **Target** | {t.box_name or '-'} |")
        A(f"| **Entry point** | {t.ip or t.host or '-'} |")
        A(f"| **Platform** | {t.platform or '-'} |")
        if t.domain:
            A(f"| **Domain** | {t.domain} |")
        A(f"| **Outcome** | {'✅ All objectives met' if success else '⚠️ Partial — objectives not fully met'} |")
        A(f"| **Flags captured** | {len(flags)} of {required} required |")
        A(f"| **Hosts with evidence of access** | {len(hosts)} |")
        A(f"| **Iterations** | {iterations} ({len(progress_iters)} productive, {errored} errored) |")
        A(f"| **Wall-clock duration** | {_fmt_dur(duration)} |")
        A(f"| **Window** | {_fmt_ts(started)} → {_fmt_ts(completed)} |")
        A("")

        # ---- 1. Executive summary
        A("## 1. Executive Summary")
        A("")
        owned = ", ".join(sorted(hosts.keys())) if hosts else "none confirmed"
        A(
            f"This engagement targeted **{t.box_name or 'the environment'}** "
            f"(`{t.ip or t.host}`{', domain `' + t.domain + '`' if t.domain else ''}). "
            f"Over {iterations} autonomous iterations, the operation captured "
            f"**{len(flags)} of {required} objective flags** and gathered evidence of access to: "
            f"**{owned}**."
        )
        A("")
        if success:
            A("All defined success conditions were satisfied.")
        else:
            A(
                "The run ended **before all objectives were met**. "
                + (
                    f"The dominant limiting factor was upstream API cyber-safeguard rejections: "
                    f"**{cyber} of {errored} errored iterations** were blocked by the model's "
                    f"real-time cyber safeguards rather than by the target's defenses."
                    if cyber
                    else "See the Reliability section for the failure breakdown."
                )
            )
        A("")

        # ---- 2. Scope
        A("## 2. Scope & Authorisation")
        A("")
        A(f"- **In-scope entry host:** `{t.ip or t.host or '-'}` ({t.box_name or 'target'})")
        if t.domain:
            A(f"- **In-scope domain(s):** `{t.domain}`")
        A(f"- **Engagement type:** authorised {t.platform or 'lab'} exercise (training range).")
        A("- **Method:** unattended, tool-driven exploitation supervised by the Clawper loop.")
        A("")

        # ---- 3. Flags
        A("## 3. Objectives Captured")
        A("")
        if flags:
            A("| # | Flag | First seen (iteration) | Timestamp |")
            A("|---|------|------------------------|-----------|")
            for i, f in enumerate(flags, 1):
                fv = f.get("flag", str(f)) if isinstance(f, dict) else str(f)
                fi = f.get("iteration", "-") if isinstance(f, dict) else "-"
                ft = _fmt_ts(f.get("discovered_at")) if isinstance(f, dict) else "-"
                A(f"| {i} | `{fv}` | {fi} | {ft} |")
        else:
            A("_No flags were captured during this run._")
        A("")

        # ---- 4. Access gained
        A("## 4. Access Gained & Compromised Hosts")
        A("")
        if hosts:
            A("Access is inferred from the credential material, tickets, and secrets harvested into the workspace.")
            A("")
            A("| Host / scope | Evidence artifacts |")
            A("|---|---|")
            for host in sorted(hosts.keys()):
                ev = ", ".join(f"`{n}`" for n in sorted(hosts[host])[:6])
                more = "" if len(hosts[host]) <= 6 else f" (+{len(hosts[host]) - 6} more)"
                A(f"| **{host}** | {ev}{more} |")
        else:
            A("_No host-attributable access artifacts were recovered._")
        A("")

        # ---- 5. Credentials & secrets
        A("## 5. Credentials & Secrets Harvested")
        A("")
        if buckets:
            for label, subs in _LOOT_CATEGORIES:
                if label in buckets:
                    names = sorted(set(buckets[label]))
                    A(f"- **{label}** ({len(names)}): " + ", ".join(f"`{n}`" for n in names[:10])
                      + ("" if len(names) <= 10 else f" _(+{len(names) - 10} more)_"))
            if "Other artifacts" in buckets:
                names = sorted(set(buckets["Other artifacts"]))
                A(f"- **Other artifacts** ({len(names)}): " + ", ".join(f"`{n}`" for n in names[:10])
                  + ("" if len(names) <= 10 else f" _(+{len(names) - 10} more)_"))
        else:
            A("_No artifacts were written to the workspace._")
        A("")

        # ---- 6. Attack narrative
        A("## 6. Attack Narrative")
        A("")
        if progress_iters:
            A("Key productive iterations and the actions taken:")
            A("")
            flag_iters = {f.get("iteration") for f in flags if isinstance(f, dict)}
            for it in progress_iters:
                itn = it.get("iteration", "?")
                dur = it.get("duration", 0) or 0
                cmds = [c for c in (it.get("commands_run", []) or [])][:8]
                marker = "  🚩 **flag(s) captured**" if itn in flag_iters else ""
                A(f"### Iteration {itn} ({_fmt_dur(dur)}){marker}")
                if cmds:
                    A("```")
                    for c in cmds:
                        # commands are already prefixed (⚙  bash  $ ...); strip prefix noise
                        A(re.sub(r"^⚙\s*bash\s*\$\s*", "$ ", c))
                    A("```")
                snip = (it.get("output_snippet", "") or "").strip()
                if snip and _CYBER_SIG not in snip:
                    A(f"> {snip[:300]}")
                A("")
        else:
            A("_No productive iterations were recorded (all attempts errored)._")
        A("")

        # ---- 7. Reliability
        A("## 7. Run Reliability & Blockers")
        A("")
        A(f"- Total iterations: **{iterations}**")
        A(f"- Productive iterations: **{len(progress_iters)}**")
        A(f"- Errored iterations: **{errored}**")
        if cyber:
            A(f"- Of those, blocked by model cyber-safeguards (`[cyber]`): **{cyber}**")
        A(f"- Longest consecutive-error streak / stalls: **{state.get('stalls_count', 0)}**")
        last_err = state.get("last_error")
        if last_err:
            A(f"- Last recorded error: `{str(last_err)[:160]}`")
        A("")

        # ---- 8. Recommendations (tailored to what showed up)
        A("## 8. Remediation Recommendations")
        A("")
        for rec in self._recommendations(buckets, hosts, t):
            A(f"- {rec}")
        A("")

        # ---- Appendix A: condensed full timeline
        A("## Appendix A — Full Iteration Ledger")
        A("")
        A("| Iter | Status | Duration | Note |")
        A("|---|---|---|---|")
        for it in history:
            itn = it.get("iteration", "?")
            st = it.get("status", "?")
            dur = _fmt_dur(it.get("duration", 0) or 0)
            note = ""
            snip = (it.get("output_snippet", "") or it.get("error_message", "") or "").strip()
            if _CYBER_SIG in snip:
                note = "cyber-safeguard block"
            elif st != "completed":
                note = (snip[:60] + "…") if snip else st
            A(f"| {itn} | {st} | {dur} | {note} |")
        A("")

        # ---- Appendix B: artifact index
        A("## Appendix B — Artifact Index")
        A("")
        if files:
            for p in sorted(files, key=lambda x: str(x)):
                try:
                    rel = p.relative_to(self.workspace_dir)
                except ValueError:
                    rel = p
                size = p.stat().st_size if p.exists() else 0
                A(f"- `{rel}` ({size} bytes)")
        else:
            A("_None._")
        A("")
        A("---")
        A("*Generated by Clawper — autonomous CTF/pentest wrapper for Claude Code. "
          "This report is assembled from run telemetry and harvested artifacts; verify findings before use.*")

        return "\n".join(L)

    def _recommendations(self, buckets: Dict, hosts: Dict, target) -> List[str]:
        recs: List[str] = []
        joined = " ".join(k.lower() for k in buckets.keys())
        if any("kerberos" in k.lower() or "certificate" in k.lower() for k in buckets):
            recs.append("**Constrained/RBCD & S4U delegation:** review Kerberos delegation on service "
                        "accounts; the run collected impersonation tickets. Remove unnecessary delegation "
                        "and mark sensitive accounts *'Account is sensitive and cannot be delegated'*.")
        if "certificate" in joined or "pfx" in joined:
            recs.append("**AD CS / PKINIT:** audit certificate templates for ESC1-ESC8; restrict enrollment "
                        "and enable manager approval on templates permitting client-auth / arbitrary SAN.")
        if any("hash" in k.lower() or "sam" in k.lower() or "secretsdump" in k.lower() for k in buckets):
            recs.append("**Credential hygiene:** rotate all exposed account passwords and the KRBTGT key; "
                        "enable LSASS protection (RunAsPPL / Credential Guard) to hinder secret extraction.")
        if "ssh keys" in joined or "id_rsa" in joined:
            recs.append("**SSH key management:** remove reused/unprotected private keys from hosts, enforce "
                        "passphrases, and scope keys to least privilege.")
        if any("gmsa" in n.lower() for names in buckets.values() for n in names) or "gmsa" in joined:
            recs.append("**gMSA exposure:** restrict `ServiceAccountManagers`-style groups that can read gMSA "
                        "passwords; monitor `msDS-ManagedPassword` reads.")
        # generic, always-useful
        recs.append("**Segmentation:** the entry host doubled as a pivot into internal segments — enforce "
                    "east-west firewalling so a single foothold cannot reach the whole estate.")
        recs.append("**Detection:** ensure the SIEM alerts on the tradecraft observed (ticket requests, "
                    "secretsdump, DCSync-style replication, anomalous service-account logons).")
        return recs
