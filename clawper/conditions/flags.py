"""
Flag detection and verification condition.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from clawper.conditions.base import ConditionResult, EvaluationContext, SuccessCondition
from clawper.config import FlagConditionConfig


# A raw pattern hit is only trusted when something around it actually says it is
# a flag. A bare 32-hex string in console output is far more often an MD5 sum,
# an NTLM hash, a git object id or an asset fingerprint, so unlabelled matches
# are kept as candidates and never satisfy a success condition.
_DECLARATION_RE = re.compile(
    r"(?P<kind>user|local|root|admin|administrator|system)?"
    r"\W{0,4}flags?\W{0,6}(?:is\W{0,4}|was\W{0,4})?$",
    re.IGNORECASE,
)

# "FLAG: <value> (USER)" — a label sitting immediately after the match types it.
_TRAILING_KIND_RE = re.compile(
    r"^\W{0,4}\(?\b(?P<kind>user|local|root|admin|administrator|system)\b",
    re.IGNORECASE,
)

_KIND_TO_TYPE = {
    "user": "user",
    "local": "user",
    "root": "root",
    "admin": "root",
    "administrator": "root",
    "system": "root",
}

# Regex quantifiers ({32}) are not flag delimiters; HTB\{...\} braces are.
_QUANTIFIER_RE = re.compile(r"\{\d+(?:,\d*)?\}")

# Clawper's own bookkeeping, by workspace-relative path. Rescanning these
# re-confirms every value ever recorded — including past false positives — so
# one bad match would launder itself into a permanent "capture". Matched by
# path, not name, so a flags.txt the agent drops elsewhere is still read.
_SKIP_PATHS = {
    "clawper_state.json",
    "report.json",
    "REPORT.md",
    "WRITEUP.md",
    "flags/flags.txt",
    "flags/flags.json",
}
_SKIP_TOPLEVEL_DIRS = {"logs"}


def _is_self_evident(pattern: str) -> bool:
    """True for wrapped formats (HTB{...}, flag{...}) that prove themselves."""
    return "{" in _QUANTIFIER_RE.sub("", pattern)


def _evidence_text(raw: str) -> Optional[str]:
    """Return only the *real command output* from a stream-json agent transcript.

    The agent stream interleaves the model's own narration (`assistant` text)
    with the actual output of the tools it ran (`user` -> `tool_result`). A flag
    is only trustworthy when the TARGET produced it — i.e. it came back in a
    tool result — never when the model merely typed the string into its prose
    (models happily invent plausible, correctly-formatted flags in a report).

    This parses the transcript and concatenates just the tool-result payloads,
    EXCLUDING results from external-knowledge tools (WebFetch / WebSearch and the
    like): a flag must be produced by acting on the target, not scraped from a
    public walkthrough. The final `result` summary event is also excluded — it
    is the model's own narration, not tool output. Returns None when the text is
    not stream-json (plain-text agent mode), so the caller can fall back to
    scanning the whole output as before.
    """
    saw_json = False
    chunks: List[str] = []
    objs: List[Dict] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        saw_json = True
        if isinstance(obj, dict):
            objs.append(obj)

    if not saw_json:
        return None

    # Pass 1: map each tool_use id -> the tool that produced it, so we can drop
    # results from tools that fetch external knowledge rather than the target.
    _EXTERNAL = {"webfetch", "websearch", "web_search", "web_fetch", "fetch"}

    def _is_external(name: str) -> bool:
        n = (name or "").lower()
        return n in _EXTERNAL or "websearch" in n or "webfetch" in n

    tool_by_id: Dict[str, str] = {}
    for obj in objs:
        if obj.get("type") != "assistant":
            continue
        for b in (obj.get("message", {}) or {}).get("content", []) or []:
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id"):
                tool_by_id[b["id"]] = b.get("name", "")

    def _collect(content) -> None:
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, list):
            for c in content:
                if isinstance(c, dict):
                    if isinstance(c.get("text"), str):
                        chunks.append(c["text"])
                    elif isinstance(c.get("content"), (str, list)):
                        _collect(c.get("content"))

    # Pass 2: collect tool_result payloads, skipping external-knowledge results.
    for obj in objs:
        if obj.get("type") not in ("user", "tool_result"):
            continue
        msg = obj.get("message", obj)
        blocks = (msg or {}).get("content", []) if isinstance(msg, dict) else []
        if isinstance(blocks, str):
            chunks.append(blocks)
            continue
        if not isinstance(blocks, list):
            continue
        for b in blocks:
            if not isinstance(b, dict) or b.get("type") not in ("tool_result", "tool-result"):
                continue
            if _is_external(tool_by_id.get(b.get("tool_use_id", ""), "")):
                continue
            _collect(b.get("content", ""))

    return "\n".join(chunks)


class FlagCondition(SuccessCondition):
    """
    Evaluates whether required CTF flags have been obtained and verified.
    Scans agent output, history, and workspace files for flag patterns.

    Matches are split into *confirmed* flags (found inside a real flag file, or
    labelled as a flag where they appear, or in a self-delimiting format) and
    *candidates*. Only confirmed flags count towards the required count and the
    user/root requirements.
    """

    def __init__(self, config: Optional[FlagConditionConfig] = None, name: str = "FlagCondition"):
        super().__init__(name=name)
        self.config = config or FlagConditionConfig()
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.config.patterns]
        self._self_evident = [_is_self_evident(p) for p in self.config.patterns]
        self.user_pattern = re.compile(self.config.user_flag_pattern, re.IGNORECASE) if self.config.user_flag_pattern else None
        self.root_pattern = re.compile(self.config.root_flag_pattern, re.IGNORECASE) if self.config.root_flag_pattern else None
        self._verify_mem: Dict[str, bool] = {}  # in-process cache: flag -> accepted

    def _load_verify_cache(self, workspace_dir: Optional[Path]) -> Dict[str, str]:
        if not workspace_dir:
            return {}
        cache_path = workspace_dir / self.config.verify_cache_file
        try:
            return json.loads(cache_path.read_text())
        except Exception:
            return {}

    def _save_verify_cache(self, workspace_dir: Optional[Path], cache: Dict[str, str]) -> None:
        if not workspace_dir:
            return
        cache_path = workspace_dir / self.config.verify_cache_file
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True))
        except Exception:
            pass

    def _verify_flags(self, flags, workspace_dir: Optional[Path]):
        """Return only flags an external verifier accepts (when one is configured).

        Uses a persistent cache (workspace) + an in-process cache so each flag is
        submitted at most once. Exit codes: 0=valid, 3=invalid, else=unknown/retry.
        With no verify_command configured, all flags pass through unchanged.
        """
        cmd = self.config.verify_command
        if not cmd:
            return set(flags), {}
        import subprocess, os

        cache = self._load_verify_cache(workspace_dir)   # flag -> "valid"/"invalid"
        accepted, statuses, dirty = set(), {}, False
        for flag in flags:
            status = cache.get(flag) or ("valid" if self._verify_mem.get(flag) else None)
            if status is None:
                try:
                    env = dict(os.environ, CLAWPER_FLAG=flag)
                    rc = subprocess.run(
                        cmd, shell=True, env=env,
                        cwd=str(workspace_dir) if workspace_dir else None,
                        capture_output=True, text=True, timeout=self.config.verify_timeout,
                    ).returncode
                except Exception:
                    rc = 2  # unknown -> do not cache, retry next iteration
                if rc == 0:
                    status = "valid"
                elif rc == 3:
                    status = "invalid"
                else:
                    statuses[flag] = "unknown"
                    continue  # not credited this round, not cached
                cache[flag] = status
                dirty = True
            if status == "valid":
                accepted.add(flag)
                self._verify_mem[flag] = True
            statuses[flag] = status
        if dirty:
            self._save_verify_cache(workspace_dir, cache)
        return accepted, statuses

    def _extract_typed(
        self,
        text: str,
        trusted: bool = False,
        default_type: str = "generic",
    ) -> Dict[str, Tuple[bool, str]]:
        """Extract flags from raw text as {flag: (confirmed, flag_type)}.

        `trusted` marks text that is itself proof of capture (the contents of a
        user.txt / root.txt), in which case every match is confirmed.
        """
        found: Dict[str, Tuple[bool, str]] = {}
        if not text:
            return found

        for pattern, self_evident in zip(self._compiled_patterns, self._self_evident):
            for match in pattern.finditer(text):
                raw = match.group(0)
                if match.groups():
                    # If regex returns groups, pick the first non-empty one
                    raw = next((g for g in match.groups() if g), raw)
                cleaned = raw.strip().strip("'\"`")
                if len(cleaned) < 8:
                    continue

                line_start = text.rfind("\n", 0, match.start()) + 1
                prefix = text[line_start:match.start()][-64:].rstrip()
                line_end = text.find("\n", match.end())
                suffix = text[match.end():line_end if line_end != -1 else len(text)][:32]

                declaration = _DECLARATION_RE.search(prefix)
                flag_type = default_type
                if declaration and declaration.group("kind"):
                    flag_type = _KIND_TO_TYPE.get(declaration.group("kind").lower(), default_type)
                if flag_type == "generic":
                    trailing = _TRAILING_KIND_RE.search(suffix)
                    if trailing:
                        flag_type = _KIND_TO_TYPE.get(trailing.group("kind").lower(), "generic")

                # A loose pattern (bare 32-hex) is a flag ONLY when it was read
                # out of a real flag file (user.txt / root.txt). A "flag"-ish
                # label in arbitrary agent output is NOT enough: an NTProofStr,
                # MD5 or wordlist line routinely lands next to the word "flag".
                # Self-delimiting formats (HTB{...}) still prove themselves
                # wherever they appear.
                confirmed = trusted or self_evident

                prev_confirmed, prev_type = found.get(cleaned, (False, "generic"))
                found[cleaned] = (
                    confirmed or prev_confirmed,
                    prev_type if prev_type != "generic" else flag_type,
                )
        return found

    def _scan_workspace_files(self, workspace_dir: Optional[Path]) -> Dict[str, Dict[str, Tuple[bool, str]]]:
        """Scan workspace files for flag content, keyed by relative path."""
        found_in_files: Dict[str, Dict[str, Tuple[bool, str]]] = {}
        if not workspace_dir or not workspace_dir.exists():
            return found_in_files

        flag_file_names = {name.lower() for name in self.config.flag_files}

        for file_path in workspace_dir.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                rel_path = file_path.relative_to(workspace_dir)
            except ValueError:
                continue
            # Skip hidden files, git directories, and Clawper's own bookkeeping
            if any(part.startswith(".") for part in rel_path.parts):
                continue
            if rel_path.as_posix() in _SKIP_PATHS:
                continue
            if rel_path.parts and rel_path.parts[0] in _SKIP_TOPLEVEL_DIRS:
                continue

            fname_lower = file_path.name.lower()
            # An exact flag-file name is proof of capture; other text files are
            # only scanned for labelled matches.
            is_flag_file = fname_lower in flag_file_names
            if not (is_flag_file or fname_lower.endswith((".txt", ".json", ".log", ".out"))):
                continue

            try:
                # Limit size to 1MB to prevent scanning giant binaries
                if file_path.stat().st_size > 1024 * 1024:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            default_type = "generic"
            if is_flag_file:
                stem = fname_lower.rsplit(".", 1)[0]
                if stem == "user":
                    default_type = "user"
                elif stem == "root":
                    default_type = "root"

            extracted = self._extract_typed(content, trusted=is_flag_file, default_type=default_type)
            if extracted:
                found_in_files[str(rel_path)] = extracted

        return found_in_files

    def evaluate(self, context: EvaluationContext) -> ConditionResult:
        found: Dict[str, Tuple[bool, str]] = {}
        origins: Dict[str, str] = {}
        sources: Dict[str, List[str]] = {}

        def merge(extracted: Dict[str, Tuple[bool, str]], source: str) -> None:
            if not extracted:
                return
            for flag, (confirmed, flag_type) in extracted.items():
                prev_confirmed, prev_type = found.get(flag, (False, "generic"))
                found[flag] = (
                    confirmed or prev_confirmed,
                    prev_type if prev_type != "generic" else flag_type,
                )
                origins.setdefault(flag, source)
            sources[source] = sorted(extracted.keys())

        # 1. Check current agent output. Confirm flags ONLY from real command
        # output (tool results), never from the model's own narration — a model
        # will readily write a correctly-formatted but entirely invented flag
        # into a "report". _evidence_text() returns None for plain-text agent
        # mode, where no such split exists and we scan the whole output.
        cur_evidence = _evidence_text(context.agent_output)
        merge(self._extract_typed(cur_evidence if cur_evidence is not None else context.agent_output),
              "current_output")

        # 2. Check previous agent outputs (same tool-result-only rule)
        for idx, prev_out in enumerate(context.all_outputs):
            prev_evidence = _evidence_text(prev_out)
            merge(self._extract_typed(prev_evidence if prev_evidence is not None else prev_out),
                  f"output_iter_{idx+1}")

        # 3. Check workspace files
        for rel_path, flags_in_file in self._scan_workspace_files(context.workspace_dir).items():
            merge(flags_in_file, f"file:{rel_path}")

        # 4. Check already recorded flags in state. These are only re-confirmed
        # if they still carry real provenance: a user/root type (which is only
        # ever assigned by reading a user.txt/root.txt flag file) or a
        # self-delimiting format. A bare generic hex recorded by an older/looser
        # run is NOT trusted back into a capture — it stays a candidate unless
        # re-found in a flag file this evaluation.
        for state_flag in context.state.get("captured_flags", []) or []:
            if isinstance(state_flag, dict):
                flag_val = state_flag.get("flag") or state_flag.get("value")
                flag_type = state_flag.get("flag_type") or "generic"
            else:
                flag_val, flag_type = state_flag, "generic"
            if not flag_val:
                continue
            val_self_evident = any(
                pat.search(flag_val)
                for pat, se in zip(self._compiled_patterns, self._self_evident)
                if se
            )
            trust = flag_type in ("user", "root") or val_self_evident
            prev_confirmed, prev_type = found.get(flag_val, (False, "generic"))
            found[flag_val] = (
                trust or prev_confirmed,
                prev_type if prev_type != "generic" else flag_type,
            )
            origins.setdefault(flag_val, "state")

        # A match on an exactly known flag is proof in itself
        for specific in self.config.specific_flags:
            if specific in found:
                found[specific] = (True, found[specific][1])

        confirmed_flags = {flag: ftype for flag, (ok, ftype) in found.items() if ok}
        candidate_flags = sorted(flag for flag, (ok, _) in found.items() if not ok)

        # External verification gate: when a verify_command is configured, a flag
        # is credited only if the verifier accepts it (e.g. HTB flag submission).
        # Extracted-but-unverified flags are demoted to candidates, so a wrong or
        # unsubmittable string can never satisfy the success condition.
        verify_statuses: Dict[str, str] = {}
        if self.config.verify_command and confirmed_flags:
            accepted, verify_statuses = self._verify_flags(list(confirmed_flags), context.workspace_dir)
            for flag in list(confirmed_flags):
                if flag not in accepted:
                    candidate_flags.append(flag)
                    del confirmed_flags[flag]
            candidate_flags = sorted(set(candidate_flags))

        all_flags = sorted(confirmed_flags)

        # Check against specific flags if configured
        if self.config.specific_flags:
            missing_specific = [f for f in self.config.specific_flags if f not in confirmed_flags]
            met_specific = len(missing_specific) == 0
        else:
            missing_specific = []
            met_specific = True

        # Check required count
        total_unique = len(all_flags)
        met_count = total_unique >= self.config.required_count

        # Check user/root flag distinction if enabled. There is deliberately no
        # count-based fallback here: "we have N flags" is not evidence that one
        # of them came out of user.txt or root.txt.
        user_flag_found = False
        root_flag_found = False

        if self.config.require_user_flag:
            if self.user_pattern:
                user_flag_found = any(self.user_pattern.search(f) for f in all_flags)
            else:
                user_flag_found = any(t == "user" for t in confirmed_flags.values())

        if self.config.require_root_flag:
            if self.root_pattern:
                root_flag_found = any(self.root_pattern.search(f) for f in all_flags)
            else:
                root_flag_found = any(t == "root" for t in confirmed_flags.values())

        user_root_met = True
        if self.config.require_user_flag and not user_flag_found:
            user_root_met = False
        if self.config.require_root_flag and not root_flag_found:
            user_root_met = False

        met = met_count and met_specific and user_root_met

        details_parts = [
            f"Captured {total_unique}/{self.config.required_count} unique flags."
        ]
        if all_flags:
            details_parts.append(f"Flags: {', '.join(all_flags)}")
        if self.config.verify_command:
            n_invalid = sum(1 for s in verify_statuses.values() if s == "invalid")
            n_unknown = sum(1 for s in verify_statuses.values() if s == "unknown")
            details_parts.append(f"HTB-verified: {len(all_flags)} valid" +
                                 (f", {n_invalid} rejected" if n_invalid else "") +
                                 (f", {n_unknown} unverifiable(retry)" if n_unknown else "") + ".")
        if self.config.specific_flags and missing_specific:
            details_parts.append(f"Missing specific flags: {', '.join(missing_specific)}")
        if self.config.require_user_flag:
            details_parts.append(f"User flag: {'[YES]' if user_flag_found else '[NO]'}")
        if self.config.require_root_flag:
            details_parts.append(f"Root flag: {'[YES]' if root_flag_found else '[NO]'}")
        if candidate_flags:
            details_parts.append(
                f"Ignored {len(candidate_flags)} unlabelled candidate(s) "
                f"(not read from a flag file and not declared as a flag)."
            )

        return ConditionResult(
            name=self.name,
            met=met,
            details=" ".join(details_parts),
            data={
                "captured_flags": all_flags,
                "flag_records": [
                    {
                        "flag": flag,
                        "flag_type": confirmed_flags[flag],
                        "origin": origins.get(flag, "output"),
                    }
                    for flag in all_flags
                ],
                "candidate_flags": candidate_flags,
                "sources": sources,
                "count": total_unique,
                "required_count": self.config.required_count,
                "user_flag_found": user_flag_found,
                "root_flag_found": root_flag_found,
            },
        )
