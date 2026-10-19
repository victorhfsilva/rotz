#!/usr/bin/env python3
"""
Rotz Recon CLI - orquestrador didatico de reconhecimento web.

Uso rapido:
    ./recon.py -d exemplo.com
    ./recon.py -d exemplo.com -d exemplo.com.br --preset deep --screenshots both
    ./recon.py -dL escopo.txt -n cliente --stages subdomains,probe,content,javascript

O script reaproveita os scripts em workflows/*/src como blocos de construcao,
escreve tudo em um diretorio por alvo e gera um relatorio _recon/summary.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

try:
    from urllib.parse import urlparse
except ImportError:
    urlparse = None


VERSION = "2.0"
SCRIPT_DIR = Path(__file__).resolve().parent


PRESETS: dict[str, list[str]] = {
    "passive": ["subdomains", "probe", "content"],
    "web": ["subdomains", "dns", "probe", "content", "javascript", "vulns"],
    "deep": ["subdomains", "infra", "dns", "probe", "content", "javascript", "fuzz", "vulns"],
    "full": ["subdomains", "asn", "infra", "dns", "probe", "content", "javascript", "fuzz", "vulns"],
    "subdomains": ["subdomains"],
}

STAGE_ALIASES = {
    "subs": "subdomains",
    "sub": "subdomains",
    "org": "asn",
    "hosts": "infra",
    "ports": "infra",
    "resolve": "probe",
    "resolve-probe": "probe",
    "fingerprint": "probe",
    "urls": "content",
    "crawl": "content",
    "js": "javascript",
    "fuzzing": "fuzz",
    "gf": "vulns",
}

STAGE_ORDER = [
    "subdomains",
    "asn",
    "infra",
    "dns",
    "probe",
    "content",
    "javascript",
    "fuzz",
    "vulns",
]


class StageError(RuntimeError):
    pass


class UI:
    def __init__(self, color: bool, quiet: bool = False):
        self.color = color
        self.quiet = quiet

    def _paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def title(self, text: str) -> None:
        if not self.quiet:
            print()
            print(self._paint(text, "1;36"))

    def step(self, text: str) -> None:
        if not self.quiet:
            print(self._paint(f"\n[>] {text}", "1;34"))

    def ok(self, text: str) -> None:
        if not self.quiet:
            print(self._paint(f"[+] {text}", "32"))

    def info(self, text: str) -> None:
        if not self.quiet:
            print(f"[*] {text}")

    def warn(self, text: str) -> None:
        print(self._paint(f"[!] {text}", "33"), file=sys.stderr)

    def error(self, text: str) -> None:
        print(self._paint(f"[x] {text}", "31"), file=sys.stderr)

    def raw(self, text: str) -> None:
        print(text)


@dataclass
class Layout:
    root: Path
    out: Path
    target: str

    @property
    def base(self) -> Path:
        return self.out / self.target

    @property
    def recondir(self) -> Path:
        return self.base / "_recon"

    @property
    def input_dir(self) -> Path:
        return self.base / "input"

    @property
    def domains_file(self) -> Path:
        return self.input_dir / "domains.txt"

    @property
    def ips_input(self) -> Path:
        return self.input_dir / "ips.txt"

    @property
    def subs_dir(self) -> Path:
        return self.base / "subs"

    @property
    def all_subs(self) -> Path:
        return self.subs_dir / "all.subs.txt"

    @property
    def all_live_urls(self) -> Path:
        return self.subs_dir / "all.live.subs.txt"

    @property
    def all_live_hosts(self) -> Path:
        return self.subs_dir / "all.live.hosts.txt"

    @property
    def dns_dir(self) -> Path:
        return self.base / "dns"

    @property
    def ips_dir(self) -> Path:
        return self.base / "ips"

    @property
    def all_ips(self) -> Path:
        return self.ips_dir / "all.ips.txt"

    @property
    def resolved_ips(self) -> Path:
        return self.ips_dir / "subdomains.resolved.ips.txt"

    @property
    def open_ports(self) -> Path:
        return self.ips_dir / "naabu" / "open_ports.txt"

    @property
    def content_dir(self) -> Path:
        return self.base / "content"

    @property
    def urls_dir(self) -> Path:
        return self.content_dir / "urls"

    @property
    def all_urls(self) -> Path:
        return self.urls_dir / "all.urls.txt"

    @property
    def gau_urls(self) -> Path:
        return self.urls_dir / "all.gau.urls.txt"

    @property
    def katana_urls(self) -> Path:
        return self.urls_dir / "all.katana.urls.txt"

    @property
    def cleaned_urls(self) -> Path:
        return self.urls_dir / "all.cleaned.urls.txt"

    @property
    def params_urls(self) -> Path:
        return self.urls_dir / "all.params.urls.txt"

    @property
    def js_urls(self) -> Path:
        return self.urls_dir / "all.js.urls.txt"

    @property
    def js_dir(self) -> Path:
        return self.content_dir / "javascript"

    @property
    def selected_js(self) -> Path:
        return self.js_dir / "all.javascript.txt"

    @property
    def js_downloads(self) -> Path:
        return self.js_dir / "downloads"

    @property
    def wordlists_dir(self) -> Path:
        return self.content_dir / "wordlists"

    @property
    def all_paths(self) -> Path:
        return self.wordlists_dir / "all.paths.txt"

    @property
    def fuzz_dir(self) -> Path:
        return self.content_dir / "fuzzing"

    @property
    def screenshots_dir(self) -> Path:
        return self.content_dir / "screenshots"

    @property
    def vuln_dir(self) -> Path:
        return self.content_dir / "vuln"

    @property
    def inventory_file(self) -> Path:
        return self.recondir / "inventory.jsonl"

    @property
    def excluded_file(self) -> Path:
        return self.recondir / "excluded.txt"

    @property
    def capped_live(self) -> Path:
        return self.recondir / "live.capped.txt"

    @property
    def log_file(self) -> Path:
        return self.recondir / "recon.log"

    @property
    def summary_md(self) -> Path:
        return self.recondir / "summary.md"

    @property
    def summary_json(self) -> Path:
        return self.recondir / "summary.json"

    @property
    def markers_dir(self) -> Path:
        return self.recondir / "markers"


@dataclass
class Stage:
    name: str
    description: str
    tools: list[str]
    watch: list[str]
    func: Callable[["Ctx"], None]


STAGES: dict[str, Stage] = {}


def register_stage(name: str, description: str, tools: list[str], watch: list[str]):
    def deco(func: Callable[["Ctx"], None]):
        STAGES[name] = Stage(name, description, tools, watch, func)
        return func

    return deco


@dataclass
class StageResult:
    name: str
    status: str
    seconds: float
    deltas: dict[str, int] = field(default_factory=dict)
    note: str = ""


@dataclass
class Ctx:
    args: argparse.Namespace
    layout: Layout
    domains: list[str]
    ui: UI
    inventory: list[dict] = field(default_factory=list)
    results: list[StageResult] = field(default_factory=list)
    soft_failures: int = 0
    started: float = field(default_factory=time.time)

    def log(self, text: str) -> None:
        self.layout.log_file.parent.mkdir(parents=True, exist_ok=True)
        with self.layout.log_file.open("a", encoding="utf-8") as fh:
            fh.write(text.rstrip("\n") + "\n")

    def echo(self, text: str) -> None:
        if not self.args.quiet:
            print(text)

    def notify_flag(self) -> str:
        return "true" if self.args.notify else "false"


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ts_short() -> str:
    return datetime.now().strftime("%H:%M:%S")


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0]
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    return value.strip("-._") or "target"


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("#")[0].split("?")[0].split("/")[0]
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if value.startswith("["):
        value = value.split("]")[0].lstrip("[")
    else:
        value = value.split(":")[0]
    value = value.strip("*.").strip(".")
    return value


def valid_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    pattern = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
    return bool(pattern.match(value))


def read_lines(path: Path, skip_comments: bool = True) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            lines = []
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if skip_comments and line.startswith("#"):
                    continue
                lines.append(line)
            return lines
    except OSError:
        return []


def uniq(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    materialized = list(lines)
    with path.open("w", encoding="utf-8") as fh:
        if materialized:
            fh.write("\n".join(materialized) + "\n")


def touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


def merge_into(path: Path, lines: Iterable[str]) -> int:
    existing = set(read_lines(path))
    new_lines = []
    added = 0
    for line in lines:
        line = line.strip()
        if not line or line in existing:
            continue
        existing.add(line)
        new_lines.append(line)
        added += 1
    if new_lines:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(new_lines) + "\n")
    return added


def host_of(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("//"):
        value = "http:" + value
    if "://" not in value:
        value = "http://" + value
    try:
        parsed = urlparse(value)
        return (parsed.hostname or "").rstrip(".").lower()
    except Exception:
        return ""


def human_seconds(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(int(seconds), 60)
    return f"{minutes}m{sec:02d}s"


def has_content(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def tool_path(name: str) -> str | None:
    if os.path.sep in name:
        p = Path(name)
        return str(p) if p.is_file() else None
    return shutil.which(name)


def resolve_wordlist(root: Path, value: str, kind: str) -> Path:
    aliases = {
        "subdomains": {
            "small": "subdomains-top1million-5000.txt",
            "medium": "subdomains-top1million-20000.txt",
            "large": "subdomains-top1million-110000.txt",
            "huge": "Domains_ProbWL.txt",
        },
        "directories": {
            "small": "fuzz-Bo0oM.txt",
            "default": "fuzz-Bo0oM.txt",
        },
    }
    if value in aliases.get(kind, {}):
        return root / "wordlists" / kind / aliases[kind][value]
    candidate = Path(value)
    if candidate.is_file():
        return candidate
    candidate = root / "wordlists" / kind / value
    if candidate.is_file():
        return candidate
    candidate = root / value
    return candidate


def ensure_tool_available(ctx: Ctx, tool: str, stage: str) -> None:
    if not tool_path(tool):
        raise StageError(
            f"ferramenta '{tool}' nao encontrada no PATH (necessaria para a etapa '{stage}'). "
            "Use --check para ver o que falta."
        )


def run_cmd(
    ctx: Ctx,
    cmd: list[str | Path],
    label: str,
    stdin_text: str | None = None,
    timeout: int | None = None,
    merge_output: bool = True,
) -> subprocess.CompletedProcess:
    cmd = [str(part) for part in cmd]
    rendered = " ".join(shlex.quote(part) for part in cmd)
    ctx.log(f"\n[{now()}] $ {rendered}")
    if ctx.args.dry_run:
        ctx.info(f"dry-run: {rendered}")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    if ctx.args.verbose:
        ctx.echo(f"    $ {rendered}")

    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ctx.layout.base),
            input=stdin_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_output else subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise StageError(f"comando nao encontrado: {cmd[0]} ({exc})") from exc
    except subprocess.TimeoutExpired as exc:
        ctx.log(f"[timeout] {label} apos {timeout}s")
        raise StageError(f"timeout de {timeout}s em {label}") from exc

    output = proc.stdout or ""
    ctx.log(output)
    if not merge_output and proc.stderr:
        ctx.log(f"[stderr]\n{proc.stderr}")
    if ctx.args.verbose and output.strip():
        ctx.echo(output.rstrip())
    if proc.returncode != 0:
        ctx.ui.warn(f"{label}: codigo de saida {proc.returncode}")
    ctx.log(f"[{now()}] < {label} rc={proc.returncode} em {human_seconds(time.time() - started)}")
    return proc


def run_py(ctx: Ctx, relative_script: str, *args: str | Path) -> subprocess.CompletedProcess:
    script = ctx.layout.root / "workflows" / relative_script
    if not script.is_file():
        raise StageError(f"script interno nao encontrado: {script}")
    timeout = ctx.args.stage_timeout or None
    return run_cmd(ctx, [sys.executable, "-u", script, *args], label=script.name, timeout=timeout)


def soft(ctx: Ctx, label: str, func: Callable[..., object], *args: object, **kwargs: object) -> object | None:
    try:
        return func(*args, **kwargs)
    except StageError as exc:
        ctx.soft_failures += 1
        ctx.ui.warn(f"{label}: {exc} (continuando)")
        return None


def collect_new_lines(proc: subprocess.CompletedProcess) -> list[str]:
    if not proc.stdout:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def scope_roots(ctx: Ctx) -> list[str]:
    roots = list(ctx.domains)
    for extra in ctx.args.scope or []:
        normalized = normalize_domain(extra)
        if normalized and normalized not in roots:
            roots.append(normalized)
    return roots


def exclusion_patterns(ctx: Ctx) -> list[re.Pattern]:
    return [re.compile(pattern, re.IGNORECASE) for pattern in (ctx.args.exclude or [])]


def in_scope(value: str, roots: list[str], excluded: list[re.Pattern], is_url: bool = False) -> bool:
    host = host_of(value) if is_url else normalize_domain(value)
    if not host:
        return False
    for pattern in excluded:
        if pattern.search(host) or pattern.search(value):
            return False
    return any(host == root or host.endswith("." + root) for root in roots)


def filter_scope_file(ctx: Ctx, path: Path, is_url: bool = False) -> int:
    if ctx.args.no_scope_filter or not path.is_file():
        return 0
    roots = scope_roots(ctx)
    excluded = exclusion_patterns(ctx)
    kept: list[str] = []
    dropped: list[str] = []
    for value in read_lines(path):
        if in_scope(value, roots, excluded, is_url=is_url):
            kept.append(value)
        else:
            dropped.append(value)
    if dropped:
        merge_into(ctx.layout.excluded_file, uniq(dropped))
        write_lines(path, kept)
    return len(dropped)


def snapshot(ctx: Ctx) -> dict[str, int]:
    L = ctx.layout
    gf_files = list(L.vuln_dir.glob("*.txt")) if L.vuln_dir.is_dir() else []
    return {
        "dominios": count_lines(L.domains_file),
        "IPs": count_lines(L.all_ips),
        "subdominios": count_lines(L.all_subs),
        "vivos": count_lines(L.all_live_urls),
        "URLs": count_lines(L.all_urls),
        "URLs limpas": count_lines(L.cleaned_urls),
        "params": count_lines(L.params_urls),
        "JS": count_lines(L.selected_js),
        "portas": count_lines(L.open_ports),
        "DNS TXT": count_lines(L.dns_dir / "txt_records.dns.txt"),
        "GF hits": sum(count_lines(path) for path in gf_files),
    }


def delta(before: dict[str, int], after: dict[str, int], keys: list[str]) -> dict[str, int]:
    return {key: after.get(key, 0) - before.get(key, 0) for key in keys if after.get(key, 0) - before.get(key, 0)}


def cap_live(ctx: Ctx) -> Path:
    L = ctx.layout
    limit = ctx.args.max_hosts or 0
    if limit <= 0:
        return L.all_live_urls

    preferred: list[str] = []
    rest: list[str] = []
    for record in ctx.inventory:
        url = record.get("url") or ""
        status = record.get("status_code")
        if url and isinstance(status, int) and 200 <= status < 400:
            preferred.append(url)
        elif url:
            rest.append(url)

    if not preferred and not rest:
        preferred = read_lines(L.all_live_urls)

    chosen = uniq(preferred + rest)[:limit]
    write_lines(L.capped_live, chosen)
    if len(chosen) < count_lines(L.all_live_urls):
        ctx.ui.info(f"limitando conteudo/JS/fuzzing a {len(chosen)} hosts (--max-hosts)")
    return L.capped_live


def marker_path(ctx: Ctx, stage: str) -> Path:
    return ctx.layout.markers_dir / f"{stage}.done"


def write_marker(ctx: Ctx, stage: str) -> None:
    path = marker_path(ctx, stage)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{now()}\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Etapas
# ---------------------------------------------------------------------------


@register_stage(
    "subdomains",
    "Descoberta de subdominios passiva (subfinder/chaos/github) e brutal force opcional (puredns).",
    ["subfinder"],
    ["subdominios"],
)
def stage_subdomains(ctx: Ctx) -> None:
    L = ctx.layout
    ensure_tool_available(ctx, "subfinder", "subdomains")
    L.subs_dir.mkdir(parents=True, exist_ok=True)
    touch(L.all_subs)

    notify = ctx.notify_flag()
    soft(ctx, "subfinder", run_py, ctx, "subdomains/src/subfinder_enum.py", L.domains_file, L.subs_dir, notify)

    use_chaos = ctx.args.chaos
    if use_chaos is None:
        use_chaos = bool(os.environ.get("PDCP_API_KEY"))
    if use_chaos:
        ensure_tool_available(ctx, "chaos", "subdomains")
        soft(ctx, "chaos", run_py, ctx, "subdomains/src/chaos_enum.py", L.domains_file, L.subs_dir, notify)

    use_github = ctx.args.github
    if use_github is None:
        use_github = bool(os.environ.get("GITHUB_TOKEN"))
    if use_github:
        ensure_tool_available(ctx, "github-subdomains", "subdomains")
        soft(ctx, "github", run_py, ctx, "subdomains/src/github_enum.py", L.domains_file, L.subs_dir, notify)

    if ctx.args.bruteforce:
        ensure_tool_available(ctx, "puredns", "subdomains")
        wordlist = resolve_wordlist(L.root, ctx.args.wordlist_subdomains, "subdomains")
        if not wordlist.is_file():
            raise StageError(f"wordlist de subdominios nao encontrada: {wordlist}")
        found: list[str] = []
        for domain in ctx.domains:
            cmd: list[str | Path] = ["puredns", "bruteforce", wordlist, domain, "-q"]
            if ctx.args.resolvers:
                cmd += ["-r", ctx.args.resolvers]
            proc = soft(ctx, f"puredns:{domain}", run_cmd, ctx, cmd, f"puredns:{domain}", None, ctx.args.stage_timeout or None, False)
            if isinstance(proc, subprocess.CompletedProcess):
                found.extend(collect_new_lines(proc))
        added = merge_into(L.all_subs, uniq(found))
        ctx.ui.info(f"puredns: {added} novos registros")

    run_py(ctx, "subdomains/src/clean_domains.py", L.all_subs)
    removed = filter_scope_file(ctx, L.all_subs)
    if removed:
        ctx.ui.info(f"{removed} subdominios fora de escopo movidos para _recon/excluded.txt")


@register_stage(
    "asn",
    "Descoberta de blocos de IP por organizacao (ASN) via metabigor.",
    ["metabigor"],
    ["IPs"],
)
def stage_asn(ctx: Ctx) -> None:
    if not ctx.args.org:
        raise StageError("a etapa 'asn' exige --org \"Nome da Organizacao\"")
    ensure_tool_available(ctx, "metabigor", "asn")
    ctx.layout.ips_dir.mkdir(parents=True, exist_ok=True)
    touch(ctx.layout.all_ips)
    if has_content(ctx.layout.ips_input):
        merge_into(ctx.layout.all_ips, read_lines(ctx.layout.ips_input))
    run_py(
        ctx,
        "organization/src/asn_discovery.py",
        ctx.args.org,
        ctx.layout.ips_dir,
        ctx.notify_flag(),
    )


@register_stage(
    "dns",
    "Coleta de registros DNS (dnsx -recon), CNAME, TXT/SPF e reverse DNS.",
    ["dnsx", "hakrevdns"],
    ["DNS TXT"],
)
def stage_dns(ctx: Ctx) -> None:
    L = ctx.layout
    if not has_content(L.all_subs):
        raise StageError("all.subs.txt vazio; rode a etapa 'subdomains' primeiro")
    ensure_tool_available(ctx, "dnsx", "dns")
    L.dns_dir.mkdir(parents=True, exist_ok=True)
    soft(ctx, "dnsx", run_py, ctx, "dns/src/dns_enum.py", L.all_subs, L.dns_dir, ctx.notify_flag())

    if has_content(L.ips_input):
        merge_into(L.all_ips, read_lines(L.ips_input))
    if has_content(L.all_ips):
        ensure_tool_available(ctx, "hakrevdns", "dns")
        soft(
            ctx,
            "revdns",
            run_py,
            ctx,
            "dns/src/revdns_enum.py",
            L.all_ips,
            L.dns_dir,
            ctx.notify_flag(),
            L.domains_file,
        )
    else:
        ctx.ui.info("all.ips.txt vazio; reverse DNS ignorado")


@register_stage(
    "infra",
    "Resolucao de IPs, enriquecimento via sdlookup e varredura de portas com naabu.",
    ["httpx", "naabu"],
    ["IPs", "portas"],
)
def stage_infra(ctx: Ctx) -> None:
    L = ctx.layout
    if not has_content(L.all_subs):
        raise StageError("all.subs.txt vazio; rode a etapa 'subdomains' primeiro")
    ensure_tool_available(ctx, "httpx", "infra")
    L.ips_dir.mkdir(parents=True, exist_ok=True)
    touch(L.all_ips)

    soft(ctx, "httpx-ip", run_py, ctx, "infrastructure/src/subdomain_resolution.py", L.subs_dir, L.ips_dir, ctx.notify_flag())

    if has_content(L.all_ips):
        if tool_path("sdlookup"):
            soft(ctx, "sdlookup", run_py, ctx, "infrastructure/src/portscan_sdlookup.py", L.all_ips, L.ips_dir, ctx.notify_flag())
        else:
            ctx.ui.warn("sdlookup ausente; enriquecimento de IP pulado")

    targets = L.resolved_ips if has_content(L.resolved_ips) else L.all_ips
    if not has_content(targets):
        ctx.ui.info("nenhum IP resolvido; varredura de portas ignorada")
        return

    ensure_tool_available(ctx, "naabu", "infra")
    cmd: list[str | Path] = [
        "naabu",
        "-list",
        targets,
        "-silent",
        "-rate",
        str(ctx.args.rate_limit),
        "-Pn",
        "-scan-all-ips",
        "-ip-version",
        "4",
    ]
    if ctx.args.top_ports:
        cmd += ["-top-ports", str(ctx.args.top_ports)]
    elif ctx.args.ports:
        cmd += ["-port", ctx.args.ports]
    if os.geteuid() != 0:
        cmd += ["-s", "connect"]
    proc = soft(ctx, "naabu", run_cmd, ctx, cmd, "naabu", None, ctx.args.stage_timeout or None, False)
    added = 0
    if isinstance(proc, subprocess.CompletedProcess):
        added = merge_into(L.open_ports, uniq(collect_new_lines(proc)))
    ctx.ui.info(f"naabu: {added} novas portas abertas")


@register_stage(
    "probe",
    "Resolucao HTTP + fingerprint web (status, titulo, tecnologias, servidor, IP, CNAME).",
    ["httpx"],
    ["vivos"],
)
def stage_probe(ctx: Ctx) -> None:
    L = ctx.layout
    if not has_content(L.all_subs):
        raise StageError("all.subs.txt vazio; rode a etapa 'subdomains' primeiro")
    ensure_tool_available(ctx, "httpx", "probe")
    L.subs_dir.mkdir(parents=True, exist_ok=True)
    L.recondir.mkdir(parents=True, exist_ok=True)

    cmd: list[str | Path] = [
        "httpx",
        "-l",
        L.all_subs,
        "-silent",
        "-json",
        "-threads",
        str(ctx.args.threads),
        "-timeout",
        str(ctx.args.timeout),
        "-retries",
        str(ctx.args.retries),
        "-tech-detect",
        "-status-code",
        "-title",
        "-web-server",
        "-ip",
        "-cname",
        "-o",
        L.inventory_file,
    ]
    if ctx.args.follow_redirects:
        cmd.append("-follow-redirects")
    for header in ctx.args.header or []:
        cmd += ["-H", header]
    if ctx.args.cookie:
        cmd += ["-H", f"Cookie: {ctx.args.cookie}"]
    if ctx.args.user_agent:
        cmd += ["-H", f"User-Agent: {ctx.args.user_agent}"]

    run_cmd(ctx, cmd, "httpx-probe", timeout=ctx.args.stage_timeout or None)

    records: list[dict] = []
    seen_urls: set[str] = set()
    if L.inventory_file.is_file():
        with L.inventory_file.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                url = record.get("url") or record.get("final_url")
                if not url:
                    continue
                if ctx.args.no_scope_filter:
                    keep = True
                else:
                    host = record.get("host") or host_of(url)
                    keep = in_scope(host, scope_roots(ctx), exclusion_patterns(ctx), is_url=False)
                if not keep:
                    merge_into(L.excluded_file, [url])
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                record["url"] = url
                records.append(record)

    records.sort(key=lambda item: (item.get("host") or "", item.get("url") or ""))
    ctx.inventory = records
    if records:
        write_lines(L.inventory_file, [json.dumps(item, ensure_ascii=False) for item in records])

    live_urls = uniq(record.get("url", "") for record in records if record.get("url"))
    live_hosts = uniq(
        (record.get("host") or host_of(record.get("url", ""))) for record in records
    )
    live_hosts = [host for host in live_hosts if host]
    write_lines(L.all_live_urls, live_urls)
    write_lines(L.all_live_hosts, live_hosts)
    ctx.ui.info(f"{len(live_urls)} URLs vivas / {len(live_hosts)} hosts")


@register_stage(
    "content",
    "Coleta de URLs historicas e crawl (gau/katana), limpeza, parametros, JS e screenshots.",
    ["gau", "katana"],
    ["URLs", "URLs limpas", "params"],
)
def stage_content(ctx: Ctx) -> None:
    L = ctx.layout
    live = cap_live(ctx)
    if not has_content(live):
        raise StageError("lista de hosts vivos vazia; rode a etapa 'probe' primeiro")

    for tool in ("gau", "katana"):
        ensure_tool_available(ctx, tool, "content")

    L.urls_dir.mkdir(parents=True, exist_ok=True)
    for path in (
        L.gau_urls,
        L.katana_urls,
        L.all_urls,
        L.cleaned_urls,
        L.params_urls,
        L.js_urls,
    ):
        touch(path)

    soft(ctx, "gau", run_py, ctx, "content/src/gau_enum.py", live, L.content_dir)
    soft(ctx, "katana", run_py, ctx, "content/src/katana_enum.py", live, L.content_dir)

    merged = uniq(read_lines(L.gau_urls) + read_lines(L.katana_urls))
    merge_into(L.all_urls, merged)

    if tool_path("uro"):
        soft(ctx, "uro", run_py, ctx, "content/src/uro_cleaning.py", L.all_urls, L.content_dir)
    else:
        ctx.ui.warn("uro ausente; usando deduplicacao simples de URLs")
        fallback = uniq(url.split("#")[0].strip() for url in read_lines(L.all_urls) if url.strip())
        write_lines(L.cleaned_urls, fallback)

    cleaned = read_lines(L.cleaned_urls)
    params = [
        line
        for line in cleaned
        if "?" in line and not re.search(r"=[A-Za-z0-9+/]{50,}", line)
    ]
    merge_into(L.params_urls, params)

    js_urls = [line for line in cleaned if re.search(r"\.js(\?|$)", line, re.IGNORECASE)]
    merge_into(L.js_urls, js_urls)

    if tool_path("unfurl"):
        soft(ctx, "unfurl", run_py, ctx, "content/src/unfurl_enum.py", L.cleaned_urls, L.content_dir)
    else:
        ctx.ui.warn("unfurl ausente; extracao de palavras/keys pulada")

    shots = ctx.args.screenshots
    if shots in ("gowitness", "both"):
        if tool_path("gowitness"):
            soft(ctx, "gowitness", run_py, ctx, "content/src/gowitness_screenshots.py", live, L.content_dir)
        else:
            ctx.ui.warn("gowitness ausente; screenshots pulados")
    if shots in ("aquatone", "both"):
        if tool_path("aquatone"):
            soft(ctx, "aquatone", run_py, ctx, "content/src/aquatone_screenshots.py", live, L.content_dir)
        else:
            ctx.ui.warn("aquatone ausente; screenshots pulados")

    for path in (L.all_urls, L.cleaned_urls, L.params_urls, L.js_urls):
        filter_scope_file(ctx, path, is_url=True)


@register_stage(
    "javascript",
    "Extracao de arquivos JS, analise de endpoints/segredos e scan com nuclei.",
    ["subjs", "katana", "nuclei"],
    ["JS"],
)
def stage_javascript(ctx: Ctx) -> None:
    L = ctx.layout
    if not has_content(L.js_urls):
        raise StageError("all.js.urls.txt vazio; rode a etapa 'content' primeiro")

    ensure_tool_available(ctx, "subjs", "javascript")
    L.js_dir.mkdir(parents=True, exist_ok=True)
    touch(L.selected_js)

    soft(ctx, "subjs", run_py, ctx, "javascript/src/subjs_enum.py", L.js_urls, L.js_dir, L.all_subs)

    if tool_path("katana"):
        soft(
            ctx,
            "katana-js",
            run_py,
            ctx,
            "javascript/src/katana_js_enum.py",
            L.js_urls,
            L.selected_js,
            L.all_subs,
            L.all_urls,
        )

    if Path("/opt/JSScanner/JSScanner.py").is_file():
        soft(
            ctx,
            "jsscanner",
            run_py,
            ctx,
            "javascript/src/jsscanner_enum.py",
            L.selected_js,
            L.js_dir,
            "/opt/JSScanner/Regex.txt",
        )
    else:
        ctx.ui.warn("JSScanner nao instalado em /opt/JSScanner; analise de regex pulada")

    if ctx.args.js_download:
        if tool_path("wget"):
            soft(ctx, "download-js", run_py, ctx, "javascript/src/download_js_files.py", L.selected_js, L.js_downloads)
        else:
            ctx.ui.warn("wget ausente; download de JS pulado")

    if ctx.args.js_nuclei:
        if not tool_path("nuclei"):
            ctx.ui.warn("nuclei ausente; scan de JS pulado")
        elif has_content(L.selected_js):
            out_file = L.js_dir / "nuclei.javascript.scan.txt"
            cmd: list[str | Path] = [
                "nuclei",
                "-silent",
                "-l",
                L.selected_js,
                "-tags",
                ctx.args.nuclei_tags,
            ]
            for header in ctx.args.header or []:
                cmd += ["-H", header]
            if ctx.args.cookie:
                cmd += ["-H", f"Cookie: {ctx.args.cookie}"]
            proc = soft(ctx, "nuclei-js", run_cmd, ctx, cmd, "nuclei-js", None, ctx.args.stage_timeout or None, False)
            added = 0
            if isinstance(proc, subprocess.CompletedProcess):
                added = merge_into(out_file, uniq(collect_new_lines(proc)))
            ctx.ui.info(f"nuclei JS: {added} novos achados")

    filter_scope_file(ctx, L.selected_js, is_url=True)


@register_stage(
    "fuzz",
    "Geracao de wordlists (cewl/URLs), fuzzing de diretorios, VHOST e exposicao de .git.",
    ["gobuster"],
    ["URLs"],
)
def stage_fuzz(ctx: Ctx) -> None:
    L = ctx.layout
    live = cap_live(ctx)
    if not has_content(live):
        raise StageError("lista de hosts vivos vazia; rode a etapa 'probe' primeiro")

    L.fuzz_dir.mkdir(parents=True, exist_ok=True)
    L.wordlists_dir.mkdir(parents=True, exist_ok=True)
    L.screenshots_dir.mkdir(parents=True, exist_ok=True)

    if ctx.args.cewl:
        if tool_path("cewl"):
            soft(ctx, "cewl", run_py, ctx, "fuzzing/src/cewl_wordlist_generation.py", live, L.wordlists_dir / "cewl")
        else:
            ctx.ui.warn("cewl ausente; wordlist customizada pulada")

    if has_content(L.all_paths):
        soft(ctx, "extract-words", run_py, ctx, "fuzzing/src/extract_words_from_paths.py", L.all_paths, L.wordlists_dir)

    ensure_tool_available(ctx, "gobuster", "fuzz")
    dir_wordlist = resolve_wordlist(L.root, ctx.args.wordlist_dirs, "directories")
    if not dir_wordlist.is_file():
        raise StageError(f"wordlist de diretorios nao encontrada: {dir_wordlist}")
    soft(ctx, "gobuster", run_py, ctx, "fuzzing/src/gobuster_fuzzing.py", live, L.fuzz_dir, dir_wordlist, ctx.notify_flag())

    sub_wordlist = resolve_wordlist(L.root, ctx.args.wordlist_subdomains, "subdomains")
    soft(
        ctx,
        "gobuster-vhost",
        run_py,
        ctx,
        "fuzzing/src/gobuster_vhost_fuzzing.py",
        live,
        L.fuzz_dir,
        sub_wordlist,
        ctx.notify_flag(),
    )

    if tool_path("goop"):
        git_dir = L.fuzz_dir / "git"
        git_dir.mkdir(parents=True, exist_ok=True)
        soft(ctx, "goop", run_cmd, ctx, ["goop", "-l", live, "-f", git_dir], "goop", None, ctx.args.stage_timeout or None, False)
    else:
        ctx.ui.warn("goop ausente; verificacao de .git pulada")


@register_stage(
    "vulns",
    "Classificacao de URLs por padroes gf (xss, sqli, ssrf, lfi, rce, idor...) e dalfox opcional.",
    ["gf"],
    ["GF hits"],
)
def stage_vulns(ctx: Ctx) -> None:
    L = ctx.layout
    if not has_content(L.cleaned_urls):
        raise StageError("all.cleaned.urls.txt vazio; rode a etapa 'content' primeiro")
    ensure_tool_available(ctx, "gf", "vulns")
    L.vuln_dir.mkdir(parents=True, exist_ok=True)

    if ctx.args.gf_install:
        source_dir = L.root / "gf"
        home_dir = Path.home()
        try:
            import pwd

            home_dir = Path(pwd.getpwuid(os.getuid()).pw_dir)
        except (ImportError, KeyError):
            pass
        dest_dir = home_dir / ".gf"
        dest_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        for pattern_file in sorted(source_dir.glob("*.json")):
            target = dest_dir / pattern_file.name
            shutil.copyfile(pattern_file, target)
            copied += 1
        ctx.ui.info(f"{copied} patterns gf instalados em {dest_dir}")

    corpus = "\n".join(read_lines(L.cleaned_urls)) + "\n"
    listing = soft(ctx, "gf-list", run_cmd, ctx, ["gf", "-list"], "gf-list", None, None, False)
    available = set(collect_new_lines(listing)) if isinstance(listing, subprocess.CompletedProcess) else set()
    if not available:
        ctx.ui.warn(
            "gf nao tem patterns instalados. Copie os arquivos de ./gf para o diretorio "
            "de patterns do gf (normalmente ~/.gf) e rode novamente. Etapa ignorada para evitar falsos positivos."
        )
        ctx.soft_failures += 1
        return
    patterns = [item.strip() for item in ctx.args.gf_patterns.split(",") if item.strip()]
    missing = [item for item in patterns if item not in available]
    if missing:
        ctx.ui.info(f"patterns gf ausentes e ignorados: {', '.join(missing)}")
    for pattern in patterns:
        if pattern not in available:
            continue
        proc = soft(ctx, f"gf:{pattern}", run_cmd, ctx, ["gf", pattern], f"gf:{pattern}", corpus, None, False)
        lines = uniq(collect_new_lines(proc)) if isinstance(proc, subprocess.CompletedProcess) else []
        target = L.vuln_dir / f"{pattern}.txt"
        added = merge_into(target, lines)
        if added:
            ctx.ui.info(f"gf {pattern}: {added} novas URLs")

    if ctx.args.dalfox and has_content(L.vuln_dir / "xss.txt"):
        if tool_path("dalfox"):
            out_file = L.vuln_dir / "dalfox.xss.txt"
            proc = soft(
                ctx,
                "dalfox",
                run_cmd,
                ctx,
                ["dalfox", "file", L.vuln_dir / "xss.txt", "--silence"],
                "dalfox",
                None,
                ctx.args.stage_timeout or None,
                False,
            )
            if isinstance(proc, subprocess.CompletedProcess):
                merge_into(out_file, uniq(collect_new_lines(proc)))
        else:
            ctx.ui.warn("dalfox ausente; scan XSS pulado")


# ---------------------------------------------------------------------------
# Relatorio
# ---------------------------------------------------------------------------


def load_inventory(path: Path) -> list[dict]:
    records: list[dict] = []
    if not path.is_file():
        return records
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def interesting_hosts(hosts: list[str]) -> list[str]:
    keywords = {
        "dev", "develop", "staging", "stage", "test", "uat", "qa", "admin",
        "internal", "intranet", "vpn", "jenkins", "gitlab", "jira", "grafana",
        "kibana", "s3", "bucket", "backup", "beta", "preprod", "homolog", "api",
        "db", "redis", "mongo", "portal", "dashboard", "auth", "login",
    }
    found = []
    for host in hosts:
        tokens = {token for token in re.split(r"[.-]", host.lower()) if token}
        if tokens & keywords:
            found.append(host)
    return found


def count_screenshots(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(1 for item in path.rglob("*") if item.is_file() and item.suffix.lower() in (".png", ".jpg", ".jpeg"))


def collect_report(ctx: Ctx) -> dict:
    L = ctx.layout
    inventory = load_inventory(L.inventory_file) or ctx.inventory
    subs = uniq(read_lines(L.all_subs))
    live_urls = uniq(read_lines(L.all_live_urls))
    live_hosts = uniq(read_lines(L.all_live_hosts))
    if not live_hosts:
        live_hosts = uniq(host_of(url) for url in live_urls)
        live_hosts = [host for host in live_hosts if host]

    status = Counter()
    tech = Counter()
    servers = Counter()
    titles = []
    for record in inventory:
        code = record.get("status_code")
        if isinstance(code, int):
            status[str(code)] += 1
        for item in record.get("tech") or []:
            tech[str(item)] += 1
        server = record.get("webserver")
        if server:
            servers[str(server)] += 1
        title = record.get("title")
        if title:
            titles.append({"url": record.get("url"), "title": title})

    ports = Counter()
    for line in read_lines(L.open_ports):
        if ":" in line:
            ports[line.rsplit(":", 1)[-1]] += 1
        else:
            ports[line] += 1

    gf_files = sorted(L.vuln_dir.glob("*.txt")) if L.vuln_dir.is_dir() else []
    gf = {path.stem: count_lines(path) for path in gf_files}
    gf = {key: value for key, value in gf.items() if value}

    email_spoof = read_lines(L.dns_dir / "vulnerable.email_spoofing.dns.txt")
    cnames = read_lines(L.dns_dir / "cname_records.dns.txt")
    txts = read_lines(L.dns_dir / "txt_records.dns.txt")

    js_secrets = {}
    for name in ("output.txt", "jsscanner.content.txt", "nuclei.javascript.scan.txt"):
        path = L.js_dir / name
        if path.is_file():
            js_secrets[name] = count_lines(path)

    screenshots = count_screenshots(L.screenshots_dir)

    return {
        "target": L.target,
        "domains": ctx.domains,
        "scope_roots": scope_roots(ctx),
        "generated_at": now(),
        "elapsed_seconds": round(time.time() - ctx.started, 2),
        "counts": {
            "subdomains": len(subs),
            "live_urls": len(live_urls),
            "live_hosts": len(live_hosts),
            "urls": count_lines(L.all_urls),
            "cleaned_urls": count_lines(L.cleaned_urls),
            "parameter_urls": count_lines(L.params_urls),
            "js_urls": count_lines(L.selected_js),
            "open_ports": count_lines(L.open_ports),
            "dns_txt": len(txts),
            "dns_cname": len(cnames),
            "email_spoofing": len(email_spoof),
            "screenshots": screenshots,
            "excluded": count_lines(L.excluded_file),
            "gf_hits": sum(gf.values()),
        },
        "status_codes": dict(status.most_common()),
        "technologies": dict(tech.most_common(25)),
        "servers": dict(servers.most_common(15)),
        "interesting_subdomains": interesting_hosts(subs)[:50],
        "parameter_samples": read_lines(L.params_urls)[:20],
        "top_titles": titles[:25],
        "open_ports_by_port": dict(ports.most_common(25)),
        "gf": gf,
        "email_spoofing": email_spoof[:25],
        "js_secret_findings": js_secrets,
        "stages": [
            {
                "name": result.name,
                "status": result.status,
                "seconds": round(result.seconds, 2),
                "deltas": result.deltas,
                "note": result.note,
            }
            for result in ctx.results
        ],
        "paths": {
            "base": str(L.base),
            "summary": str(L.summary_md),
            "log": str(L.log_file),
            "inventory": str(L.inventory_file),
            "subdomains": str(L.all_subs),
            "live": str(L.all_live_urls),
            "urls": str(L.all_urls),
            "vuln": str(L.vuln_dir),
            "screenshots": str(L.screenshots_dir),
        },
    }


def md_table(headers: list[str], rows: list[list[object]]) -> str:
    if not rows:
        return "_sem dados_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        cells = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in row]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def build_markdown(report: dict) -> str:
    counts = report["counts"]
    lines: list[str] = []
    lines.append(f"# Reconhecimento - {report['target']}\n")
    lines.append(f"- **Dominios:** {', '.join(report['domains'])}")
    lines.append(f"- **Gerado em:** {report['generated_at']}")
    lines.append(f"- **Duracao:** {human_seconds(report['elapsed_seconds'])}")
    lines.append(f"- **Saida:** `{report['paths']['base']}`\n")

    lines.append("## Funil\n")
    rows = [
        ["Subdominios", counts["subdomains"]],
        ["Hosts vivos", counts["live_hosts"]],
        ["URLs vivas", counts["live_urls"]],
        ["URLs coletadas", counts["urls"]],
        ["URLs limpas", counts["cleaned_urls"]],
        ["URLs com parametros", counts["parameter_urls"]],
        ["Arquivos JS", counts["js_urls"]],
        ["Portas abertas", counts["open_ports"]],
        ["Achados gf", counts["gf_hits"]],
        ["Screenshots", counts["screenshots"]],
        ["Fora de escopo", counts["excluded"]],
    ]
    lines.append(md_table(["Metrica", "Total"], rows))

    lines.append("## Tecnologias\n")
    lines.append(md_table(["Tecnologia", "Hosts"], [[k, v] for k, v in report["technologies"].items()]))

    lines.append("## Status HTTP\n")
    lines.append(md_table(["Status", "Total"], [[k, v] for k, v in report["status_codes"].items()]))

    lines.append("## Servidores web\n")
    lines.append(md_table(["Servidor", "Total"], [[k, v] for k, v in report["servers"].items()]))

    lines.append("## Subdominios interessantes\n")
    if report["interesting_subdomains"]:
        for host in report["interesting_subdomains"]:
            lines.append(f"- `{host}`")
        lines.append("")
    else:
        lines.append("_nenhum padrao interessante encontrado_\n")

    lines.append("## Paginas com titulo (amostra)\n")
    if report["top_titles"]:
        for item in report["top_titles"][:15]:
            lines.append(f"- `{item.get('url')}` - {item.get('title')}")
        lines.append("")
    else:
        lines.append("_sem titulos coletados_\n")

    lines.append("## URLs com parametros (amostra)\n")
    if report["parameter_samples"]:
        for url in report["parameter_samples"]:
            lines.append(f"- `{url}`")
        lines.append("")
    else:
        lines.append("_nenhuma URL com parametros_\n")

    lines.append("## Portas abertas\n")
    lines.append(md_table(["Porta", "Ocorrencias"], [[k, v] for k, v in report["open_ports_by_port"].items()]))

    lines.append("## Classes de vulnerabilidade (gf)\n")
    lines.append(md_table(["Padrao", "URLs"], [[k, v] for k, v in report["gf"].items()]))

    lines.append("## DNS\n")
    lines.append(f"- TXT: {counts['dns_txt']}")
    lines.append(f"- CNAME: {counts['dns_cname']}")
    lines.append(f"- Possivel email spoofing (SPF fraco): {counts['email_spoofing']}")
    for item in report["email_spoofing"][:10]:
        lines.append(f"  - `{item}`")
    lines.append("")

    lines.append("## JavaScript\n")
    if report["js_secret_findings"]:
        for name, total in report["js_secret_findings"].items():
            lines.append(f"- `{name}`: {total} linhas")
    else:
        lines.append("_nenhum resultado de JS scanner/nuclei_")
    lines.append("")

    lines.append("## Etapas executadas\n")
    stage_rows = []
    for stage in report["stages"]:
        delta_text = ", ".join(f"{k} +{v}" for k, v in stage["deltas"].items()) or "-"
        stage_rows.append([stage["name"], stage["status"], human_seconds(stage["seconds"]), delta_text])
    lines.append(md_table(["Etapa", "Status", "Tempo", "Novos"], stage_rows))

    lines.append("## Proximos passos sugeridos\n")
    suggestions: list[str] = []
    if counts["email_spoofing"]:
        suggestions.append("Revise SPF/DMARC: ha dominios com politica de email permissiva.")
    if counts["gf_hits"]:
        suggestions.append("Priorize as classes em `content/vuln/` e valide manualmente XSS, SSRF, LFI e IDOR.")
    if report["interesting_subdomains"]:
        suggestions.append("Comece pelos subdominios de dev/staging/admin/api; costumam ter controles mais fracos.")
    sensitive = {"6379", "9200", "27017", "11211", "5432", "3306", "2375", "2379", "10250"}
    if sensitive.intersection(report["open_ports_by_port"]):
        suggestions.append("Portas de servicos sensiveis expostas: valide autenticacao e segmentacao.")
    if report["js_secret_findings"]:
        suggestions.append("Revise `content/javascript/` por chaves/tokens e solicite rotacao se confirmado.")
    if counts["parameter_urls"]:
        suggestions.append("Use as URLs com parametros para testes de injecao e arjun/param discovery.")
    suggestions.append("Valide o escopo e a autorizacao antes de qualquer teste ativo.")
    for item in suggestions:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Artefatos\n")
    for key, value in report["paths"].items():
        lines.append(f"- **{key}:** `{value}`")
    lines.append("")
    return "\n".join(lines)


def write_report(ctx: Ctx) -> dict:
    report = collect_report(ctx)
    L = ctx.layout
    L.recondir.mkdir(parents=True, exist_ok=True)
    L.summary_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    L.summary_md.write_text(build_markdown(report), encoding="utf-8")

    counts = report["counts"]
    ctx.ui.title("Resumo do reconhecimento")
    ctx.echo(f"  Dominios ......... {len(report['domains'])}")
    ctx.echo(f"  Subdominios ...... {counts['subdomains']}")
    ctx.echo(f"  Hosts vivos ...... {counts['live_hosts']}")
    ctx.echo(f"  URLs ............. {counts['urls']} ({counts['parameter_urls']} com parametros)")
    ctx.echo(f"  JS ............... {counts['js_urls']}")
    ctx.echo(f"  Portas abertas ... {counts['open_ports']}")
    ctx.echo(f"  Achados gf ....... {counts['gf_hits']}")
    ctx.echo(f"  Fora de escopo ... {counts['excluded']}")

    if report["technologies"]:
        top = ", ".join(f"{name}({total})" for name, total in list(report["technologies"].items())[:8])
        ctx.ui.info(f"tecnologias: {top}")
    if report["open_ports_by_port"]:
        top = ", ".join(f"{port}({total})" for port, total in list(report["open_ports_by_port"].items())[:8])
        ctx.ui.info(f"portas: {top}")
    if report["gf"]:
        top = ", ".join(f"{name}({total})" for name, total in sorted(report["gf"].items(), key=lambda kv: -kv[1])[:8])
        ctx.ui.info(f"gf: {top}")
    if report["interesting_subdomains"]:
        top = ", ".join(report["interesting_subdomains"][:6])
        ctx.ui.info(f"subdominios interessantes: {top}")
    if counts["email_spoofing"]:
        ctx.ui.warn(f"{counts['email_spoofing']} registro(s) com SPF permissivo (possivel email spoofing)")

    ctx.ui.ok(f"relatorio: {L.summary_md}")
    ctx.ui.ok(f"json:      {L.summary_json}")
    ctx.ui.ok(f"log:       {L.log_file}")
    return report


# ---------------------------------------------------------------------------
# Execucao
# ---------------------------------------------------------------------------


def print_stage_table(ctx: Ctx) -> None:
    if not ctx.results:
        return
    ctx.ui.title("Etapas")
    width = max(len(stage.name) for stage in ctx.results)
    for result in ctx.results:
        status_color = {"ok": "32", "skipped": "36", "warn": "33"}.get(result.status, "31")
        label = ctx.ui._paint(result.status.ljust(7), status_color) if ctx.ui.color else result.status.ljust(7)
        deltas = " ".join(f"{key}+{value}" for key, value in result.deltas.items())
        note = f"  {result.note}" if result.note else ""
        print(f"  {result.name.ljust(width)}  {label}  {human_seconds(result.seconds).rjust(7)}  {deltas}{note}")


def execute_stage(ctx: Ctx, stage: Stage, index: int, total: int) -> None:
    ui = ctx.ui
    if ctx.args.resume and marker_path(ctx, stage.name).is_file():
        ui.step(f"({index}/{total}) {stage.name}: ignorada (--resume)")
        ctx.results.append(StageResult(stage.name, "skipped", 0.0, note="marker existente"))
        return

    ui.step(f"({index}/{total}) {stage.name}: {stage.description}")
    before = snapshot(ctx)
    started = time.time()
    ctx.soft_failures = 0
    status = "ok"
    note = ""
    try:
        stage.func(ctx)
    except StageError as exc:
        status = "fail"
        note = str(exc)
        ui.error(f"{stage.name}: {exc}")
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001 - queremos continuar o pipeline
        status = "error"
        note = f"{type(exc).__name__}: {exc}"
        ui.error(f"{stage.name}: {note}")

    elapsed = time.time() - started
    if status == "ok" and ctx.soft_failures:
        status = "warn"
        note = f"{ctx.soft_failures} subcomando(s) falharam"
    changes = delta(before, snapshot(ctx), stage.watch)
    if status == "ok":
        write_marker(ctx, stage.name)
    ctx.results.append(StageResult(stage.name, status, elapsed, changes, note))
    if changes:
        ui.info(", ".join(f"{key} +{value}" for key, value in changes.items()))

    if status != "ok" and ctx.args.fail_fast:
        raise SystemExit(2)


def print_plan(ctx: Ctx, stages: list[str]) -> None:
    ctx.ui.title("Plano de reconhecimento")
    ctx.echo(f"  alvo ......... {ctx.layout.target}")
    ctx.echo(f"  dominios ..... {', '.join(ctx.domains)}")
    ctx.echo(f"  escopo ....... {', '.join(scope_roots(ctx))}")
    ctx.echo(f"  saida ........ {ctx.layout.base}")
    ctx.echo(f"  preset ....... {ctx.args.preset or 'custom'}")
    ctx.echo("")
    ctx.echo("  etapas:")
    for index, name in enumerate(stages, 1):
        stage = STAGES[name]
        ctx.echo(f"    {index}. {name:<12} {stage.description}")
    ctx.echo("")
    ctx.echo(f"  relatorio: {ctx.layout.summary_md}")
    ctx.echo(f"  log:       {ctx.layout.log_file}")


def print_explain() -> None:
    print("Etapas disponiveis\n")
    for name in STAGE_ORDER:
        stage = STAGES[name]
        print(f"  {name}")
        print(f"    {stage.description}")
        print(f"    ferramentas: {', '.join(stage.tools) or '-'}")
        print()


def print_tool_check(ctx: Ctx, stages: list[str]) -> int:
    required: list[str] = []
    for name in stages:
        for tool in STAGES[name].tools:
            if tool not in required:
                required.append(tool)
    if "subdomains" in stages and ctx.args.bruteforce and "puredns" not in required:
        required.append("puredns")
    if "subdomains" in stages:
        if ctx.args.chaos or (ctx.args.chaos is None and os.environ.get("PDCP_API_KEY")):
            required.append("chaos")
        if ctx.args.github or (ctx.args.github is None and os.environ.get("GITHUB_TOKEN")):
            required.append("github-subdomains")
    if ctx.args.screenshots in ("gowitness", "both"):
        required.append("gowitness")
    if ctx.args.screenshots in ("aquatone", "both"):
        required.append("aquatone")
    if ctx.args.js_download:
        required.extend(["wget", "js-beautify"])

    optional = ["anew", "uro", "unfurl", "sdlookup", "goop", "cewl", "dalfox"]
    if ctx.args.cewl and "cewl" not in required:
        required.append("cewl")
    if ctx.args.dalfox and "dalfox" not in required:
        required.append("dalfox")

    missing = 0
    ctx.ui.title("Verificacao de ferramentas (obrigatorias para as etapas escolhidas)")
    for tool in required:
        path = tool_path(tool)
        if path:
            ctx.ui.ok(f"{tool:<20} {path}")
        else:
            missing += 1
            ctx.ui.warn(f"{tool:<20} NAO ENCONTRADO")

    ctx.ui.info("opcionais:")
    for tool in optional:
        path = tool_path(tool)
        mark = "ok " if path else "-- "
        ctx.ui.info(f"  [{mark}] {tool:<18} {path or 'ausente (recurso sera pulado)'}")

    ctx.ui.info(f"{len(required) - missing}/{len(required)} ferramentas obrigatorias disponiveis")
    if missing:
        ctx.ui.warn("instale as ferramentas ausentes pelo playbook.yml ou ajuste as etapas")
    return 0


def parse_stages(args: argparse.Namespace) -> list[str]:
    if args.stages:
        raw = [item.strip() for item in args.stages.split(",") if item.strip()]
    elif args.preset:
        raw = PRESETS.get(args.preset, PRESETS["web"])
    else:
        raw = PRESETS["web"]

    selected: list[str] = []
    for item in raw:
        name = STAGE_ALIASES.get(item, item)
        if name not in STAGES:
            raise SystemExit(f"etapa desconhecida: {item}. Use --list-stages para ver as opcoes.")
        if name not in selected:
            selected.append(name)

    for item in args.exclude_stage or []:
        name = STAGE_ALIASES.get(item, item)
        if name in selected:
            selected.remove(name)

    if args.passive:
        selected = [name for name in selected if name not in ("infra", "fuzz")]

    selected.sort(key=STAGE_ORDER.index)
    return selected


def parse_domains(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.domain or [])
    if args.domains_file:
        path = Path(args.domains_file)
        if not path.is_file():
            raise SystemExit(f"arquivo de dominios nao encontrado: {path}")
        raw.extend(read_lines(path))
    domains: list[str] = []
    for value in raw:
        normalized = normalize_domain(value)
        if not normalized:
            continue
        if not valid_domain(normalized):
            raise SystemExit(f"dominio invalido: {value!r} (normalizado: {normalized!r})")
        if normalized not in domains:
            domains.append(normalized)
    if not domains:
        raise SystemExit("informe ao menos um dominio com -d/--domain ou -dL/--domains-file")
    return domains


def build_parser() -> argparse.ArgumentParser:
    epilog = """
Exemplos:
  ./recon.py -d exemplo.com
  ./recon.py -d exemplo.com -d exemplo.com.br --preset deep --screenshots both
  ./recon.py -dL escopo.txt -n cliente --stages subdomains,probe,content,javascript --max-hosts 50
  ./recon.py -d exemplo.com --passive --no-bruteforce
  ./recon.py --explain
  ./recon.py --check -d exemplo.com

Presets: passive, web, deep, full, subdomains.
Etapas: subdomains, asn, dns, infra, probe, content, javascript, fuzz, vulns.
"""
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="Rotz Recon CLI: pipeline didatico de reconhecimento web por dominio ou lista de dominios.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )

    target = parser.add_argument_group("Alvo")
    target.add_argument("-d", "--domain", action="append", metavar="DOMINIO", help="dominio alvo (pode repetir)")
    target.add_argument("-dL", "--domains-file", metavar="ARQUIVO", help="arquivo com um dominio por linha")
    target.add_argument("--ips-file", metavar="ARQUIVO", help="arquivo com IPs/CIDRs sementes (opcional)")
    target.add_argument("-n", "--name", metavar="NOME", help="nome curto do alvo (default: primeiro dominio)")
    target.add_argument("--root", metavar="DIR", help="raiz do projeto (default: diretorio do recon.py)")
    target.add_argument("-o", "--output", metavar="DIR", help="diretorio base de saida (default: <root>/output)")
    target.add_argument("--scope", action="append", metavar="DOMINIO", help="dominio/apex adicional considerado em escopo")
    target.add_argument("--exclude", action="append", metavar="REGEX", help="regex de hosts a excluir")
    target.add_argument("--no-scope-filter", action="store_true", help="nao descartar hosts/URLs fora do escopo")

    pipeline = parser.add_argument_group("Pipeline")
    pipeline.add_argument("-s", "--stages", metavar="LISTA", help="etapas separadas por virgula (substitui o preset)")
    pipeline.add_argument("-p", "--preset", choices=sorted(PRESETS), default="web", help="conjunto de etapas (default: web)")
    pipeline.add_argument("--exclude-stage", action="append", metavar="ETAPA", help="remove etapa do preset")
    pipeline.add_argument("--passive", action="store_true", help="sem bruteforce/portas/fuzzing/screenshots")
    pipeline.add_argument("--resume", action="store_true", help="pula etapas ja concluidas (marcadores em _recon)")
    pipeline.add_argument("--fail-fast", action="store_true", help="aborta na primeira etapa com erro")
    pipeline.add_argument("--dry-run", "--plan", dest="dry_run", action="store_true", help="mostra o plano e nao executa")
    pipeline.add_argument("--list-stages", action="store_true", help="lista as etapas e sai")
    pipeline.add_argument("--explain", action="store_true", help="explica cada etapa e ferramenta e sai")
    pipeline.add_argument("--check", action="store_true", help="verifica ferramentas necessarias e sai")

    sub = parser.add_argument_group("Subdominios e DNS")
    sub.add_argument("--bruteforce", action=argparse.BooleanOptionalAction, default=None, help="brutal force com puredns (default: on, off em modo passive)")
    sub.add_argument("--chaos", action=argparse.BooleanOptionalAction, default=None, help="usar chaos (default: on se PDCP_API_KEY existir)")
    sub.add_argument("--github", action=argparse.BooleanOptionalAction, default=None, help="usar github-subdomains (default: on se GITHUB_TOKEN existir)")
    sub.add_argument("--wordlist-subdomains", default="small", metavar="NOME|PATH", help="wordlist de subdominios (small/medium/large/huge ou caminho)")
    sub.add_argument("--resolvers", metavar="ARQUIVO", help="resolvers.txt para puredns")
    sub.add_argument("--org", metavar="NOME", help="organizacao para a etapa asn (metabigor)")
    sub.add_argument("--max-hosts", type=int, default=0, metavar="N", help="limita hosts nas etapas content/javascript/fuzz (0 = sem limite)")

    web = parser.add_argument_group("HTTP e conteudo")
    web.add_argument("--threads", type=int, default=100, help="threads do httpx (default: 100)")
    web.add_argument("--timeout", type=int, default=5, help="timeout HTTP em segundos (default: 5)")
    web.add_argument("--retries", type=int, default=0, help="retries do httpx (default: 0)")
    web.add_argument("--follow-redirects", action=argparse.BooleanOptionalAction, default=True, help="seguir redirects no probe (default: on)")
    web.add_argument("-H", "--header", action="append", metavar="'Nome: valor'", help="header extra para httpx/nuclei")
    web.add_argument("--cookie", metavar="COOKIE", help="cookie de autenticacao para httpx/nuclei")
    web.add_argument("--user-agent", metavar="UA", help="User-Agent customizado")
    web.add_argument("--screenshots", choices=["none", "gowitness", "aquatone", "both"], default="none", help="captura de screenshots")

    scan = parser.add_argument_group("Portas, fuzzing e JS")
    scan.add_argument("--ports", default="80,443,8080,8443,3000,4000,5000,8800,9000,8888,8181", metavar="LISTA", help="portas do naabu")
    scan.add_argument("--top-ports", type=int, default=0, metavar="N", help="usa as N portas mais comuns do naabu (ignora --ports)")
    scan.add_argument("--rate-limit", type=int, default=1000, help="rate limit do naabu (default: 1000)")
    scan.add_argument("--wordlist-dirs", default="default", metavar="NOME|PATH", help="wordlist de diretorios (default/small ou caminho)")
    scan.add_argument("--cewl", action="store_true", help="gera wordlist por host com cewl (lento)")
    scan.add_argument("--js-download", action=argparse.BooleanOptionalAction, default=False, help="baixa e formata arquivos JS")
    scan.add_argument("--js-nuclei", action=argparse.BooleanOptionalAction, default=None, help="roda nuclei nos JS (default: on, off em modo passive)")
    scan.add_argument("--nuclei-tags", default="js,secrets,exposure,token", help="tags do nuclei para JS")
    scan.add_argument("--gf-patterns", default="debug_logic,idor,interestingEXT,interestingparams,interestingsubs,lfi,rce,redirect,sqli,ssrf,ssti,xss", help="padroes gf separados por virgula")
    scan.add_argument("--gf-install", action="store_true", help="copia os patterns de ./gf para ~/.gf antes de rodar")
    scan.add_argument("--dalfox", action="store_true", help="roda dalfox nas URLs classificadas como xss")

    out = parser.add_argument_group("Saida e execucao")
    out.add_argument("--notify", action="store_true", help="habilita notificacoes dos scripts via notify/telegram")
    out.add_argument("--stage-timeout", type=int, default=0, metavar="SEG", help="timeout por comando/etapa (0 = sem limite)")
    out.add_argument("--no-report", action="store_true", help="nao gera _recon/summary.md/json")
    out.add_argument("-v", "--verbose", action="store_true", help="mostra a saida dos comandos")
    out.add_argument("-q", "--quiet", action="store_true", help="menos saida no console")
    out.add_argument("--no-color", action="store_true", help="desabilita cores ANSI")
    out.add_argument("--version", action="version", version=f"recon.py {VERSION}")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    passive_mode = bool(args.passive or args.preset == "passive")
    if args.bruteforce is None:
        args.bruteforce = not passive_mode
    if args.js_nuclei is None:
        args.js_nuclei = not passive_mode
    if args.passive:
        args.screenshots = "none"
        if args.preset in (None, "web"):
            args.preset = "passive"

    stages = parse_stages(args)

    if args.list_stages:
        print("Etapas disponiveis\n")
        for name in STAGE_ORDER:
            stage = STAGES[name]
            print(f"  {name:<12} {stage.description}")
        print("\nPresets:")
        for name, items in PRESETS.items():
            print(f"  {name:<12} {', '.join(items)}")
        return 0

    if args.explain:
        print_explain()
        return 0

    domains = parse_domains(args)
    root = Path(args.root).resolve() if args.root else SCRIPT_DIR
    if not (root / "workflows").is_dir():
        raise SystemExit(f"raiz invalida: {root}/workflows nao existe")
    out = Path(args.output).resolve() if args.output else root / "output"
    target = slugify(args.name or domains[0])
    layout = Layout(root=root, out=out, target=target)
    ui = UI(color=sys.stdout.isatty() and not args.no_color, quiet=args.quiet)

    layout.base.mkdir(parents=True, exist_ok=True)
    layout.input_dir.mkdir(parents=True, exist_ok=True)
    layout.recondir.mkdir(parents=True, exist_ok=True)
    write_lines(layout.domains_file, domains)
    if args.ips_file:
        ips_source = Path(args.ips_file)
        if not ips_source.is_file():
            raise SystemExit(f"arquivo de IPs nao encontrado: {ips_source}")
        write_lines(layout.ips_input, read_lines(ips_source))
    else:
        legacy_ips = root / "input" / target / "ips.txt"
        if legacy_ips.is_file():
            shutil.copy(legacy_ips, layout.ips_input)

    ctx = Ctx(args=args, layout=layout, domains=domains, ui=ui)
    if not args.quiet:
        ui.title(f"Rotz Recon {VERSION}")
        ui.info(f"alvo: {layout.target}")
        ui.info(f"dominios: {', '.join(domains)}")
        ui.info(f"saida: {layout.base}")
        ui.info(f"etapas: {', '.join(stages)}")
    layout.log_file.parent.mkdir(parents=True, exist_ok=True)
    with layout.log_file.open("a", encoding="utf-8") as fh:
        fh.write(
            f"\n\n===== {now()} | target={layout.target} | domains={','.join(domains)} "
            f"| stages={','.join(stages)} =====\n"
        )

    if args.check:
        return print_tool_check(ctx, stages)

    if args.dry_run:
        print_plan(ctx, stages)
        return 0

    for index, name in enumerate(stages, 1):
        execute_stage(ctx, STAGES[name], index, len(stages))

    print_stage_table(ctx)

    if not args.no_report:
        write_report(ctx)

    ctx.log(f"[{now()}] fim")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\ninterrompido", file=sys.stderr)
        raise SystemExit(130)
