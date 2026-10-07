import re
import pathlib
from dataclasses import dataclass, asdict

SKIP_DIRS = {".git", ".venv", "workdir", "node_modules", "reports", "__pycache__", "tests"}

SECRET_PATTERNS = {
    "token de GitHub": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "key de OpenRouter": r"sk-or-[A-Za-z0-9\-]{20,}",
    "key de AWS": r"AKIA[0-9A-Z]{16}",
    "clave privada": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
}


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    file: str
    line: int | None
    evidence: str
    rule: str


def _files(root):
    root = pathlib.Path(root)
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if p.is_file() and not (set(rel.parts) & SKIP_DIRS) and p.stat().st_size < 1_000_000:
            yield p, rel.as_posix()


def scan_secrets(root):
    out, n = [], 0
    for p, rel in _files(root):
        if rel == ".env.example":
            continue
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for name, rx in SECRET_PATTERNS.items():
                if re.search(rx, line):
                    n += 1
                    out.append(Finding(f"SEC-{n:03}", "secret", "high", rel, i,
                                       "[REDACTED]", f"posible {name}"))
    return out


def scan_workflows(root):
    out, n = [], 0
    wf_dir = pathlib.Path(root, ".github", "workflows")
    if not wf_dir.exists():
        return out
    for p in sorted(wf_dir.glob("*.y*ml")):
        rel = p.relative_to(root).as_posix()
        text = p.read_text(errors="ignore")
        if "permissions:" not in text:
            n += 1
            out.append(Finding(f"WF-{n:03}", "workflow", "medium", rel, None,
                               "no existe bloque 'permissions:'",
                               "permisos por defecto potencialmente amplios"))
        for i, line in enumerate(text.splitlines(), 1):
            m = re.search(r"uses:\s*([\w\-./]+)@([\w.\-]+)", line)
            if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
                n += 1
                out.append(Finding(f"WF-{n:03}", "workflow", "low", rel, i,
                                   line.strip(), "acción no fijada a un SHA de commit"))
            if "pull_request_target" in line:
                n += 1
                out.append(Finding(f"WF-{n:03}", "workflow", "high", rel, i,
                                   line.strip(), "pull_request_target requiere revisión"))
    return out


def scan_hygiene(root):
    out = []
    gi = pathlib.Path(root, ".gitignore")
    if not gi.exists() or ".env" not in gi.read_text(errors="ignore"):
        out.append(Finding("HY-001", "hygiene", "high", ".gitignore", None,
                           "'.env' no aparece en .gitignore",
                           "riesgo de versionar secretos"))
    if pathlib.Path(root, ".env").exists():
        out.append(Finding("HY-002", "hygiene", "info", ".env", None,
                           "existe un .env local",
                           "verificar que no esté versionado (git ls-files .env)"))
    return out


def collect(root="."):
    findings = scan_secrets(root) + scan_workflows(root) + scan_hygiene(root)
    return [asdict(f) for f in findings]