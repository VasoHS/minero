import re
import pathlib
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, asdict

from ..timeouts import SUBPROCESS_TIMEOUT

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


def _scan_targets(root):
    """Archivos que git versiona o versionaría (excluye los ignorados, como .env).
    Si no es un repo git, recorre el árbol completo."""
    root = pathlib.Path(root)
    try:
        r = subprocess.run(
            ["git", "-c", "core.quotepath=off", "-C", str(root),
             "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True, text=True, check=True,
            timeout=SUBPROCESS_TIMEOUT)
        rels = [l for l in r.stdout.splitlines() if l]
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return list(_files(root))
    out = []
    for rel in rels:
        p = root / rel
        if (p.is_file() and not (set(pathlib.PurePosixPath(rel).parts) & SKIP_DIRS)
                and p.stat().st_size < 1_000_000):
            out.append((p, rel))
    return out


def scan_secrets(root):
    out, n = [], 0
    for p, rel in _scan_targets(root):
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
                                       "[REDACTED]",
                                       f"posible {name} en archivo no ignorado por git"))
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
            if re.search(r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(ba)?sh\b", line):
                n += 1
                out.append(Finding(f"WF-{n:03}", "workflow", "medium", rel, i,
                                   line.strip(),
                                   "script remoto ejecutado sin verificar integridad"))            
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
    return out


def _tracked(root):
    """Archivos versionados por git (None si no es un repo git)."""
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files"],
                           capture_output=True, text=True, check=True,
                           timeout=SUBPROCESS_TIMEOUT)
        return [l for l in r.stdout.splitlines() if l]
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


# Dockerfiles que el Reporter inspecciona (runtime y Dev Container).
DOCKERFILES = ("Dockerfile", ".devcontainer/Dockerfile")


def scan_docker(root):
    out = []
    for rel in DOCKERFILES:
        p = pathlib.Path(root, rel)
        if not p.exists():
            continue
        lines = p.read_text(errors="ignore").splitlines()

        def add(sev, line, ev, rule, rel=rel):
            out.append(Finding(f"DK-{len(out) + 1:03}", "docker", sev,
                               rel, line, ev, rule))

        if not any(l.strip().upper().startswith("USER ") for l in lines):
            add("medium", None, "no hay instrucción USER",
                "el contenedor se ejecuta como root")
        for i, l in enumerate(lines, 1):
            s = l.strip()
            m = re.match(r"FROM\s+(\S+)", s, re.I)
            if m:
                image = m.group(1)
                last = image.split("/")[-1]
                if (image.lower() != "scratch" and "@sha256:" not in image
                        and (":" not in last or image.endswith(":latest"))):
                    add("low", i, s, "imagen base sin versión fija (tag ausente o latest)")
            if re.search(r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(ba)?sh\b", s):
                add("medium", i, s, "script remoto ejecutado sin verificar integridad")
    return out


def scan_tracked_artifacts(root):
    files = _tracked(root)
    out = []
    if files is None:
        return out
    for rel in files:
        name = pathlib.PurePosixPath(rel).name
        if name == ".env":
            out.append(Finding(f"TR-{len(out) + 1:03}", "hygiene", "high", rel, None,
                               "'.env' está versionado", "archivo de secretos en el repositorio"))
        elif re.search(r"\.(pem|key|p12)$", name, re.I):
            out.append(Finding(f"TR-{len(out) + 1:03}", "hygiene", "high", rel, None,
                               "archivo de clave versionado", "posible material criptográfico en el repositorio"))
        elif re.search(r"\.(zip|tar\.gz)$", name, re.I) or re.fullmatch(r"results.*\.json", name):
            out.append(Finding(f"TR-{len(out) + 1:03}", "hygiene", "info", rel, None,
                               "artefacto generado versionado",
                               "revisar que no contenga datos sensibles y si debe estar en el repo"))
    return out


def scan_lockfile(root):
    files = _tracked(root)
    if files is None or "pyproject.toml" not in files:
        return []
    names = {pathlib.PurePosixPath(f).name for f in files}
    has_lock = ({"uv.lock", "poetry.lock", "Pipfile.lock"} & names
                or any(re.fullmatch(r"requirements.*\.txt", n) for n in names))
    if has_lock:
        return []
    return [Finding("DEP-001", "dependencies", "medium", "pyproject.toml", None,
                    "no hay lockfile ni requirements con versiones resueltas",
                    "las dependencias no están fijadas: builds no reproducibles y escaneo de CVEs limitado")]


def scan_dependencies(root):
    """Syft + Grype sobre una copia de los archivos versionados.
    Devuelve (hallazgos, nota de cobertura)."""
    from ..sbom_runner import generate_sbom, get_syft_version
    from ..grype_runner import get_grype_version, scan_vulnerabilities

    syft, grype = get_syft_version(), get_grype_version()
    if not syft or not grype:
        return [], "omitido: syft/grype no están disponibles en el PATH"
    files = _tracked(root)
    if files is None:
        return [], "omitido: el directorio no es un repositorio git"

    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        snap = tmp / "repo"
        for rel in files:
            src = pathlib.Path(root, rel)
            if src.is_file() and src.stat().st_size < 5_000_000:
                dst = snap / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        snap.mkdir(exist_ok=True)
        sbom = generate_sbom(snap, tmp / "self.cdx.json", syft)
        if sbom.status == "failed":
            return [], "omitido: Syft falló al generar el SBOM"
        if sbom.components == 0:
            return [], ("ejecutado, pero el SBOM tiene 0 componentes: "
                        "el resultado NO es concluyente (¿falta lockfile?)")
        vr = scan_vulnerabilities(f"sbom:{tmp / 'self.cdx.json'}",
                                  tmp / "self.grype.json", grype)

    if vr.status == "failed":
        return [], "omitido: Grype falló al escanear"
    out = []
    serious = [v for v in vr.vulnerabilities if v.severity in ("Critical", "High")]
    for v in serious[:20]:
        fix = f"; corregido en {v.fixed_version}" if v.fixed_version else "; sin versión corregida conocida"
        out.append(Finding(f"VUL-{len(out) + 1:03}", "vulnerability", v.severity.lower(),
                           "(SBOM del repositorio)", None,
                           f"{v.id} en {v.package} {v.version}{fix}",
                           "vulnerabilidad conocida en dependencia (Grype)"))
    note = f"ejecutado ({sbom.components} componentes, {vr.total} vulnerabilidades en total)"
    if len(serious) > 20:
        note += f"; se listan 20 de {len(serious)} Critical/High"
    return out, note


def collect_with_coverage(root="."):
    findings, coverage = [], {}
    for name, fn in [("secretos (archivos no ignorados por git)", scan_secrets),
                     ("workflows", scan_workflows),
                     ("docker (Dockerfile y .devcontainer/Dockerfile)", scan_docker),
                     ("higiene (.gitignore)", scan_hygiene),
                     ("archivos versionados", scan_tracked_artifacts),
                     ("lockfile", scan_lockfile)]:
        res = fn(root)
        findings += res
        coverage[name] = f"ejecutado ({len(res)} hallazgos)"
    dep, note = scan_dependencies(root)
    findings += dep
    coverage["dependencias (Syft+Grype)"] = note
    return [asdict(f) for f in findings], coverage


def collect(root="."):
    return collect_with_coverage(root)[0]