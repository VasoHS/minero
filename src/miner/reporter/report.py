import json
import re
import pathlib
import datetime

from .collector import collect
from .llm import ask
from .prompts import SYSTEM


def build_report(root=".", output="reports/security-report.md", use_llm=True):
    findings = collect(root)

    if not findings:
        narrative = "No se encontraron hallazgos con las reglas actuales."
    elif use_llm:
        narrative = ask(SYSTEM, json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        narrative = ("_Reporte generado sin modelo de lenguaje (`--no-llm`): "
                     "solo se incluye la evidencia del apéndice._")
    valid = {f["id"] for f in findings}
    cited = set(re.findall(r"\[([A-Z]+-\d{3})\]", narrative))
    invalid = cited - valid
    warning = ""
    if invalid:
        warning = (f"\n> **Advertencia:** el modelo citó IDs que no existen en la evidencia: "
                   f"{sorted(invalid)}. Revisar manualmente.\n")

    rows = "\n".join(
        f"| {f['id']} | {f['severity']} | `{f['file']}` | {f['line'] or '-'} | {f['rule']} |"
        for f in findings
    )
    appendix = ("\n## Apéndice: evidencia\n\n"
                "| ID | Severidad | Archivo | Línea | Regla |\n|---|---|---|---|---|\n" + rows)

    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    md = (f"# Reporte de seguridad\n\n_Generado: {now}_  \n"
          f"_Hallazgos detectados: {len(findings)}_\n\n{warning}\n{narrative}\n{appendix}\n")

    out = pathlib.Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    return out