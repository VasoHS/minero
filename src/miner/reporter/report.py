import json
import re
import pathlib
import datetime

from .collector import collect_with_coverage
from .llm import ask
from .prompts import SYSTEM


def build_report(root=".", output="reports/security-report.md", use_llm=True):
    findings, coverage = collect_with_coverage(root)

    if not findings:
        narrative = ("No se encontraron hallazgos con las reglas actuales. "
                     "Revise la sección de cobertura: ausencia de hallazgos no implica ausencia de riesgo.")
    elif use_llm:
        payload = {"hallazgos": findings, "cobertura": coverage}
        narrative = ask(SYSTEM, json.dumps(payload, ensure_ascii=False, indent=2))
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
    uncited = valid - cited
    if use_llm and findings and uncited:
        warning += (f"\n> **Nota:** el modelo no comentó estos hallazgos "
                    f"(ver apéndice): {sorted(uncited)}.\n")

    cov = "\n".join(f"| {k} | {v} |" for k, v in coverage.items())
    coverage_md = "\n## Cobertura del análisis\n\n| Verificación | Estado |\n|---|---|\n" + cov

    rows = "\n".join(
        f"| {f['id']} | {f['severity']} | `{f['file']}` | {f['line'] or '-'} | {f['rule']} | {f['evidence']} |"
        for f in findings
    )
    appendix = ("\n## Apéndice: evidencia\n\n"
                "| ID | Severidad | Archivo | Línea | Regla | Evidencia |\n"
                "|---|---|---|---|---|---|\n" + rows)

    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    mode = "con modelo de lenguaje" if use_llm else "sin modelo de lenguaje"
    md = (f"# Reporte de seguridad\n\n_Generado: {now}_  \n"
          f"_Hallazgos detectados: {len(findings)} ({mode})_\n\n"
          f"{warning}\n{narrative}\n{coverage_md}\n{appendix}\n")

    out = pathlib.Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    return out