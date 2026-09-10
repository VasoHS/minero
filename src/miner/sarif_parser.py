import json
from pathlib import Path
from typing import List
from .models import Finding

def parse_sarif(sarif_path: Path) -> List[Finding]:
    if not sarif_path.exists():
        return []
    
    with open(sarif_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    findings = []
    runs = data.get("runs", [])
    if not runs:
        return findings
    
    for result in runs[0].get("results", []):
        rule_id = result.get("ruleId", "unknown")
        message = result.get("message", {}).get("text", "")
        level = result.get("level", "warning")
        
        locations = result.get("locations", [])
        artifact = "unknown"
        start_line = None
        if locations:
            phys_loc = locations[0].get("physicalLocation", {})
            artifact = phys_loc.get("artifactLocation", {}).get("uri", "unknown")
            region = phys_loc.get("region", {})
            start_line = region.get("startLine")
        
        findings.append(Finding(
            rule_id=rule_id,
            severity=level,
            message=message,
            file=artifact,
            start_line=start_line
        ))
    
    return findings
