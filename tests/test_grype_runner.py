import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest

from miner.grype_runner import (
    SEVERITIES,
    get_grype_version,
    parse_matches,
    scan_vulnerabilities,
    summarize_by_severity,
)
from miner.models import Vulnerability


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def make_match(vuln_id="CVE-2021-0001", severity="High", name="lodash",
               version="4.17.20", type="npm", namespace="nvd:cpe",
               fix_versions=None):
    vulnerability = {
        "id": vuln_id,
        "severity": severity,
        "namespace": namespace,
    }
    if fix_versions is not None:
        vulnerability["fix"] = {"versions": fix_versions}
    return {
        "vulnerability": vulnerability,
        "artifact": {"name": name, "version": version, "type": type},
    }


# ---------------------------------------------------------------------------
# get_grype_version
# ---------------------------------------------------------------------------

def test_get_grype_version_success():
    with patch("miner.grype_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"version": "0.87.0"}))
        version = get_grype_version()

    assert version == "0.87.0"
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == ["grype", "version", "-o", "json"]
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True


@pytest.mark.parametrize(
    "error",
    [
        subprocess.CalledProcessError(returncode=1, cmd="grype version"),
        FileNotFoundError(),
        OSError(),
    ],
)
def test_get_grype_version_returns_none_on_error(error):
    with patch("miner.grype_runner.subprocess.run", side_effect=error):
        assert get_grype_version() is None


def test_get_grype_version_returns_none_on_invalid_json():
    with patch("miner.grype_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout="no es json")
        assert get_grype_version() is None


def test_get_grype_version_returns_none_without_version_key():
    with patch("miner.grype_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"other": "value"}))
        assert get_grype_version() is None


def test_get_grype_version_returns_none_for_numeric_version():
    with patch("miner.grype_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"version": 1.2}))
        assert get_grype_version() is None


def test_get_grype_version_returns_none_for_empty_version():
    with patch("miner.grype_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"version": ""}))
        assert get_grype_version() is None


# ---------------------------------------------------------------------------
# parse_matches
# ---------------------------------------------------------------------------

def test_parse_matches_full_entry():
    data = {"matches": [make_match(
        vuln_id="CVE-2021-1234",
        severity="Critical",
        name="openssl",
        version="1.1.1",
        type="deb",
        namespace="debian:11",
        fix_versions=["1.1.1k", "1.1.1l"],
    )]}

    vulnerabilities = parse_matches(data)

    assert len(vulnerabilities) == 1
    vulnerability = vulnerabilities[0]
    assert vulnerability.id == "CVE-2021-1234"
    assert vulnerability.severity == "Critical"
    assert vulnerability.package == "openssl"
    assert vulnerability.version == "1.1.1"
    assert vulnerability.type == "deb"
    assert vulnerability.fixed_version == "1.1.1k"
    assert vulnerability.namespace == "debian:11"


def test_parse_matches_without_fix_versions():
    vulnerabilities = parse_matches({"matches": [make_match()]})
    assert vulnerabilities[0].fixed_version is None


def test_parse_matches_empty_fix_versions():
    vulnerabilities = parse_matches(
        {"matches": [make_match(fix_versions=[])]}
    )
    assert vulnerabilities[0].fixed_version is None


@pytest.mark.parametrize("raw_versions", ["1.1.1k", 5, {"v": "1"}])
def test_parse_matches_fix_versions_not_a_list(raw_versions):
    vulnerabilities = parse_matches(
        {"matches": [make_match(fix_versions=raw_versions)]}
    )
    assert vulnerabilities[0].fixed_version is None


def test_parse_matches_fix_versions_null():
    match = make_match()
    match["vulnerability"]["fix"] = {"versions": None}
    vulnerabilities = parse_matches({"matches": [match]})
    assert vulnerabilities[0].fixed_version is None


def test_parse_matches_fix_not_a_dict():
    match = make_match()
    match["vulnerability"]["fix"] = "1.1.1k"
    vulnerabilities = parse_matches({"matches": [match]})
    assert vulnerabilities[0].fixed_version is None


@pytest.mark.parametrize("raw_version", [123, None, ""])
def test_parse_matches_non_string_fix_version(raw_version):
    vulnerabilities = parse_matches(
        {"matches": [make_match(fix_versions=[raw_version])]}
    )
    assert vulnerabilities[0].fixed_version is None


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("critical", "Critical"),
        ("HIGH", "High"),
        ("  Medium ", "Medium"),
        ("low", "Low"),
        ("negligible", "Negligible"),
        ("unknown", "Unknown"),
        ("bogus", "Unknown"),
        (None, "Unknown"),
        (5, "Unknown"),
    ],
)
def test_parse_matches_normalizes_severity(raw, expected):
    match = make_match(severity=raw)
    vulnerabilities = parse_matches({"matches": [match]})
    assert vulnerabilities[0].severity == expected


def test_parse_matches_missing_fields_uses_defaults():
    vulnerabilities = parse_matches({"matches": [{}]})
    vulnerability = vulnerabilities[0]
    assert vulnerability.id == "unknown"
    assert vulnerability.package == "unknown"
    assert vulnerability.severity == "Unknown"
    assert vulnerability.version is None
    assert vulnerability.type is None
    assert vulnerability.fixed_version is None


def test_parse_matches_non_string_optional_fields_do_not_raise():
    # Pydantic v2 no coacciona int->str: los campos no-string deben quedar en None.
    match = make_match()
    match["artifact"]["version"] = 123
    match["artifact"]["type"] = ["npm"]
    match["vulnerability"]["namespace"] = 42

    vulnerabilities = parse_matches({"matches": [match]})

    vulnerability = vulnerabilities[0]
    assert vulnerability.version is None
    assert vulnerability.type is None
    assert vulnerability.namespace is None


def test_parse_matches_skips_non_dict_entries():
    data = {"matches": [make_match(), "no soy un objeto", 42]}
    vulnerabilities = parse_matches(data)
    assert len(vulnerabilities) == 1


def test_parse_matches_missing_matches_returns_empty():
    assert parse_matches({"source": {}}) == []


def test_parse_matches_matches_not_a_list_returns_none():
    assert parse_matches({"matches": "nope"}) is None


def test_parse_matches_non_dict_returns_none():
    assert parse_matches(["no es un objeto"]) is None
    assert parse_matches("texto") is None


# ---------------------------------------------------------------------------
# summarize_by_severity
# ---------------------------------------------------------------------------

def test_summarize_by_severity_counts_and_zeros():
    vulnerabilities = [
        Vulnerability(id="CVE-1", severity="High", package="a"),
        Vulnerability(id="CVE-2", severity="High", package="b"),
        Vulnerability(id="CVE-3", severity="Critical", package="c"),
        Vulnerability(id="CVE-4", severity="Unknown", package="d"),
    ]
    summary = summarize_by_severity(vulnerabilities)

    assert set(summary) == set(SEVERITIES)
    assert summary["Critical"] == 1
    assert summary["High"] == 2
    assert summary["Medium"] == 0
    assert summary["Low"] == 0
    assert summary["Negligible"] == 0
    assert summary["Unknown"] == 1


# ---------------------------------------------------------------------------
# scan_vulnerabilities
# ---------------------------------------------------------------------------

def test_scan_vulnerabilities_success(tmp_path):
    source = f"sbom:{tmp_path / 'repo.cdx.json'}"
    output_file = tmp_path / "nested" / "out.grype.json"
    observed = {}

    def fake_run(cmd, **kwargs):
        output = Path(cmd[cmd.index("--file") + 1])
        observed["parent_existed"] = output.parent.is_dir()
        write_json(output, {"matches": [
            make_match(vuln_id="CVE-2", severity="Medium", name="flask"),
            make_match(vuln_id="CVE-1", severity="Critical", name="requests"),
        ]})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run) as mock_run:
        result = scan_vulnerabilities(source, output_file, grype_version="0.87.0")

    assert result.status == "scanned"
    assert result.total == 2
    assert result.grype_version == "0.87.0"
    assert result.file == str(output_file)
    assert result.generated_at is not None
    assert result.by_severity["Critical"] == 1
    assert result.by_severity["Medium"] == 1
    assert observed["parent_existed"] is True
    assert output_file.exists()

    args, kwargs = mock_run.call_args
    assert args[0] == [
        "grype",
        source,
        "-o",
        "json",
        "--file",
        str(output_file),
    ]
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True


def test_scan_vulnerabilities_sorts_by_severity_then_package(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [
            make_match(vuln_id="CVE-3", severity="Low", name="aaa"),
            make_match(vuln_id="CVE-2", severity="High", name="zzz"),
            make_match(vuln_id="CVE-1", severity="High", name="aaa"),
        ]})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert [v.id for v in result.vulnerabilities] == ["CVE-1", "CVE-2", "CVE-3"]


def test_scan_vulnerabilities_tie_breaks_by_version(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [
            make_match(vuln_id="CVE-1", severity="High", name="pkg", version="2.0"),
            make_match(vuln_id="CVE-1", severity="High", name="pkg", version="1.0"),
        ]})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert [v.version for v in result.vulnerabilities] == ["1.0", "2.0"]


def test_scan_vulnerabilities_no_matches(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": []})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "no_vulnerabilities"
    assert result.total == 0
    assert result.by_severity["Critical"] == 0
    assert result.file == str(output_file)


def test_scan_vulnerabilities_discards_previous_output_before_grype(tmp_path):
    output_file = tmp_path / "out.grype.json"
    output_file.write_text("reporte viejo", encoding="utf-8")
    observed = {}

    def fake_run(cmd, **kwargs):
        output = Path(cmd[cmd.index("--file") + 1])
        observed["existed_at_run"] = output.exists()
        write_json(output, {"matches": [make_match()]})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "scanned"
    assert observed["existed_at_run"] is False


def test_scan_vulnerabilities_unreadable_result_is_failure(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        Path(cmd[cmd.index("--file") + 1]).write_text(
            "<html>no es json</html>", encoding="utf-8"
        )
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "failed"
    assert result.total == 0
    assert result.file is None
    assert not output_file.exists()


def test_scan_vulnerabilities_missing_matches_key_is_success(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"descriptor": {}})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "no_vulnerabilities"
    assert result.total == 0
    assert result.vulnerabilities == []
    assert result.by_severity["Critical"] == 0
    assert result.by_severity["Unknown"] == 0


def test_scan_vulnerabilities_matches_not_a_list_is_failure(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": "nope"})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "failed"
    assert result.total == 0
    assert result.file is None
    # Un reporte con 'matches' no-lista se considera ilegible y se descarta.
    assert not output_file.exists()


def test_scan_vulnerabilities_skips_non_dict_entries(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [
            make_match(vuln_id="CVE-1"),
            "no soy un objeto",
            42,
            None,
        ]})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "scanned"
    assert result.total == 1
    assert result.vulnerabilities[0].id == "CVE-1"


def test_scan_vulnerabilities_normalizes_non_canonical_severity(tmp_path):
    output_file = tmp_path / "out.grype.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [
            make_match(vuln_id="CVE-1", severity="bogus", name="pkg-a"),
            make_match(vuln_id="CVE-2", severity="Negligible", name="pkg-b"),
        ]})
        return Mock(returncode=0)

    with patch("miner.grype_runner.subprocess.run", side_effect=fake_run):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "scanned"
    assert result.total == 2
    assert result.by_severity["Unknown"] == 1
    assert result.by_severity["Negligible"] == 1
    assert result.by_severity["Critical"] == 0
    # 'Negligible' precede a 'Unknown' en el orden de severidad.
    assert [v.id for v in result.vulnerabilities] == ["CVE-2", "CVE-1"]


def test_scan_vulnerabilities_failure_discards_output(tmp_path):
    output_file = tmp_path / "out.grype.json"
    output_file.write_text("parcial", encoding="utf-8")
    error = subprocess.CalledProcessError(returncode=1, cmd="grype")

    with patch("miner.grype_runner.subprocess.run", side_effect=error):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "failed"
    assert result.total == 0
    assert result.file is None
    assert not output_file.exists()


@pytest.mark.parametrize(
    "error",
    [
        subprocess.CalledProcessError(returncode=1, cmd="grype"),
        FileNotFoundError(),
        OSError(),
    ],
)
def test_scan_vulnerabilities_failed(tmp_path, error):
    output_file = tmp_path / "out.grype.json"
    with patch("miner.grype_runner.subprocess.run", side_effect=error):
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "failed"
    assert result.total == 0
    assert result.file is None
    assert result.grype_version == "0.87.0"
    assert result.generated_at is not None


def test_scan_vulnerabilities_mkdir_failure(tmp_path):
    blocker = tmp_path / "bloqueado"
    blocker.write_text("no soy un directorio", encoding="utf-8")
    output_file = blocker / "sub" / "grype.json"

    with patch("miner.grype_runner.subprocess.run") as mock_run:
        result = scan_vulnerabilities("dir:/repo", output_file, grype_version="0.87.0")

    assert result.status == "failed"
    assert result.total == 0
    assert result.file is None
    assert result.grype_version == "0.87.0"
    # Ni siquiera se llega a invocar Grype si no se puede preparar la salida.
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# scan_vulnerabilities con progreso en tiempo real (Popen)
# ---------------------------------------------------------------------------

class FakeStdout:
    """Doble de `process.stdout`: iterable, cerrable y con líneas controladas."""

    def __init__(self, lines):
        self._lines = lines
        self.closed = False

    def __iter__(self):
        return iter(self._lines)

    def close(self):
        self.closed = True


def make_process(lines, returncode=0):
    """Simula un subprocess.Popen con stdout iterable y wait() controlado."""
    process = Mock()
    process.stdout = FakeStdout(lines)
    process.wait.return_value = returncode
    return process


def test_scan_vulnerabilities_with_progress_streams_lines(tmp_path):
    output_file = tmp_path / "nested" / "out.grype.json"
    progress = Mock()
    observed = {}

    def fake_popen(cmd, **kwargs):
        observed["cmd"] = cmd
        observed["kwargs"] = kwargs
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [make_match()]})
        return make_process(["linea 1\n", "\n", "linea 2\n"], returncode=0)

    with patch("miner.grype_runner.subprocess.Popen", side_effect=fake_popen) as mock_popen:
        result = scan_vulnerabilities(
            "dir:/repo", output_file, grype_version="0.87.0", progress=progress
        )

    assert result.status == "scanned"
    assert result.total == 1
    assert output_file.exists()
    # Se transmite cada línea no vacía, sin el salto de línea final.
    assert progress.line.call_args_list == [call("linea 1"), call("linea 2")]
    assert mock_popen.call_count == 1
    assert observed["kwargs"]["stdout"] == subprocess.PIPE
    assert observed["kwargs"]["stderr"] == subprocess.STDOUT
    assert observed["kwargs"]["text"] is True
    assert observed["kwargs"]["bufsize"] == 1


def test_scan_vulnerabilities_with_progress_failure_reports_error(tmp_path):
    output_file = tmp_path / "out.grype.json"
    progress = Mock()

    def fake_popen(cmd, **kwargs):
        return make_process(["grype: error\n"], returncode=1)

    with patch("miner.grype_runner.subprocess.Popen", side_effect=fake_popen):
        result = scan_vulnerabilities(
            "dir:/repo", output_file, grype_version="0.87.0", progress=progress
        )

    assert result.status == "failed"
    assert result.total == 0
    assert result.file is None
    assert not output_file.exists()
    # La línea de error igualmente se transmite en vivo.
    progress.line.assert_called_once_with("grype: error")
    progress.error.assert_called()
    assert any(
        "Grype falló" in args[0] for args, _ in progress.error.call_args_list
    )


def test_scan_vulnerabilities_with_progress_file_not_found(tmp_path):
    output_file = tmp_path / "out.grype.json"
    progress = Mock()

    with patch(
        "miner.grype_runner.subprocess.Popen", side_effect=FileNotFoundError()
    ):
        result = scan_vulnerabilities(
            "dir:/repo", output_file, grype_version="0.87.0", progress=progress
        )

    assert result.status == "failed"
    assert result.file is None
    progress.error.assert_called_once()
    assert "Grype falló" in progress.error.call_args.args[0]


def test_scan_vulnerabilities_progress_line_exception_does_not_abort(tmp_path):
    output_file = tmp_path / "out.grype.json"
    progress = Mock()
    progress.line.side_effect = RuntimeError("callback roto")

    def fake_popen(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [make_match()]})
        return make_process(["linea\n"], returncode=0)

    with patch("miner.grype_runner.subprocess.Popen", side_effect=fake_popen):
        result = scan_vulnerabilities(
            "dir:/repo", output_file, grype_version="0.87.0", progress=progress
        )

    # Un fallo al mostrar el avance no debe abortar el escaneo.
    assert result.status == "scanned"
    progress.line.assert_called_once_with("linea")


def test_scan_vulnerabilities_progress_error_exception_is_ignored(tmp_path):
    blocker = tmp_path / "bloqueado"
    blocker.write_text("no soy un directorio", encoding="utf-8")
    output_file = blocker / "sub" / "out.grype.json"
    progress = Mock()
    progress.error.side_effect = RuntimeError("no se pudo reportar")

    result = scan_vulnerabilities(
        "dir:/repo", output_file, grype_version="0.87.0", progress=progress
    )

    # El fallo al notificar el error tampoco interrumpe el escaneo.
    assert result.status == "failed"
    progress.error.assert_called_once()


def test_scan_vulnerabilities_progress_closes_stdout(tmp_path):
    output_file = tmp_path / "out.grype.json"
    progress = Mock()
    process = make_process(["linea\n"], returncode=0)

    def fake_popen(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [make_match()]})
        return process

    with patch("miner.grype_runner.subprocess.Popen", side_effect=fake_popen):
        scan_vulnerabilities(
            "dir:/repo", output_file, grype_version="0.87.0", progress=progress
        )

    assert process.stdout.closed is True


def test_scan_vulnerabilities_progress_interrupt_kills_process(tmp_path):
    output_file = tmp_path / "out.grype.json"
    progress = Mock()
    # Un KeyboardInterrupt (BaseException) no debe dejar el hijo huérfano.
    progress.line.side_effect = KeyboardInterrupt()
    process = make_process(["linea\n"], returncode=0)

    with patch(
        "miner.grype_runner.subprocess.Popen", return_value=process
    ):
        with pytest.raises(KeyboardInterrupt):
            scan_vulnerabilities(
                "dir:/repo", output_file, grype_version="0.87.0", progress=progress
            )

    process.kill.assert_called_once()
    process.wait.assert_called_once()
    assert process.stdout.closed is True


def test_scan_vulnerabilities_progress_handles_carriage_return(tmp_path):
    output_file = tmp_path / "out.grype.json"
    progress = Mock()

    def fake_popen(cmd, **kwargs):
        write_json(Path(cmd[cmd.index("--file") + 1]), {"matches": [make_match()]})
        return make_process(["progreso\r\n"], returncode=0)

    with patch("miner.grype_runner.subprocess.Popen", side_effect=fake_popen):
        scan_vulnerabilities(
            "dir:/repo", output_file, grype_version="0.87.0", progress=progress
        )

    progress.line.assert_called_once_with("progreso")
