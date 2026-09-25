import json
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from miner.sbom_runner import count_components, generate_sbom, get_syft_version


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# get_syft_version
# ---------------------------------------------------------------------------

def test_get_syft_version_success():
    with patch("miner.sbom_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"version": "1.2.3"}))
        version = get_syft_version()

    assert version == "1.2.3"
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == ["syft", "version", "-o", "json"]
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True


@pytest.mark.parametrize(
    "error",
    [
        subprocess.CalledProcessError(returncode=1, cmd="syft version"),
        FileNotFoundError(),
        OSError(),
    ],
)
def test_get_syft_version_returns_none_on_error(error):
    with patch("miner.sbom_runner.subprocess.run", side_effect=error):
        assert get_syft_version() is None


def test_get_syft_version_returns_none_on_invalid_json():
    with patch("miner.sbom_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout="no es json")
        assert get_syft_version() is None


def test_get_syft_version_returns_none_without_version_key():
    with patch("miner.sbom_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"other": "value"}))
        assert get_syft_version() is None


def test_get_syft_version_returns_none_for_numeric_version():
    with patch("miner.sbom_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"version": 1.2}))
        assert get_syft_version() is None


def test_get_syft_version_returns_none_for_empty_version():
    with patch("miner.sbom_runner.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout=json.dumps({"version": ""}))
        assert get_syft_version() is None


# ---------------------------------------------------------------------------
# count_components
# ---------------------------------------------------------------------------

def test_count_components_list(tmp_path):
    sbom = write_json(tmp_path / "bom.json", {"components": [{"a": 1}, {"b": 2}]})
    assert count_components(sbom) == 2


def test_count_components_missing_key(tmp_path):
    sbom = write_json(tmp_path / "bom.json", {"metadata": {}})
    assert count_components(sbom) == 0


def test_count_components_empty_list(tmp_path):
    sbom = write_json(tmp_path / "bom.json", {"components": []})
    assert count_components(sbom) == 0


def test_count_components_not_a_list_returns_none(tmp_path):
    sbom = write_json(tmp_path / "bom.json", {"components": "nope"})
    assert count_components(sbom) is None


def test_count_components_invalid_json_returns_none(tmp_path):
    sbom = tmp_path / "bom.json"
    sbom.write_text("{ no json", encoding="utf-8")
    assert count_components(sbom) is None


def test_count_components_missing_file_returns_none(tmp_path):
    assert count_components(tmp_path / "missing.json") is None


def test_count_components_json_is_list_returns_none(tmp_path):
    sbom = write_json(tmp_path / "bom.json", [{"name": "a"}])
    assert count_components(sbom) is None


def test_count_components_non_utf8_bytes_returns_none(tmp_path):
    sbom = tmp_path / "bom.json"
    sbom.write_bytes(b"\xff\xfe\x00 not utf-8")
    # No debe propagar UnicodeDecodeError; se trata como SBOM ilegible.
    assert count_components(sbom) is None


# ---------------------------------------------------------------------------
# generate_sbom
# ---------------------------------------------------------------------------

def test_generate_sbom_success(tmp_path):
    source_dir = tmp_path / "src"
    output_file = tmp_path / "nested" / "out.cdx.json"
    observed = {}

    def fake_run(cmd, **kwargs):
        output = Path(cmd[3].split("=", 1)[1])
        # generate_sbom debe crear el directorio padre antes de invocar Syft.
        observed["parent_existed"] = output.parent.is_dir()
        write_json(output, {"components": [{"name": "a"}, {"name": "b"}]})
        return Mock(returncode=0)

    with patch("miner.sbom_runner.subprocess.run", side_effect=fake_run) as mock_run:
        result = generate_sbom(source_dir, output_file, syft_version="9.9.9")

    assert result.status == "generated"
    assert result.components == 2
    assert result.syft_version == "9.9.9"
    assert result.file == str(output_file)
    assert result.generated_at is not None
    assert observed["parent_existed"] is True
    assert output_file.exists()

    args, kwargs = mock_run.call_args
    assert args[0] == [
        "syft",
        f"dir:{source_dir}",
        "-o",
        f"cyclonedx-json={output_file}",
    ]
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True


def test_generate_sbom_no_components(tmp_path):
    output_file = tmp_path / "out.cdx.json"

    def fake_run(cmd, **kwargs):
        write_json(Path(cmd[3].split("=", 1)[1]), {"components": []})
        return Mock(returncode=0)

    with patch("miner.sbom_runner.subprocess.run", side_effect=fake_run):
        result = generate_sbom(tmp_path / "src", output_file, syft_version="9.9.9")

    assert result.status == "no_components"
    assert result.components == 0
    assert result.syft_version == "9.9.9"
    assert result.file == str(output_file)


def test_generate_sbom_discards_previous_output_before_syft(tmp_path):
    output_file = tmp_path / "out.cdx.json"
    output_file.write_text("sbom viejo", encoding="utf-8")
    observed = {}

    def fake_run(cmd, **kwargs):
        output = Path(cmd[3].split("=", 1)[1])
        # El SBOM previo debe haberse borrado antes de invocar a Syft.
        observed["existed_at_run"] = output.exists()
        write_json(output, {"components": [{"name": "a"}]})
        return Mock(returncode=0)

    with patch("miner.sbom_runner.subprocess.run", side_effect=fake_run):
        result = generate_sbom(tmp_path / "src", output_file, syft_version="9.9.9")

    assert result.status == "generated"
    assert observed["existed_at_run"] is False


def test_generate_sbom_unreadable_result_is_failure(tmp_path):
    output_file = tmp_path / "out.cdx.json"

    def fake_run(cmd, **kwargs):
        # Syft "termina bien" pero deja un SBOM ilegible.
        Path(cmd[3].split("=", 1)[1]).write_text(
            "<html>no es json</html>", encoding="utf-8"
        )
        return Mock(returncode=0)

    with patch("miner.sbom_runner.subprocess.run", side_effect=fake_run):
        result = generate_sbom(tmp_path / "src", output_file, syft_version="9.9.9")

    assert result.status == "failed"
    assert result.components == 0
    assert result.file is None
    # El SBOM ilegible se elimina.
    assert not output_file.exists()


def test_generate_sbom_failure_discards_output(tmp_path):
    output_file = tmp_path / "out.cdx.json"
    output_file.write_text("parcial", encoding="utf-8")
    error = subprocess.CalledProcessError(returncode=1, cmd="syft dir")

    with patch("miner.sbom_runner.subprocess.run", side_effect=error):
        result = generate_sbom(tmp_path / "src", output_file, syft_version="9.9.9")

    assert result.status == "failed"
    assert result.components == 0
    assert result.file is None
    assert not output_file.exists()


def test_generate_sbom_mkdir_failure(tmp_path):
    # Un archivo en medio de la ruta hace que mkdir(parents=True) falle con OSError.
    blocker = tmp_path / "bloqueado"
    blocker.write_text("no soy un directorio", encoding="utf-8")
    output_file = blocker / "sub" / "bom.json"

    with patch("miner.sbom_runner.subprocess.run") as mock_run:
        result = generate_sbom(tmp_path / "src", output_file, syft_version="9.9.9")

    assert result.status == "failed"
    assert result.components == 0
    assert result.file is None
    assert result.syft_version == "9.9.9"
    # Ni siquiera se llega a invocar Syft si no se puede preparar la salida.
    mock_run.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        subprocess.CalledProcessError(returncode=1, cmd="syft dir"),
        FileNotFoundError(),
        OSError(),
    ],
)
def test_generate_sbom_failed(tmp_path, error):
    output_file = tmp_path / "out.cdx.json"
    with patch("miner.sbom_runner.subprocess.run", side_effect=error):
        result = generate_sbom(tmp_path / "src", output_file, syft_version="9.9.9")

    assert result.status == "failed"
    assert result.components == 0
    assert result.file is None
    assert result.syft_version == "9.9.9"
    assert result.generated_at is not None
