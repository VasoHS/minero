import subprocess
from unittest.mock import patch

from miner.git_utils import clone_repository


def test_clone_repository_success(tmp_path):
    dest = tmp_path / "repo"
    with patch("miner.git_utils.subprocess.run") as mock_run:
        result = clone_repository("https://github.com/org/repo.git", dest)

    assert result is True
    mock_run.assert_called_once()

    args, kwargs = mock_run.call_args
    assert args[0] == [
        "git",
        "clone",
        "--depth",
        "1",
        "https://github.com/org/repo.git",
        str(dest),
    ]
    assert kwargs["check"] is True


def test_clone_repository_called_process_error(tmp_path):
    dest = tmp_path / "repo"
    error = subprocess.CalledProcessError(returncode=1, cmd="git clone")
    with patch("miner.git_utils.subprocess.run", side_effect=error):
        result = clone_repository("https://github.com/org/repo.git", dest)

    assert result is False


def test_clone_repository_file_not_found(tmp_path):
    dest = tmp_path / "repo"
    with patch("miner.git_utils.subprocess.run", side_effect=FileNotFoundError):
        result = clone_repository("https://github.com/org/repo.git", dest)

    assert result is False
