import subprocess
from unittest.mock import Mock, patch

import pytest

from miner.git_utils import (
    clone_repository,
    get_head_commit,
    get_remote_url,
    parse_full_name,
)


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


def test_get_head_commit_success(tmp_path):
    repo_dir = tmp_path / "repo"
    with patch("miner.git_utils.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout="abc123def\n")
        result = get_head_commit(repo_dir)

    assert result == "abc123def"
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == ["git", "-C", str(repo_dir), "rev-parse", "HEAD"]
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True


def test_get_head_commit_empty_returns_none(tmp_path):
    with patch("miner.git_utils.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout="   \n")
        result = get_head_commit(tmp_path / "repo")

    assert result is None


@pytest.mark.parametrize(
    "error",
    [
        subprocess.CalledProcessError(returncode=128, cmd="git rev-parse"),
        FileNotFoundError(),
        OSError(),
    ],
)
def test_get_head_commit_error_returns_none(tmp_path, error):
    with patch("miner.git_utils.subprocess.run", side_effect=error):
        result = get_head_commit(tmp_path / "repo")

    assert result is None


def test_get_remote_url_success(tmp_path):
    repo_dir = tmp_path / "repo"
    with patch("miner.git_utils.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout="git@github.com:org/repo.git\n")
        result = get_remote_url(repo_dir)

    assert result == "git@github.com:org/repo.git"
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == ["git", "-C", str(repo_dir), "remote", "get-url", "origin"]
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True


def test_get_remote_url_empty_returns_none(tmp_path):
    with patch("miner.git_utils.subprocess.run") as mock_run:
        mock_run.return_value = Mock(stdout="\n")
        result = get_remote_url(tmp_path / "repo")

    assert result is None


def test_get_remote_url_error_returns_none(tmp_path):
    error = subprocess.CalledProcessError(returncode=2, cmd="git remote")
    with patch("miner.git_utils.subprocess.run", side_effect=error):
        result = get_remote_url(tmp_path / "repo")

    assert result is None


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/octocat/hello-world.git", "octocat/hello-world"),
        ("https://github.com/octocat/hello-world", "octocat/hello-world"),
        ("git@github.com:octocat/hello-world.git", "octocat/hello-world"),
        ("git@github.com:octocat/hello-world", "octocat/hello-world"),
        ("octocat/hello-world", "octocat/hello-world"),
        (None, None),
        ("", None),
        ("   ", None),
        ("https://github.com/onlyowner", None),
        ("just-a-name", None),
    ],
)
def test_parse_full_name(url, expected):
    assert parse_full_name(url) == expected
