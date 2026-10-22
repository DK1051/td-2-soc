"""The blind-hunt guard of scripts/run_detections.py (no emulator needed).

Uses a temporary folder shaped like the repo; it never looks at the real 2e-blind-hunt/data.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import run_detections


def make_repo(tmp_path, with_labels):
    data = tmp_path / "2e-blind-hunt" / "data"
    data.mkdir(parents=True)
    (tmp_path / "fixtures").mkdir()
    if with_labels:
        (tmp_path / "2e-blind-hunt" / "my-labels.json").write_text("{}", encoding="utf-8")
    return data


def test_hunt_data_refused_without_labels(tmp_path):
    data = make_repo(tmp_path, with_labels=False)
    assert not run_detections.data_dir_allowed(data, tmp_path)
    assert not run_detections.data_dir_allowed(data / "sub", tmp_path)
    assert not run_detections.data_dir_allowed(tmp_path / "fixtures" / ".." / "2e-blind-hunt" / "data",
                                               tmp_path)


def test_hunt_data_refused_through_a_symlink(tmp_path):
    data = make_repo(tmp_path, with_labels=False)
    link = tmp_path / "innocent-looking"
    link.symlink_to(data, target_is_directory=True)
    assert not run_detections.data_dir_allowed(link, tmp_path)


def test_hunt_data_allowed_once_labels_exist(tmp_path):
    data = make_repo(tmp_path, with_labels=True)
    assert run_detections.data_dir_allowed(data, tmp_path)


def test_other_folders_always_allowed(tmp_path):
    make_repo(tmp_path, with_labels=False)
    assert run_detections.data_dir_allowed(tmp_path / "fixtures", tmp_path)
    # a folder that merely starts with the same letters is not the hunt data
    assert run_detections.data_dir_allowed(tmp_path / "2e-blind-hunt" / "data-copy", tmp_path)
