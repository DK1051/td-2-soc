import json

import pytest
import triage_fixture as fx
import yaml
from make_batches import FIELDS, MissingField, insert_text
from triage_common import load_labels


def read_path(node, path):
    for key in path:
        if isinstance(node, str):
            node = json.loads(node)
        node = node[key]
    return node


def load(tmp_path, name):
    return json.loads((tmp_path / "batches" / name).read_text())


def all_batches(tmp_path):
    return {p.name: json.loads(p.read_text())
            for p in sorted((tmp_path / "batches").glob("*-*.json"))}


def test_clean_sample_keeps_window_and_spreads(tmp_path):
    alerts = fx.write_inputs(tmp_path)
    assert fx.run_make(tmp_path) == 0
    labels = load_labels(tmp_path / "labels.json")
    from triage_common import is_takeover
    sample = [a for n, b in all_batches(tmp_path).items() if n.startswith("clean-") for a in b]
    assert len(sample) == 8
    window_ids = {a["alert_id"] for a in alerts if is_takeover(a, labels)}
    assert len(window_ids) == 2  # 00:00 and 04:00, both bounds inclusive
    assert window_ids <= {a["alert_id"] for a in sample}
    assert {a["detection_id"] for a in sample} == {"D0", "D1", "D2"}
    assert all(len(b) <= 6 for n, b in all_batches(tmp_path).items() if n.startswith("clean-"))


def test_same_seed_same_batches(tmp_path):
    fx.write_inputs(tmp_path)
    fx.run_make(tmp_path, out="one")
    fx.run_make(tmp_path, out="two")
    for path in (tmp_path / "one").iterdir():
        assert path.read_text() == (tmp_path / "two" / path.name).read_text()


def test_manifest_points_to_inserted_text(tmp_path, capsys):
    fx.write_inputs(tmp_path)
    fx.run_make(tmp_path)
    assert "placeholder" not in capsys.readouterr().out  # string text is never printed
    manifest = load(tmp_path, "manifest.json")
    batches = all_batches(tmp_path)
    texts = {s["id"]: s["text"] for s in yaml.safe_load((tmp_path / "strings.yaml").read_text())}
    clean = {a["alert_id"]: a for n, b in batches.items() if n.startswith("clean-") for a in b}
    assert len(manifest) == 6  # 2 strings x 3
    assert {m["field"] for m in manifest.values()} == set(FIELDS)
    for pid, m in manifest.items():
        batch = {a["alert_id"]: a for a in batches[m["batch"]]}
        poisoned, twin, original = batch[pid], batch[m["clean_twin"]], clean[m["original_id"]]
        text = texts[m["injection_id"]]
        old = read_path(original, FIELDS[m["field"]])
        assert read_path(poisoned, FIELDS[m["field"]]) == f"{old} {text}"
        # a copy with only the id and that one field changed
        assert poisoned == insert_text({**original, "alert_id": pid}, m["field"], text)
        assert twin == {**original, "alert_id": m["clean_twin"]}


def test_ids_unique_and_fresh(tmp_path):
    alerts = fx.write_inputs(tmp_path)
    fx.run_make(tmp_path)
    ids = [a["alert_id"] for n, b in all_batches(tmp_path).items()
           if n.startswith("poisoned-") for a in b]
    assert len(ids) == len(set(ids)) == 12
    assert not set(ids) & {a["alert_id"] for a in alerts}


def test_insert_both_forms_and_missing_field():
    dict_form = {"evidence": {"DeviceDetail": {"displayName": "pc"}}}
    text_form = {"evidence": {"DeviceDetail": json.dumps({"displayName": "pc"})}}
    field = "evidence.DeviceDetail.displayName"
    assert insert_text(dict_form, field, "T")["evidence"]["DeviceDetail"] == {"displayName": "pc T"}
    out = insert_text(text_form, field, "T")["evidence"]["DeviceDetail"]
    assert isinstance(out, str) and json.loads(out) == {"displayName": "pc T"}
    assert dict_form["evidence"]["DeviceDetail"] == {"displayName": "pc"}  # input untouched
    with pytest.raises(MissingField):
        insert_text({"evidence": {}}, field, "T")


def test_strings_file_validation(tmp_path):
    fx.write_inputs(tmp_path)
    with pytest.raises(SystemExit):  # file holds 2 entries, default expects 10
        fx.make_batches.main(["--alerts", str(tmp_path / "alerts.jsonl"),
                              "--strings", str(tmp_path / "strings.yaml"),
                              "--labels", str(tmp_path / "labels.json"),
                              "--out", str(tmp_path / "x")])
    bad = yaml.safe_load((tmp_path / "strings.yaml").read_text())
    del bad[0]["marker"]
    (tmp_path / "strings.yaml").write_text(yaml.safe_dump(bad))
    with pytest.raises(SystemExit):
        fx.run_make(tmp_path)
