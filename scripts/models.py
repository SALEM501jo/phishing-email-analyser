"""
Model binaries live in GitHub Releases, not in git: the repo stays small, and models/manifest.json (committed)
records exactly which model the code expects - version, SHA-256 of every file, the commit that trained it, and
headline metrics. Small readable files (model-info.json, metrics.json) stay in git so their diffs show lineage.

    python scripts/models.py fetch     # download the model the manifest names, verify checksums (CI, Docker, fresh clone)
    python scripts/models.py verify    # check local files against the manifest
    python scripts/models.py publish   # after training: upload local models as release "model-<version>", update the manifest

Needs the GitHub CLI (gh), logged in, or GH_TOKEN in CI.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"
MANIFEST = MODELS / "manifest.json"
LINEAR = "phishing-content-model.zip"
TRANSFORMER_DIR = MODELS / "transformer"
TRANSFORMER_ZIP = "transformer.zip"   # the transformer folder travels as one asset


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gh(*args, capture=False):
    result = subprocess.run(["gh", *args], cwd=ROOT, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def load_manifest():
    if not MANIFEST.exists():
        sys.exit(f"{MANIFEST.relative_to(ROOT)} not found - nothing published yet")
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def transformer_marker(manifest):
    return TRANSFORMER_DIR / f".from-{manifest['release']}"


def local_ok(manifest, asset):
    if asset["name"] == TRANSFORMER_ZIP:   # unpacked on fetch; a marker records which release it came from
        return transformer_marker(manifest).exists() and (TRANSFORMER_DIR / "model.onnx").exists()
    path = MODELS / asset["name"]
    return path.exists() and path.stat().st_size == asset["size"] and sha256(path) == asset["sha256"]


def fetch():
    manifest = load_manifest()
    missing = [a for a in manifest["assets"] if not local_ok(manifest, a)]
    if not missing:
        print(f"models up to date ({manifest['release']})")
        return
    with tempfile.TemporaryDirectory() as tmp:
        for asset in missing:
            print(f"downloading {asset['name']} ({asset['size'] / 1e6:.0f} MB) from {manifest['release']}")
            gh("release", "download", manifest["release"], "--pattern", asset["name"], "--dir", tmp, "--clobber")
            downloaded = Path(tmp) / asset["name"]
            actual = sha256(downloaded)
            if actual != asset["sha256"]:
                sys.exit(f"CHECKSUM MISMATCH for {asset['name']}: expected {asset['sha256']}, got {actual} - refusing to use it")
            if asset["name"] == TRANSFORMER_ZIP:
                shutil.rmtree(TRANSFORMER_DIR, ignore_errors=True)
                with zipfile.ZipFile(downloaded) as z:
                    z.extractall(TRANSFORMER_DIR)
                transformer_marker(manifest).touch()
            else:
                shutil.move(downloaded, MODELS / asset["name"])
    print(f"models fetched and verified ({manifest['release']})")


def verify():
    manifest = load_manifest()
    bad = [a["name"] for a in manifest["assets"] if not local_ok(manifest, a)]
    if bad:
        sys.exit(f"not matching the manifest: {', '.join(bad)} - run: python scripts/models.py fetch")
    print(f"all model files match {manifest['release']}")


def headline(metrics):
    """The calibrated end-to-end numbers on the modern test split, for quick comparison between releases."""
    calibrated = ((metrics.get("endToEndModernEnglish") or {}).get("transformer")          # transformer metrics.json
                  or (metrics.get("endToEnd") or {}).get("calibrated") or {})               # linear metrics.json
    pick = lambda m: {k: m.get(k) for k in ("precision", "recall", "falsePositiveRate")} if m else None
    return {"phishingVerdict": pick(calibrated.get("phishingVerdict")), "anyWarning": pick(calibrated.get("anyWarning"))}


def publish():
    linear_info = json.loads((MODELS / "model-info.json").read_text(encoding="utf-8"))
    has_transformer = (TRANSFORMER_DIR / "model.onnx").exists()
    # With a transformer, it is the model that decides - the release is named after it; the linear model explains.
    info_dir = TRANSFORMER_DIR if has_transformer else MODELS
    info = json.loads((info_dir / "model-info.json").read_text(encoding="utf-8"))
    version = info["version"]
    release = f"model-{version}"
    assets = [MODELS / LINEAR]
    with tempfile.TemporaryDirectory() as tmp:
        if has_transformer:
            bundle = Path(tmp) / TRANSFORMER_ZIP
            with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
                for f in sorted(TRANSFORMER_DIR.rglob("*")):
                    if f.is_file() and not f.name.startswith(".from-"):
                        z.write(f, f.relative_to(TRANSFORMER_DIR).as_posix())
            assets.append(bundle)

        metrics_path = info_dir / "metrics.json"
        metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True).stdout.strip()
        notes = [f"Model {version}, trained {info.get('trainedAtUtc', '?')} (published from commit {commit[:12]}).", "",
                 info.get("description", ""), "",
                 f"Explanations (strongest cue words) from the linear model {linear_info['version']}." if has_transformer else "",
                 "Files are verified against models/manifest.json by scripts/models.py fetch."]
        existing = subprocess.run(["gh", "release", "view", release], cwd=ROOT, capture_output=True).returncode == 0
        if existing:
            gh("release", "upload", release, *map(str, assets), "--clobber")
        else:
            gh("release", "create", release, *map(str, assets), "--title", f"Model {version}", "--notes", "\n".join(notes))

        manifest = {
            "release": release,
            "version": version,
            "trainedAtUtc": info.get("trainedAtUtc"),
            "explainerVersion": linear_info["version"] if has_transformer else None,
            "languages": info.get("languages"),
            "previewLanguages": info.get("previewLanguages"),
            "publishedAtUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "publishedFromCommit": commit,
            "assets": [{"name": a.name, "size": a.stat().st_size, "sha256": sha256(a)} for a in assets],
            "headlineMetrics": headline(metrics),
        }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if TRANSFORMER_DIR.exists() and (TRANSFORMER_DIR / "model.onnx").exists():
        transformer_marker(manifest).touch()
    print(f"published {release}; commit models/manifest.json")


if __name__ == "__main__":
    commands = {"fetch": fetch, "verify": verify, "publish": publish}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(__doc__)
    commands[sys.argv[1]]()
