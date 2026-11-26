"""Download the spine tools' RELEASED binaries and check them against each release's SHA256SUMS.

Nothing is built. Usage:
    python3 -m e2e.fetch --out DIR                       # latest release of every tool
    python3 -m e2e.fetch --out DIR --pinned FILE         # the tags and checksums in FILE
    python3 -m e2e.fetch --out DIR --write-pin FILE      # latest, and record them in FILE

DIR must not exist. It receives bin/, the downloaded archives and tools.json (what was used).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

OWNER = "cmdrvl"
USER_AGENT = "cmdrvl-e2e"
# binary name -> repository
TOOLS = {
    "vacuum": "vacuum", "hashbytes": "hash", "lock": "lock", "fingerprint": "fingerprint",
    "profile": "profile", "shape": "shape", "rvl": "rvl", "verify": "verify", "assess": "assess",
    "pack": "pack", "benchmark": "benchmark", "veil": "veil", "airlock": "airlock", "twinning": "twinning",
}
# How releases spell this platform in asset names, most preferred first.
PLATFORMS = {
    ("Darwin", "x86_64"): ("x86_64-apple-darwin", "darwin-x86_64"),
    ("Darwin", "arm64"): ("aarch64-apple-darwin", "darwin-arm64"),
    ("Linux", "x86_64"): ("x86_64-unknown-linux-gnu", "linux-x86_64", "x86_64-unknown-linux-musl"),
}


class FetchError(Exception):
    pass


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def latest_tag(repo: str) -> str:
    """Follow github.com's releases/latest redirect (no API call, no token)."""
    request = urllib.request.Request(
        f"https://github.com/{OWNER}/{repo}/releases/latest", headers={"User-Agent": USER_AGENT}, method="HEAD"
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        final = response.geturl()
    if "/releases/tag/" not in final:
        raise FetchError(f"{repo}: no latest release (redirected to {final})")
    return final.rsplit("/", 1)[1]


def checksums(repo: str, tag: str) -> dict[str, str]:
    """asset name -> sha256, from the release's SHA256SUMS file."""
    for name in ("SHA256SUMS", f"{repo}-{tag}-SHA256SUMS"):
        try:
            text = download(f"https://github.com/{OWNER}/{repo}/releases/download/{tag}/{name}").decode("utf-8")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            raise
        found = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2:
                found[parts[1].lstrip("*").rsplit("/", 1)[-1]] = parts[0].lower()
        return found
    raise FetchError(f"{repo} {tag}: no SHA256SUMS asset")


def pick_asset(repo: str, names: list[str]) -> str:
    key = (platform.system(), platform.machine())
    if key not in PLATFORMS:
        raise FetchError(f"no release assets are mapped for platform {key}")
    for spelling in PLATFORMS[key]:
        matches = [n for n in names if spelling in n and n.endswith(".tar.gz")]
        if len(matches) == 1:
            return matches[0]
        if matches:
            raise FetchError(f"{repo}: several assets match {spelling}: {matches}")
    raise FetchError(f"{repo}: no .tar.gz asset for {key} among {sorted(names)}")


def extract_binary(archive: Path, binary: str, destination: Path) -> None:
    """Copy exactly the named executable out of the archive; nothing else is unpacked."""
    with tarfile.open(archive, "r:gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1] == binary]
        if len(members) != 1:
            raise FetchError(f"{archive.name}: expected one file named {binary}, found {len(members)}")
        data = tar.extractfile(members[0]).read()
    destination.write_bytes(data)
    destination.chmod(0o755)


def fetch_one(binary: str, repo: str, out: Path, pinned: dict | None) -> dict:
    tag = pinned["tag"] if pinned else latest_tag(repo)
    sums = checksums(repo, tag)
    asset = pick_asset(repo, list(sums))
    expected = sums[asset]
    if pinned:
        recorded = pinned.get("sha256", {}).get(asset)
        if not recorded:
            raise FetchError(f"{repo} {tag} {asset}: the pin file records no checksum for this asset")
        if recorded != expected:
            raise FetchError(f"{repo} {tag} {asset}: SHA256SUMS changed since it was pinned")
    data = download(f"https://github.com/{OWNER}/{repo}/releases/download/{tag}/{asset}")
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise FetchError(f"{repo} {tag} {asset}: sha256 {actual} does not match SHA256SUMS {expected}")
    archive = out / "archives" / asset
    archive.write_bytes(data)
    path = out / "bin" / binary
    extract_binary(archive, binary, path)
    version = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=60)
    if version.returncode != 0:
        raise FetchError(f"{binary} {tag}: --version exited {version.returncode}: {version.stderr.strip()}")
    return {"repo": f"{OWNER}/{repo}", "tag": tag, "asset": asset, "sha256": expected,
            "version_output": version.stdout.strip()}


def fetch(out: Path, pinned_file: Path | None = None) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    (out / "bin").mkdir()
    (out / "archives").mkdir()
    pinned = json.loads(pinned_file.read_text()) if pinned_file else None
    used = {}
    for binary, repo in TOOLS.items():
        entry = pinned["tools"][binary] if pinned else None
        used[binary] = fetch_one(binary, repo, out, entry)
        print(f"{binary:12} {used[binary]['tag']:10} {used[binary]['version_output']}", flush=True)
    record = {"platform": f"{platform.system()}-{platform.machine()}",
              "versions": "pinned" if pinned else "latest", "tools": used}
    (out / "tools.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def pin_from(record: dict) -> dict:
    """A pin file for the releases in a tools.json, with each platform's published checksum."""
    spellings = [spelling for options in PLATFORMS.values() for spelling in options]
    pinned = {}
    for binary, entry in record["tools"].items():
        sums = checksums(TOOLS[binary], entry["tag"])
        pinned[binary] = {"tag": entry["tag"], "sha256": {
            name: digest for name, digest in sorted(sums.items())
            if name.endswith(".tar.gz") and any(spelling in name for spelling in spellings)}}
    return {"tools": pinned}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pinned", type=Path)
    parser.add_argument("--write-pin", type=Path, help="also write a pin file for the releases fetched")
    args = parser.parse_args()
    try:
        record = fetch(args.out, args.pinned)
        if args.write_pin:
            args.write_pin.write_text(json.dumps(pin_from(record), indent=2, sort_keys=True) + "\n")
    except (FetchError, urllib.error.URLError, OSError) as error:
        print(f"fetch failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    os.environ.setdefault("NO_COLOR", "1")
    raise SystemExit(main())
