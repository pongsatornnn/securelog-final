#!/usr/bin/env python3
"""Download the pinned Filebeat binary from this repository's GitHub Release."""

import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def release_repo(project_dir: str) -> str:
    configured = os.environ.get("FILEBEAT_RELEASE_REPO", "").strip()
    if configured:
        repo = configured
    else:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={project_dir}", "-C", project_dir,
             "remote", "get-url", "origin"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        repo = result.stdout.strip()
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:)?([\w.-]+/[\w.-]+?)(?:\.git)?/?", repo)
    if not match:
        raise ValueError("GitHub origin not found; set FILEBEAT_RELEASE_REPO=owner/repo")
    return match.group(1)


def github_token() -> str:
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    identities = [(None, None, os.environ.copy())]
    sudo_user = os.environ.get("SUDO_USER", "")
    if os.geteuid() == 0 and sudo_user and sudo_user != "root":
        try:
            account = pwd.getpwnam(sudo_user)
        except KeyError:
            pass
        else:
            identities.append((account.pw_uid, account.pw_gid,
                               {**os.environ, "HOME": account.pw_dir}))
    for uid, gid, environment in identities:
        try:
            result = subprocess.run(
                ["git", "credential", "fill"],
                input="protocol=https\nhost=github.com\n\n", text=True,
                capture_output=True, check=False, timeout=10,
                env={**environment, "GIT_TERMINAL_PROMPT": "0"},
                user=uid, group=gid,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("password="):
                    return line.partition("=")[2]
    return ""


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected and urllib.parse.urlparse(newurl).hostname != urllib.parse.urlparse(request.full_url).hostname:
            redirected.remove_header("Authorization")
        return redirected


def download(tag: str, asset_name: str, expected_sha: str, output: Path, project_dir: str) -> None:
    repo = release_repo(project_dir)
    token = github_token()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "SecureLog-setup"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(SafeRedirect())
    release_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    with opener.open(urllib.request.Request(release_url, headers=headers), timeout=30) as response:
        release = json.load(response)
    asset = next((item for item in release["assets"] if item["name"] == asset_name), None)
    if not asset:
        raise ValueError(f"Release asset {asset_name} not found in {repo}/{tag}")
    request = urllib.request.Request(
        asset["url"], headers={**headers, "Accept": "application/octet-stream"}
    )
    digest = hashlib.sha256()
    with opener.open(request, timeout=60) as response, output.open("wb") as target:
        while chunk := response.read(1024 * 1024):
            target.write(chunk)
            digest.update(chunk)
    if digest.hexdigest() != expected_sha:
        output.unlink(missing_ok=True)
        raise ValueError("Release asset SHA-256 mismatch")
    print(f"Verified Filebeat ACL release asset from {repo}: {digest.hexdigest()}")


if __name__ == "__main__":
    try:
        download(sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]), sys.argv[5])
    except (OSError, ValueError, KeyError, urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"Release download unavailable: {error}", file=sys.stderr)
        sys.exit(1)
