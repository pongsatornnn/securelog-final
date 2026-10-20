#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${FILEBEAT_ACL_BINARY:-$PROJECT_DIR/for_Agent/build/filebeat-acl-8.19.23-amd64}"
GO_VERSION=1.26.8
GO_SHA256=d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b
BEATS_COMMIT=b90e15b68b4d5e79188b519937f55db9fd6524d2
RELEASE_TAG=filebeat-acl-v8.19.23-1
RELEASE_ASSET=filebeat-acl-8.19.23-linux-amd64
RELEASE_SHA256=2f66b0bbfa1cdf6192ec04695f30f55850f8da2386dea44f2f94f596d486987f

if [ -x "$OUTPUT" ]; then
    OUTPUT_SHA256="$(sha256sum "$OUTPUT" | awk '{print $1}')"
    if { [ "$OUTPUT_SHA256" = "$RELEASE_SHA256" ] ||
         { [ -f "$OUTPUT.sha256" ] && [ "$(cat "$OUTPUT.sha256")" = "$OUTPUT_SHA256" ]; }; } &&
       "$OUTPUT" version 2>/dev/null | grep -q 'filebeat version 8.19.23 '; then
        echo "Filebeat ACL binary is ready: $OUTPUT"
        exit 0
    fi
fi

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
    echo "Filebeat ACL build currently supports Linux x86_64 only" >&2
    exit 1
}
for command_name in curl git python3 sha256sum tar; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing build tool: $command_name" >&2
        exit 1
    }
done

BUILD_DIR="$(mktemp -d "${FILEBEAT_BUILD_TMPDIR:-${TMPDIR:-/tmp}}/securelog-filebeat.XXXXXXXX")"
cleanup() {
    chmod -R u+w "$BUILD_DIR" 2>/dev/null || true
    rm -rf "$BUILD_DIR" || true
}
trap cleanup EXIT

if [ "${FILEBEAT_BUILD_FROM_SOURCE:-0}" != 1 ]; then
    echo "Downloading prebuilt Filebeat ACL binary from GitHub Release"
    export FILEBEAT_RELEASE_REPO="${FILEBEAT_RELEASE_REPO:-pongsatornnn/security-Project}"
    if python3 "$PROJECT_DIR/for_Agent/download_filebeat_acl.py" \
        "$RELEASE_TAG" "$RELEASE_ASSET" "$RELEASE_SHA256" "$BUILD_DIR/filebeat-acl" "$PROJECT_DIR"; then
        chmod 755 "$BUILD_DIR/filebeat-acl"
        "$BUILD_DIR/filebeat-acl" version | grep -q 'filebeat version 8.19.23 ' || {
            echo "Downloaded Filebeat has the wrong version" >&2
            exit 1
        }
        mkdir -p "$(dirname "$OUTPUT")"
        install -m 755 "$BUILD_DIR/filebeat-acl" "$OUTPUT"
        rm -f "$OUTPUT.sha256"
        echo "Filebeat ACL binary is ready: $OUTPUT"
        exit 0
    fi
    echo "Release download unavailable; building the pinned Filebeat source instead" >&2
fi

if command -v go >/dev/null 2>&1 && [ "$(go version | awk '{print $3}')" = "go$GO_VERSION" ]; then
    GO="$(command -v go)"
else
    GO_TARBALL="$BUILD_DIR/go$GO_VERSION.linux-amd64.tar.gz"
    echo "Downloading Go $GO_VERSION"
    curl -fL --retry 3 --connect-timeout 15 \
        "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" -o "$GO_TARBALL"
    echo "$GO_SHA256  $GO_TARBALL" | sha256sum -c -
    mkdir -p "$BUILD_DIR/toolchain"
    tar -C "$BUILD_DIR/toolchain" -xzf "$GO_TARBALL"
    rm -f "$GO_TARBALL"
    GO="$BUILD_DIR/toolchain/go/bin/go"
fi

echo "Downloading Elastic Beats v8.19.23 source"
git clone --quiet --depth 1 --single-branch --branch v8.19.23 \
    https://github.com/elastic/beats.git "$BUILD_DIR/beats"
[ "$(git -C "$BUILD_DIR/beats" rev-parse HEAD)" = "$BEATS_COMMIT" ] || {
    echo "Elastic Beats v8.19.23 tag does not point to the expected commit" >&2
    exit 1
}
python3 "$PROJECT_DIR/for_Agent/build_filebeat_acl.py" "$BUILD_DIR/beats"

echo "Building Filebeat (this may take several minutes)"
(
    cd "$BUILD_DIR/beats"
    GOCACHE="$BUILD_DIR/go-cache" GOPATH="$BUILD_DIR/go-path" GOFLAGS=-modcacherw \
        GOMAXPROCS=1 "$GO" build -p 1 -o "$BUILD_DIR/filebeat-acl" ./filebeat
)
"$BUILD_DIR/filebeat-acl" version | grep -q 'filebeat version 8.19.23 ' || {
    echo "Built Filebeat has the wrong version" >&2
    exit 1
}

mkdir -p "$(dirname "$OUTPUT")"
install -m 755 "$BUILD_DIR/filebeat-acl" "$OUTPUT"
sha256sum "$OUTPUT" | awk '{print $1}' > "$OUTPUT.sha256"
echo "Filebeat ACL binary is ready: $OUTPUT"
