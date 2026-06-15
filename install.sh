#!/bin/bash
# Install CAI with TFM modifications into an existing cai_env.
#
# Usage:
#   # Option 1: Overwrite files in existing cai_env (fast, no reinstall)
#   ./install.sh /path/to/cai_env
#
#   # Option 2: Full pip install (creates entry points, resolves deps)
#   ./install.sh --pip /path/to/cai_env

set -e

MODE="rsync"
if [ "$1" = "--pip" ]; then
    MODE="pip"
    shift
fi

CAI_ENV="${1:-}"

if [ -z "$CAI_ENV" ]; then
    echo "Usage: ./install.sh [--pip] /path/to/cai_env"
    echo ""
    echo "  Default:  rsync src/cai/ over the installed package (fast)"
    echo "  --pip:    pip install -e . into the venv (full reinstall)"
    exit 1
fi

if [ ! -d "$CAI_ENV" ]; then
    echo "Error: $CAI_ENV does not exist"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$MODE" = "pip" ]; then
    echo "Installing via pip into $CAI_ENV ..."
    source "$CAI_ENV/bin/activate"
    pip install -e "$SCRIPT_DIR"
    echo "Done. CAI installed in editable mode."
else
    SITE_PACKAGES="$CAI_ENV/lib/python3.*/site-packages/cai"
    TARGET=$(echo $SITE_PACKAGES)

    if [ ! -d "$TARGET" ]; then
        echo "Error: CAI not found in $CAI_ENV"
        echo "Make sure CAI is already installed (pip install cai-framework)"
        exit 1
    fi

    echo "Syncing src/cai/ -> $TARGET ..."
    rsync -av --exclude='__pycache__' --exclude='*.pyc' \
        "$SCRIPT_DIR/src/cai/" "$TARGET/"
    echo "Done. Changes applied to $TARGET"
fi
