#!/bin/bash

# Script pour forcer le pull depuis un repo distant
# Usage : ./pull.sh [branche] [remote]
# Par défaut : branche=master, remote=origin

BRANCH=${1:-master}
REMOTE=${2:-origin}

echo "[+] Fetching from $REMOTE..."
git fetch --all

echo "[+] Resetting local branch to $REMOTE/$BRANCH..."
git reset --hard $REMOTE/$BRANCH

echo "[✓] Repo local synchronisé avec $REMOTE/$BRANCH"
