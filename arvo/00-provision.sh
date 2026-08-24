#!/usr/bin/env bash
# One-time setup for a fresh Ubuntu 22.04/24.04 x86_64 box.
# ARVO reproducer images are x86-only, which is why this cannot run on the arm64 Mac.
set -euo pipefail

echo "== sanity: architecture must be x86_64 =="
arch=$(uname -m)
[ "$arch" = "x86_64" ] || { echo "FATAL: arch is $arch, ARVO images need x86_64"; exit 1; }
echo "  ok: $arch"

echo "== docker =="
if ! command -v docker >/dev/null; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io
  sudo usermod -aG docker "$USER" || true
  echo "  docker installed (log out/in for group membership, or use sudo)"
else
  echo "  docker present: $(docker --version)"
fi

echo "== supporting tools =="
sudo apt-get install -y -qq python3 python3-pip git jq curl unzip file gdb >/dev/null
echo "  ok"

echo "== disk =="
avail=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
echo "  ${avail}G available on /"
[ "$avail" -ge 120 ] || echo "  WARNING: ARVO images are large; 150-200G recommended"

echo
echo "provisioned. next: ./01-fetch-arvo.sh"
