#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Integration smoke test for the `iou` CLI: craft a capture of an attack
# sequence and assert the replay denies the shadow read and fails closed on the
# unknown opcode.  Exercised by `make test`.
set -eu
here=$(dirname "$0")
bin="$here/../build/iou"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 64-byte SQEs matching include/iou_sqe.h (packed layout).
# OPENAT(/etc/shadow ptr 0xdeadbeef, dfd=-100)
printf '\x12\x00\x00\x00\x9c\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$tmp/cap.sqe"
# READ(fd=3, len=512)
printf '\x16\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> "$tmp/cap.sqe"
# UNKNOWN opcode 200
printf '\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> "$tmp/cap.sqe"

printf '0xdeadbeef\t/etc/shadow\n' > "$tmp/paths.txt"
printf 'deny action=file_read,file_create path=/etc/shadow\n' > "$tmp/rules.txt"

out=$("$bin" check "$tmp/rules.txt" "$tmp/cap.sqe" --paths "$tmp/paths.txt")

echo "$out" | grep -q '"opcode":18.*"verdict":"deny"' && \
  echo "openat shadow -> deny OK" || { echo "FAIL: openat shadow not denied"; exit 1; }
echo "$out" | grep -q '"opcode":200.*"verdict":"alert"' && \
  echo "unknown opcode -> alert OK" || { echo "FAIL: unknown opcode not alerted"; exit 1; }
echo "$out" | grep -q '"opcode":22.*"verdict":"allow"' && \
  echo "plain read -> allow OK" || { echo "FAIL: plain read not allowed"; exit 1; }
echo "test_cli: all checks passed"
