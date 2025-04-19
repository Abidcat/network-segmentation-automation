#!/bin/bash
# Run Zeek via Docker on a given interface (default: lo)
IFACE=${1:-lo}
POLICY_DIR="$(realpath ~/network-automation/zeek-config)"

echo "Starting Zeek in Docker on $IFACE..."
docker run --rm \
  --net=host \
  -v "$POLICY_DIR":/policy \
  -w /policy \
  zeek/zeek:latest \
  zeek -i "$IFACE" network-segmentation.zeek
