#!/bin/sh
# Auto-ceremony for the single-host demo (see demo.yml). Everything here is
# what the distributed flow does by hand across machines — it can be
# automatic ONLY because all parties share this one host anyway, so nothing
# security-relevant is skipped that single-host hadn't already forfeited.
set -eu
CERTS=/opt/sovra/certs
CONFIG=/opt/sovra/config

# Idempotent across `up` re-runs: the ceremony happened once, keep it.
[ -f "$CERTS/.demo-ceremony-done" ] && exit 0

# 1. PKI: one CA, one leaf per process. SANs are the compose service names
#    (this network's addressing); every leaf gets all of them — over-broad
#    SANs are harmless inside a single-CA closed system.
sovra-cli certs ca --dir "$CERTS"
for n in orchestrator cosigner0 cosigner1 cosigner2; do
  sovra-cli certs csr --dir "$CERTS" --stem "$n" --cn "sovra-$n" \
    --san api --san cosigner0 --san cosigner1 --san cosigner2
  sovra-cli certs sign "$CERTS/$n.csr.pem" --dir "$CERTS"
done

# 2. Identities: born BEFORE the cosigners start, so the roster is complete
#    at first boot and the two-phase bootstrap collapses to one phase.
P0=$(sovra-cli identity --data-dir /data0)
P1=$(sovra-cli identity --data-dir /data1)
P2=$(sovra-cli identity --data-dir /data2)
printf '%s,%s,%s' "$P0" "$P1" "$P2" > "$CERTS/participants"

# 3. Demo signing policy: Sepolia only, any recipient, 1 ETH cap, no calldata.
cat > "$CONFIG/policy-demo.toml" <<'POLICY'
allowed_chain_ids = [11155111]
allowed_recipients = ["*"]
max_value_wei = "1000000000000000000"
allow_calldata = false
POLICY

touch "$CERTS/.demo-ceremony-done"
# Init runs as root (volume mount points); everything belongs to `sovra`.
chown -R 999:999 "$CERTS" "$CONFIG" /data0 /data1 /data2
echo "demo ceremony complete: certs, identities, roster, policy"
