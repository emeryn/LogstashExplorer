#!/usr/bin/env sh
# Emits Kubernetes Secret manifests with freshly generated random values (stdout).
#   ./deploy/k8s/gen-secrets.sh | kubectl apply -f -
# Re-running rotates nothing already applied unless you apply again — keep the output out of git.
# Production: replace with External Secrets / Vault Agent and delete this script's output.
set -eu
NS=logstash-explorer
b64url() { openssl rand "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
pw() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "$1"; }

cat <<EOF
apiVersion: v1
kind: Secret
metadata: { name: lsx-db, namespace: $NS }
type: Opaque
stringData:
  db_password: "$(pw 32)"
---
apiVersion: v1
kind: Secret
metadata: { name: lsx-app, namespace: $NS }
type: Opaque
stringData:
  master_key: "$(b64url 32)"
  kem_x25519_sk: "$(b64url 32)"
  kem_mlkem768_seed: "$(b64url 64)"
  admin_initial_password: "$(pw 16)Aa1-"
---
apiVersion: v1
kind: Secret
metadata: { name: lsx-runner, namespace: $NS }
type: Opaque
stringData:
  runner_token: "$(b64url 48)"
EOF
