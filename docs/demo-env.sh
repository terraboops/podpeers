# Sourced (hidden) by docs/demo.tape. Uses only the throwaway e2e cluster.
ROOT="$(pwd)"
export PATH="$ROOT/bin:$ROOT/skills/podpeers-netpol/scripts:$PATH"
export KUBECONFIG="$ROOT/.e2e/kubeconfig"
export PS1='\[\e[1;35m\]$\[\e[0m\] '
mkdir -p "$ROOT/.e2e/demo" && cd "$ROOT/.e2e/demo" && rm -rf run
# A kubeconfig for an invented, unreachable "production" cluster.
cat > prod.kubeconfig <<'KC'
apiVersion: v1
kind: Config
clusters: [{name: prod, cluster: {server: "https://cluster.example.invalid:6443"}}]
users: [{name: me, user: {token: not-a-real-token}}]
contexts: [{name: prod-eu, context: {cluster: prod, user: me}}]
current-context: prod-eu
KC
# The deliberately broken policy for the last scene: drop web's egress to api.
make_broken() {
  python3 - <<'PY'
import yaml
docs = [d for d in yaml.safe_load_all(open('run/policy.yaml')) if d]
for d in docs:
    if d['metadata']['name'] == 'podpeers-shop-web':
        d['spec']['egress'] = d['spec']['egress'][1:]
yaml.safe_dump_all(docs, open('run/broken.yaml', 'w'))
PY
}
