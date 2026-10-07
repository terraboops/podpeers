# Records docs/demo.gif against the throwaway local k3d cluster (make e2e-cluster)
# with the examples/shop Helm release installed in pp-helm. Run: vhs docs/demo.tape
Output docs/demo.gif
Require podpeers
Set Shell bash
Set FontSize 15
Set Width 1300
Set Height 760
Set Padding 18
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0
Set Theme "Catppuccin Mocha"

Hide
Type "source docs/demo-env.sh && clear" Enter
Sleep 1s
Show

Type "# podpeers will not touch a cluster that isn't local" Enter
Type "podpeers capture --kubeconfig prod.kubeconfig -n shop -l app=web" Enter
Sleep 3s

Type "# local cluster: observe a Helm release while its helm test runs" Enter
Type "netpol-check.sh baseline --release shop -n pp-helm --context k3d-podpeers-e2e --duration 25s --out run" Enter
Set PlaybackSpeed 6.0
Wait+Screen@90s /baseline OK/
Set PlaybackSpeed 1.0
Sleep 2s
Type "clear; podpeers render -format text run/baseline.json | cut -c1-110" Enter
Sleep 5s

Type "clear; grep -A9 'WHY each rule' run/policy.yaml | tail -10" Enter
Sleep 6s

Type "clear; # apply the suggested policy, re-run helm test under a new capture, diff" Enter
Type "netpol-check.sh verify --release shop -n pp-helm --context k3d-podpeers-e2e --duration 25s --out run/good --policy run/policy.yaml --baseline run/baseline.json" Enter
Set PlaybackSpeed 6.0
Wait+Screen@120s /VERDICT/
Set PlaybackSpeed 1.0
Sleep 4s

Hide
Type "python3 -c \"import yaml; d=[x for x in yaml.safe_load_all(open('run/policy.yaml')) if x]; [x['spec'].__setitem__('egress', x['spec']['egress'][1:]) for x in d if x['metadata']['name']=='podpeers-shop-web']; yaml.safe_dump_all(d, open('run/broken.yaml','w'))\"" Enter
Sleep 1s
Show
Type "clear; # now a policy that silently drops web -> api (helm test still passes)" Enter
Type "netpol-check.sh verify --release shop -n pp-helm --context k3d-podpeers-e2e --duration 25s --out run/bad --policy run/broken.yaml --baseline run/baseline.json --rollback-on-fail" Enter
Set PlaybackSpeed 6.0
Wait+Screen@150s /VERDICT/
Set PlaybackSpeed 1.0
Sleep 7s
