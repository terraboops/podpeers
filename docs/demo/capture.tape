# Scene 1: capture traffic directly with podpeers, then start the web UI.
# Run from the repo root (see make-demo.sh).
Output .e2e/demo/capture.mp4
Set Shell bash
Set FontSize 15
Set Width 1280
Set Height 820
Set Padding 20
Set TypingSpeed 14ms
Set Theme "Catppuccin Mocha"

Hide
Type "export PATH=$PWD/bin:$PATH KUBECONFIG=$PWD/.e2e/kubeconfig PS1='\[\e[1;35m\]$\[\e[0m\] '; cd .e2e/demo && clear" Enter
Sleep 500ms
Show

Type "podpeers capture -A -l app.kubernetes.io/part-of=shop --duration 10s -o peers.json" Enter
Sleep 2.5s
Hide
Sleep 14s
Show
Sleep 2.5s
Type "podpeers serve peers.json" Enter
Sleep 2s
