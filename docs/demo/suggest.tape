# Scene 3: turn the observation into NetworkPolicy and apply it.
Output .e2e/demo/suggest.mp4
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

Type "podpeers suggest -workload Deployment/cart peers.json | head -40" Enter
Sleep 5s
Hide
Type "clear" Enter
Sleep 300ms
Show
Type "podpeers suggest -o policies.yaml peers.json && kubectl apply -f policies.yaml" Enter
Sleep 3s
