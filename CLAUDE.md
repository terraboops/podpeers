# podpeers: agent contract

Read this before changing anything in this repo.

## Hard rules

1. **Never run podpeers, its tests, or kubectl/helm against any context other
   than a local cluster you created.** The machine this is developed on may
   have a production cluster as its default context. Always pass
   `--kubeconfig .e2e/kubeconfig --context k3d-podpeers-e2e` (or use
   `make e2e`, which does). If a task seems to need a non-local cluster,
   stop and ask.
2. **Never weaken the guard** (`internal/guard`, `connect()` in
   `cmd/podpeers`) without a test proving the default is still refusal. The
   default must stay "refuse"; the only opt-in is `--allow-context=<exact
   name>`.
3. **The MCP server stays read-only.** Do not add a tool that runs a capture
   or touches a cluster.
4. **No `Claude-Session:` (or other session-link) trailers in commit messages**
   in this public repo. Existing history is left as is; that call is the
   operator's.
5. **Public repo hygiene:** no cluster names, hostnames, contexts, IPs (other
   than RFC 5737/3849 documentation ranges and loopback), credentials,
   tokens, or kubeconfig contents anywhere: code, fixtures, docs, or commit
   messages. `./hack/hygiene.sh` enforces part of this in CI. Fixture names
   are invented.

## Layout

- `cmd/podpeers`: CLI (`capture`, `check-context`, `render`, `query`,
  `serve`, `suggest`, `diff`, `mcp`)
- `internal/guard`: context safety gates (pre-flight and node check)
- `internal/procnet`: `/proc/net` parser and the sampler script
- `internal/capture`: ephemeral-container orchestration (client-go)
- `internal/graph`: the capture model (`podpeers/v1` JSON) and edge analysis
- `internal/policy`: NetworkPolicy suggestions, reasoning, gaps, refusals
- `internal/diff`: before/after comparison (blocked / lost / new)
- `internal/gql`, `internal/render`, `internal/mcp`: query, views, MCP
- `skills/podpeers-netpol`: the Claude Code skill (first-class deliverable)
- `examples/shop`: Helm chart used by the skill e2e and the skill's docs
- `test/e2e`: real-cluster suite (`//go:build e2e`)

## Working loop

```bash
make vet test           # always
make docs               # after touching any Markdown diagram (renders them like GitHub does)
make e2e                # for anything touching capture, policy, diff, the skill or its script
make mutants-e2e        # after changing a protection or its test: each mutant must still be killed
```

Trunk-based: commit to `main`; branch only to carry a pull request. A change
to behaviour needs a unit test, and an e2e assertion if it depends on real
kernel or CNI behaviour. Several bugs here only showed up on a real cluster:
TIME_WAIT leftovers masking blocked connects, REJECT leaving sockets in
CLOSE, the new-pod policy race. Report what could not be tested, plainly.
