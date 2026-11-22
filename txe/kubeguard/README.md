# kubeguard: kube-run and kubectl-context-guard (TXE-8039)

On 2026-11-21 an agent's `kubectl get ... -A`, with no `--context` and no `--kubeconfig`, read the
production cluster, because that workstation's default kubeconfig context was production. Naming a context
does not fix that: a context is a local alias, the same name can mean another cluster in another file, and
a context can be repointed inside its file. This directory holds the source of the class fix:

- **`kube_run.py`, kube-run**: the one identity-bound path for an agent's cluster API call.
  `kube-run [--authorization FILE] [--timeout SECONDS] <cluster-id> -- <kubectl arguments>`. It checks, in
  order:
  - a registered cluster id (fixed registry path);
  - no target, identity or TLS override (KR04);
  - an authorization policy (KR06 to KR09);
  - server and CA sha256 pins before any contact (KR10 to KR14), and an `https://` server only, in the
    registry entry and in the kubeconfig (KR27). A cluster's `insecure-skip-tls-verify` must be absent or an
    unquoted `false`/`False`/`FALSE`; every other value is KR14. That is conservative: kubectl reads YAML 1.1
    booleans (`y`, `on`, ...), and kube-run refuses even the other false spellings (`n`, `no`, `off`, `"false"`);
  - static credentials only (KR23);
  - a TLS-verified kube-system Namespace UID probe (KR15, KR16);
  - a kubeconfig re-hash (KR17).
  Only then does it make the request, under B5 host custody. Diagnostics are stable codes with values
  withheld. The full contract is in its docstring.
  **kube-run is read-only.** It runs only these verbs:
  - `get` on the closed built-in resource types (forwarded in canonical form; no short names, categories or CRDs), `logs` (on a pod only) and `events`;
  - `rollout status`;
  - `auth can-i` and `auth whoami`;
  - the discovery verbs `api-resources`, `api-versions`, `explain` and `version` (with no operand).

  **Functional reduction, read verbs with implicit reads.** `describe`, `top`, `cluster-info`, `rollout history`,
  `logs` on a non-pod `TYPE/NAME`, and `get all` are refused (KR05). Their kubectl implementation reads resource
  types the request does not name, so an authorization record could not scope them from the arguments. Use `get`
  with the exact types instead. The audit, at the pinned kubectl v1.34.9 (kubernetes/kubernetes@v1.34.9
  `staging/src/k8s.io/kubectl` and `staging/src/k8s.io/cli-runtime`, which are k8s.io/kubectl and
  k8s.io/cli-runtime v0.34.9):

  | Verb | (1) Discovery and version metadata | (2) Resource reads | (3) Subresource reads | Verdict, and what a grant authorizes |
  |---|---|---|---|---|
  | `get` | RESTMapper and discovery to resolve names; a category name expands through discovery (`cli-runtime/pkg/resource/builder.go:642-654`) | the named types only (`cmd/get/get.go:470`, `:616`) | `--subresource=<s>` | KEEP, for the closed built-in resources only, forwarded in canonical form (below). A grant on the plural `<type>` authorizes reading that type in the namespace. `<type>/<s>` must be granted for a subresource. Short names, categories (`all` included) and custom resources are refused |
  | `logs` | RESTMapper | the pod (a NAME, `pod/NAME`, or pods by `-l`) | `pods/log` | KEEP for pods only. A `logs` grant on `pods` authorizes reading the pods and their `pods/log`. Any other `TYPE/NAME` reads that object and then its pods (`polymorphichelpers/logsforobject.go:169-175`), so it is refused |
  | `events` | RESTMapper for `--for` (`cmd/events/events.go:165-171`) | `events` only, filtered by field selector (`:231-233`, list and watch `:239-248`) | none | KEEP. A grant on `events` authorizes listing events |
  | `rollout status` | RESTMapper | the named object, list and watch (`cmd/rollout/rollout_status.go:187-192`); the status viewers read only that object (`polymorphichelpers/rollout_status.go:59-120`) | none | KEEP. A grant on the object's type authorizes it |
  | `auth can-i` | RESTMapper and discovery for the resource argument | none: it CREATES a SelfSubjectAccessReview (`cmd/auth/cani.go:269-272`). `--list`, which would create a SelfSubjectRulesReview (`:148`, `:254-259`), is not forwarded | none | KEEP. A grant authorizes `selfsubjectaccessreviews` |
  | `auth whoami` | none | none: it CREATES a SelfSubjectReview (`cmd/auth/whoami.go:177-178`) | none | KEEP. A grant authorizes `selfsubjectreviews` |
  | `api-resources`, `api-versions`, `explain`, `version` | discovery groups and resources (`cmd/apiresources/apiversions.go:86`), OpenAPI (`cmd/explain/explain.go`), `/version` | none | none | KEEP. Metadata only (`<discovery>`) |
  | `describe` | RESTMapper | the named object, AND related objects: the node describer lists the node's pods (`describe/describe.go:3725-3772`), and describers read events and controllers | varies | REMOVE (KR05). The implicit set differs per describer and is not modelled |
  | `top` | RESTMapper | nodes or pods, AND metrics API objects (`cmd/top/top_node.go:180-220`; `top_pod.go:233-262`) | none | REMOVE (KR05) |
  | `cluster-info` | `/version`, the API host | Services in kube-system by label (`cmd/clusterinfo/clusterinfo.go:98-100`) | none | REMOVE (KR05) |
  | `rollout history` | RESTMapper | the object, AND ReplicaSets (`polymorphichelpers/history.go:313-319`) or ControllerRevisions (`:338`, `:359`) | none | REMOVE (KR05) |

  Every verb also reads cached discovery metadata. That is metadata, not a resource grant.

  **What kube-run does and does not establish here:**
  - **Resource versus category: closed, canonical operands** (`RESOURCE_SPELLINGS`). The trace at the pinned
    sources (cli-runtime and client-go v0.34.9):
    - the builder replaces EVERY comma piece of the first argument that equals ANY discovered category name
      with that category's members, before REST mapping and with no precedence for real resource names
      (`resource/builder.go:618`, `:642-665`; `restmapper/category_expansion.go:59-88`). So a CRD declaring
      `categories: [pods]` would turn `get pods` into a read of that CRD, and no plain word is safe;
    - a CRD can claim a short name, and the shortcut expander takes the first match
      (`restmapper/shortcut.go:154-180`). An exact resource name or singular is never rewritten (`:132-146`);
    - a CRD's categories and short names must be DNS-1035 labels, so they never contain `.` or `/`
      (apiextensions-apiserver `validation.go:769-781`). An operand with two or more dots is a fully specified
      group/version/resource (`schema.ParseResourceArg`; builder `mappingFor`, `:768-780`).
    So kube-run accepts only the exact plural or singular name, or the canonical form, of the built-in
    resources in `RESOURCE_SPELLINGS`. It authorizes each by its plural name, and FORWARDS it in canonical
    `resource.version.group` form (core: `pods.v1.`; for example `deployments.v1.apps/web`). A dotted operand
    cannot equal a CRD category or short name, and it is mapped exactly. The identity probe names
    `namespaces.v1.` too. After a bare type, later words are names and are forwarded unchanged. `logs` takes
    `pod`/`pods` only (its typed pod operand is resolved by REST mapping; `po` could be claimed).
    - **Residual, a prerequisite:** an aggregated API server (an APIService, installed by a cluster admin) serves
      its own discovery, which CRD validation does not cover. One that advertises a dotted category could still
      collide. That is trusted cluster configuration, not something kube-run checks at runtime.
    - **Current source-contract limitation:** custom resources (CRDs) cannot be read through kube-run, and
      short names are refused. A fully-qualified CRD allowlist would be a separate, reviewed extension.
    - **Scope of the guarantee.** Canonicalization removes category and short-name expansion UNDER THE TRACED
      MODEL above, with the aggregated-API prerequisite. It does NOT make an incorrect table entry harmless: a
      wrong but EXISTING group or version would name a DIFFERENT API resource, while authorization uses the
      plural name. The table is security-critical reviewed data, pinned by a test, and each entry was verified
      against the pinned Kubernetes v1.34.9 API registration:

      | Group / version | Resources (canonical `resource.version.group`) | Registration (kubernetes@v1.34.9) | Enabled by default |
      |---|---|---|---|
      | core `v1` | pods, replicationcontrollers, services, endpoints, nodes, limitranges, persistentvolumes, persistentvolumeclaims | `pkg/registry/core/rest/storage_core.go:232`, `:257`, `:284`, `:290`, `:294`, `:300`, `:304`, `:309` | yes (`pkg/controlplane/instance.go:448`) |
      | core `v1` | events, resourcequotas, namespaces, secrets, serviceaccounts, configmaps | `pkg/registry/core/rest/storage_core_generic.go:125`, `:129`, `:134`, `:140`, `:144`, `:151` | yes (`instance.go:448`) |
      | `apps/v1` | deployments, statefulsets, daemonsets, replicasets, controllerrevisions | `pkg/registry/apps/rest/storage_apps.go:56`, `:67`, `:78`, `:88`, `:99` | yes (`instance.go:449`) |
      | `batch/v1` | jobs, cronjobs | `pkg/registry/batch/rest/storage_batch.go:51`, `:61` | yes (`instance.go:454`) |
      | `networking.k8s.io/v1` | networkpolicies, ingresses, ingressclasses | `pkg/registry/networking/rest/storage_settings.go:61`, `:70`, `:80` | yes (`instance.go:459`) |
      | `policy/v1` | poddisruptionbudgets | `pkg/registry/policy/rest/storage_policy.go:49` | yes (`instance.go:461`) |
      | `storage.k8s.io/v1` | storageclasses | `pkg/registry/storage/rest/storage_storage.go:107` | yes (`instance.go:464`) |
      | `rbac.authorization.k8s.io/v1` | roles, rolebindings, clusterroles, clusterrolebindings | `pkg/registry/rbac/rest/storage_rbac.go:109`, `:114`, `:119`, `:124` | yes (`instance.go:462`) |
      | `coordination.k8s.io/v1` | leases | `pkg/registry/coordination/rest/storage_coordination.go:65` | yes (`instance.go:456`) |
      | `discovery.k8s.io/v1` | endpointslices | `pkg/registry/discovery/rest/storage_discovery.go:51` | yes (`instance.go:457`) |
      | `autoscaling/v2` | horizontalpodautoscalers | `pkg/registry/autoscaling/rest/storage_autoscaling.go:86` (v2; v1 also exists at `:70`) | yes (`instance.go:453`) |
      | `apiextensions.k8s.io/v1` | customresourcedefinitions | `staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/apiserver.go:148` | its own server (the CRD definitions only, not custom resources) |

      Version availability: `events` is the core `v1` resource. `events.k8s.io/v1` also serves events
      (`pkg/registry/events/rest/storage_events.go:54`) and is not reachable through kube-run. HPAs are pinned to
      `autoscaling/v2`. A cluster that disables a version (`--runtime-config`) makes kubectl fail on that exact
      GVR, rather than remapping it.
    - **Scope: namespaced or cluster-wide.** kubectl ignores `-n` for a cluster-scoped type and reads the whole
      cluster's collection, so the record's `namespaces` is checked PER RESOURCE SCOPE:
      - A namespaced resource is covered by the request's namespace (`*` with `--all-namespaces`).
      - A cluster-scoped resource needs the record's explicit global grant, `namespaces: ["*"]`. A named
        namespace never grants it, with or without `-n`.
      - A mixed request (`get pods,nodes -n x`) needs both, so a cluster grant never widens the namespaced part.
      - Unknown or missing scope metadata refuses.

      Each entry's scope is its registry strategy's `NamespaceScoped()` at kubernetes@v1.34.9
      (`pkg/registry/<group>/<resource>/strategy.go`, cited per entry in `kube_run.py`, pinned by a test). The
      cluster-scoped entries are namespaces (`core/namespace/strategy.go:48`), nodes (`core/node/strategy.go:58`),
      persistentvolumes (`core/persistentvolume/strategy.go:49`), ingressclasses
      (`networking/ingressclass/strategy.go:44`), storageclasses (`storage/storageclass/strategy.go:41`),
      clusterroles (`rbac/clusterrole/strategy.go:49`), clusterrolebindings (`rbac/clusterrolebinding/strategy.go:48`)
      and customresourcedefinitions (apiextensions-apiserver `pkg/registry/customresourcedefinition/strategy.go:54`).
      The other 26 are namespaced. The fixed resources are cluster-scoped too:
      - `auth can-i`: selfsubjectaccessreviews (`authorization/selfsubjectaccessreview/rest.go:44`);
      - `auth whoami`: selfsubjectreviews (`authentication/selfsubjectreview/rest.go:49`);
      - the discovery verbs: `<discovery>`, which are non-resource paths.

      Records for those need `namespaces: ["*"]`.
  - **Discovery metadata.** Every verb reads API discovery (`/api`, `/apis`, cached) through the RESTMapper.
    `explain` also reads the OpenAPI document, and `version` reads `/version`. Records do NOT authorize or scope
    this metadata: it is read with the cluster credential and is not limited by kube-run. It reveals the
    cluster's resource types and versions, not objects.
  - **Subresources.**
    - `logs` reads the `pods/log` subresource of the named pods. A `logs` grant on `pods` is taken to authorize
      both the pods read and `pods/log`, with no separate `pods/log` entry. That is a stated semantic of the
      record, not separate enforcement.
    - `events` reads only the `events` resource, by list and watch, with no subresource.
    - `rollout status` lists and watches the named object's resource. It reads the status field, with no
      subresource.
    - `get --subresource=<s>` must be granted as `<type>/<s>`, which is enforced.
  Every mutating, interactive or tunnelling verb is refused before contact: `delete`, `edit`, `patch`, `label`,
  `annotate`, `scale`, `wait`, `apply`, `create`, `replace`, `diff`, `exec`, `cp`, `attach`, `port-forward`,
  `run`, `debug`, `proxy`, `expose`, `autoscale`, `set`, `drain`, `cordon`, `uncordon`, `taint`, `certificate`,
  `rollout restart|undo|pause|resume`, and any plugin or unknown verb.
  A read is still authorized by cluster, resources and namespace, because a read can widen too:
  - every resource operand counts (`get pods/a secrets/b` is pods and secrets), including those after `--`;
  - every true spelling of `--all-namespaces` and `-A` means all namespaces;
  - `--subresource=<s>` is authorized as `<resource>/<s>`;
  - `auth` and `rollout` are authorized with their subcommand (`auth can-i`, `rollout status`);
  - an attached or clustered `-s` (`-sURL`, `-its`) is a server override, refused like `--server`;
  - options follow a per-verb arity table (`VERB_OPTIONS` in `kube_run.py`): for each read verb, the options
    that take a value and the options that take none. In `logs`, `-f` (follow) and `-p` (previous) take no
    value. Only the options in that table, plus a few global ones, are forwarded. Any other option (`--raw`
    included), and any attached or clustered short option (`-wA`, `-ojson`), is refused: write each option and
    its value separately;
  - a value is never another option, so `-o --namespace x` and `-l -A` are refused. A value that looks like an
    option (`--tail=-1`, `--tail -1`) is refused rather than reinterpreted. `--opt=value` is read explicitly,
    and after `--` every token is an operand. **kube-run forwards nothing it did not inspect:** only `get`,
    `rollout` and `logs` (`TERMINATOR_OPERANDS`) take operands after `--`, each checked by its own operand rule.
    For every other verb, or before a verb, any token after `--` is refused (KR05). After a bare type, later
    words are names: kubectl expands aliases and categories only in the first argument (cli-runtime
    `resource/builder.go`, `ResourceTypeOrNameArgs`);
  - `-f`/`--filename`/`-k`/`--kustomize` (file or kustomization reads) are refused on every verb.
  The registry entry must pin kubectl by absolute path. kube-run never looks kubectl up on the caller's PATH.
  Example: `kube-run --authorization rec.json txe-onprem-ci -- get pods -n arc-runners -o wide`.
- **`b5_custody.py`**: the reviewed B5 host-process custody, copied byte for byte (provenance below) and
  pinned by sha256 in `kube_run.py`.
- **`kubectl-context-guard.py`**: a PreToolUse hook that lets an agent's cluster API call through only on the
  installed kube-run path:
  - direct kubectl API calls are refused (H01), and so are helm, flux, k9s and stern API calls (H07);
  - anything it cannot read fails closed (H02 to H05, H12 to H14);
  - a client's name is allowed only in a position the hook understands: a client's own argv (classified), the
    installed kube-run's argv (H09 to H11), or an argument or input of the small closed data set (`echo`,
    `printf`, `cat`, `grep`, `which`, `test`) with its listed options only. Anywhere else it is refused (H15). An interpreter's code, arguments or input
    naming a client, and a shell or interpreter reading a pipe while the command names a client, are refused
    as H03. `watch` without `--exec` runs its words as shell text, and they are checked as such;
  - wrapper options follow per-wrapper arity tables. An option whose value is optional and attached only
    (`watch -d`/`--differences`, GNU `xargs -i`/`--replace`, `-e`/`--eof`, `-l`/`--max-lines`) consumes no
    word, and its attached short form (`-d1`, `-ifoo`) is unsupported: unknown, so refused when a client
    follows. A word consumed as a REQUIRED value never names a client (`watch -n kubectl ...` is H03), so a
    wrong table entry fails closed;
  - **the kube-run exception has one bounded grammar (H16).** A Bash command in which the installed kube-run
    is accepted must be EXACTLY one simple command: `<absolute literal path of the installed kube-run>
    <literal word> ...`, with words separated by spaces or tabs and nothing before the first word or after the
    last. A word is literal when quote removal alone decodes it:
    - unquoted characters exclude `` $ ` \ * ? [ ] ~ { } ! # ( ) < > ; & | ``;
    - `'...'` is literal as is;
    - `"..."` is literal when it holds no `` $ ` \ `` or `!`.
    Every other shape is refused, whatever it seems to do:
    - another command or any separator (`;`, `&&`, `||`, `|`, `&`, a newline);
    - a keyword, group, subshell or nested shell (`bash -c '<kube-run> ...'`, `$(<kube-run> ...)`);
    - a wrapper or prefix assignment;
    - any redirection or here-string (`2>&1`, `> out`, `< /dev/null`), and a comment;
    - any substitution, parameter, arithmetic, tilde or brace expansion, glob, escape or ANSI-C quote.
    An upper-case assignment-shaped argument (`PATH=/tmp/bin`) is refused too, as defence in depth against an
    inherited keyword mode. This is a bounded POSITIVE grammar: the hook does not claim to know which other
    shell syntax leaves kube-run's environment alone, and it is not proof of a trusted pre-existing
    environment (see the installation contract below);
  - **in a line that names a cluster client, a code-running command (a shell, `source`/`.`, `eval`, an
    interpreter) is inspected only through EXACTLY ONE literal inline program channel** (`inline_program`):
    | Caller | `-c` literal | literal args | literal here-doc / here-string | script or file operand | input redirect, `< <(..)`, pipe | other |
    |---|---|---|---|---|---|---|
    | shell (`bash`, `sh`, `zsh`, ...) | recurse | (positional) | recurse | refuse | refuse | refuse: unknown option, `--rcfile`/`--init-file` (either form), any `--opt=v`, two channels, none |
    | `eval` | n/a | recurse | refuse if combined (two channels) | n/a | refuse | refuse: no args, a non-literal arg |
    | `source` / `.` | n/a | n/a | refuse (a file is always opaque, `/dev/stdin` included) | refuse | refuse | refuse |
    | interpreter (`python3`, `node`, ...) | refuse | refuse | refuse | refuse | refuse | refuse (no channel of theirs is modelled) |
    "Literal" means: a `-c` word or `eval` argument that quote removal alone decodes, and a here-document with a
    QUOTED delimiter (`<<'EOF'`). The shell options are a CLOSED grammar: single letters from
    `abefhkmnptuvxBCEHPTcsilr`, `-o`/`+o`/`-O`/`+O` with the next word, and the long flags `--norc`,
    `--noprofile`, `--login`, `--posix`, `--verbose`, `--restricted`, `--noediting`, `--debugger` and
    `--protected`. In a line naming no client, the earlier behaviour applies: the `-c` text and standard input
    are checked. This makes no claim about code hidden elsewhere;
  - **local forms are a closed, evidenced grammar** (`LOCAL_FORMS`, `parse_local`, `local_form`). A client
    command the hook classifies as local stays local only if its WHOLE argv matches one form, with every
    option checked, before and after the subcommand. That covers repeated flags, `--name=value`, attached short
    values (`-ojson`), short clusters and `--`. Unknown options, ambiguous arity, and missing, empty or invalid
    values all make it an API call (H01/H07). The forms:

    **Supported versions are the ones txehq/txe pins**: kubectl v1.34.9, helm v4.2.3, flux v2.9.4, kustomize v5.8.1
    (the pin locations are in the source above `LOCAL_FORMS`). The flux v2.9.5 mention in txe (a code comment in
    `ops/ci/prod-release.py`) records a measurement and is not a pin. v2.9.5, Helm 3 and other versions are NOT modelled.
    **An install prerequisite is not runtime enforcement:** the hook cannot learn the installed version without
    executing it, so it does NOT detect or refuse an incompatible binary by version. Any adoption needs a verified,
    pinned executable identity and environment; none is done here.

    Evidence is each tool's SOURCE at its pinned tag (`file:line`). B is boolean, V a value, O an optional value
    that never takes the next word.

    | Form | Options (arity, values) and their definition | Operands | Excluded (execution-, network- or cluster-capable) |
    |---|---|---|---|
    | `kubectl` bare; `kubectl help <built-in>`; `<built-in> ... --help`/`-h` | help only | a built-in of v1.34.9 (`cmd.go:380-492`); never `create` | Help for a non-built-in: kubectl dispatches unknown commands to a plugin (`cmd.go:121-140`; `help` is exempt at `cmd.go:133-135`). `create <unknown>` dispatches a `kubectl-create-*` plugin even with `--help` (`cmd.go:144-161`, `172-175`) |
    | `kubectl version --client` | `--client` B, required (`version/version.go:89`, "no server required"); `-o`/`--output` V json\|yaml (`:90`, validated at `:120`) | none | `--client` absent |
    | `kubectl completion <shell>` | none | bash\|zsh\|fish\|powershell (`completion/completion.go:116-120`, looked up at `:154`) | n/a |
    | `kubectl options` | none (`options/options.go:37`) | none | n/a |
    | `kubectl plugin list` | `--name-only` B (`plugin/plugin.go:108`) | none | n/a: it lists files on PATH and executes none (no exec in `plugin.go`) |
    | `kubectl config current-context` | `--kubeconfig` V, `--context` V (`cli-runtime .../config_flags.go:351`, `:44`) | none | n/a: it reads the starting config (`config/current_context.go:64`) |
    | `kubectl config get-contexts` | `--no-headers` B (`config/get_contexts.go:85`); `-o`/`--output` V name (`:86`, supported set `:92`); `--kubeconfig`, `--context` | context names | n/a |
    | `kubectl config view` | `--minify` B (`config/view.go:99`); `-o`/`--output` V json\|yaml (PrintFlags `:92`); `--kubeconfig`, `--context` | none | `--raw` (`:97`) and `--flatten` (`:98`) refused as H08: secrets are redacted only when neither is set (`:149-155`, `RedactSecrets`); `--merge`, `--template` and other `-o` values |
    | `helm` bare; `helm help <built-in>`; `--help` | help only | a built-in of v4.2.3 (`pkg/cmd/root.go` command list) | Help for a plugin: plugins load with `DisableFlagParsing` (`load_plugins.go:134`), so `--help` reaches them. A plugin with a built-in's name is rejected (`load_plugins.go:139`) |
    | `helm version` | `--short` B (`version.go:74`); `--template` V (`:75`) | none | n/a |
    | `helm completion <shell>`; `helm env` | none | bash\|zsh\|fish\|powershell (subcommands, `completion.go:101-141`); none (`env.go:35`) | n/a |
    | `helm repo list` | `--no-headers` B (`repo_list.go:59`); `-o`/`--output` V table\|json\|yaml (`repo_list.go:60`, `flags.go:121`) | none | `repo add/update` |
    | `helm template [NAME] <./chart>` | `-a`/`--api-versions` V (`template.go:215`); `--devel` B (`install.go:200`); `--disable-openapi-validation` B (`:202`); `--dry-run` O, bare or `=client` (`template.go:218-221`, NoOptDefVal "unset"); `-g`/`--generate-name` B (`install.go:197`); `--include-crds` B (`template.go:211`); `--is-upgrade` B (`:213`); `-l`/`--labels` V (`install.go:209`); `--name-template` V (`:198`); `--no-hooks` B (`:193`); `-s`/`--show-only` V (`template.go:207`); `--skip-crds` B (`install.go:206`); `--skip-tests` B (`template.go:212`); `--set`, `--set-string`, `--set-json`, `--set-literal` V (`flags.go:52-56`); `-f`/`--values` V, a comma list, with no URL scheme anywhere (`flags.go:51`: "a YAML file or a URL"); `--kube-version` V (`template.go:214`); `--skip-schema-validation` B (`install.go:208`); `-n`/`--namespace` V (`pkg/cli/environment.go:153`) | 1-2; the last is a local chart path | `--post-renderer`, `--post-renderer-args` (`flags.go:46-47`, `:172`: a plugin it executes); `--dependency-update` (`install.go:201`); `--repo`, `--username`, `--password`, TLS and `--pass-credentials` (`flags.go:108-116`); `--version`, `--verify`, `--keyring` (`flags.go:105-107`); `--enable-dns` (`install.go:210`); `--output-dir` (`template.go:208`); `--set-file` (`flags.go:54`); `--dry-run=server`; `--validate` (`template.go:209`); the kube connection flags (`environment.go:154-169`); a non-local chart |
    | `helm lint [<./chart>...]` | `--strict` (`lint.go:147`), `--with-subcharts` (`:148`), `--quiet` (`:149`), `--skip-schema-validation` (`:150`) B; `--kube-version` V (`:151`); the template value flags (`:152` to `flags.go:51-56`, `--set-file` excluded); `-n` | local chart paths | URL values |
    | `flux version --client` | `--client` B, required (`version.go:66`); `-o`/`--output` V json\|yaml (`:68`, validated in `version.go`) | none | `--client` absent |
    | `flux completion <shell>` | none (`completion.go:32`) | bash\|zsh\|fish\|powershell | n/a |
    | `flux build artifact` | `-p`/`--path` V (`build_artifact.go:63`); `-o`/`--output` V (`:64`), both local paths; `--ignore-paths` V (`:65`); `--resolve-symlinks` B (`:66`) | none | `--add-ignore-paths` does NOT exist at v2.9.4 |
    | `flux install --export` | `--export` B, required (`install.go:92`; the manifest is written and the command returns before any cluster client, `install.go:205-207`); `--components`, `--components-extra` V (`:96`, `:98`); `--registry` V (`:101`); `--image-pull-secret` V (`:105`); `--watch-all-namespaces` B (`:107`); `--log-level` V debug\|info\|error (`:109`); `--network-policy` B (`:110`); `--cluster-domain` V (`:112`); `--toleration-keys` V (`:113`) | none (`cobra.NoArgs`, `:43`) | `-v`/`--version` (`:94`; a non-default version is resolved and downloaded from GitHub; empty uses the embedded manifests: `version_utils.go` `getVersion`/`isEmbeddedVersion`); `--manifests` (`:100`); `--registry-creds` (`:103`); `--force` (`:115`); no `--export` (it installs) |
    | `kustomize build <local dir>` | NONE | exactly one local directory (no `://`, `?`, `@`, or host-like first segment; `build.go:49` "build DIR") | every flag (`build.go:107-130`): output path, function basics (KRM functions), load restrictor, enable plugins, reorder, managed-by label, enable helm. A git-URL directory |

    `flux` help counts only the four commands above as built-ins. flux registers a plugin as a subcommand for every
    non-built-in name, with `DisableFlagParsing` (`plugin.go:45-60`), and only those four commands' sources were
    read. kubectl also reads kuberc preferences (aliases and default flags, `cmd.go:361`). Those, `$HELM_PLUGINS`
    and flux plugins are inherited configuration under the prerequisite below.

    The source files are kept in TXE-8039's local evidence store. NOT local any more (each H01/H07/H03): `kubectl kustomize`, `oc`/`kubecolor`/`microk8s.kubectl` local forms, `helm plugin|dependency|package|create|show|pull|push|registry|search|verify`, `helm repo` other than list, `flux create|envsubst|build kustomization`, flux OCI commands, `k9s` and `stern` local forms, `kubectl config get-clusters|get-users`, `--dry-run=none`, and any standalone `kustomize` use other than `build <local dir>`. A client name in a local form's argument is refused (H03), but only as **defence in depth**: an arbitrary helper can invoke a client without naming it in the command;
  - **what this grammar cannot establish (source-only prerequisites):** literal option checking does NOT show that chart or kustomization CONTENTS (templates, remote bases, helmCharts), inherited CONFIGURATION (helm repositories, registry and plugin directories, `$HELM_PLUGINS`, kubeconfig exec users, kubectl kuberc preferences with their aliases and default flags, git configuration) or installed PLUGINS (kubectl, helm and flux plugins) are trusted, or that the installed binaries are the pinned versions. Those are deployment prerequisites of any install, recorded here, not facts the hook proves. The parser boundary is NOT the only residual risk;

## What state this is in

- **Unwired source is inert.** Nothing in this directory installs itself. Nothing here changes a
  kubeconfig, a current-context, a credential, a settings file or a hook configuration.
- **Once wired, the hook BLOCKS calls.** With no cluster registered, every agent cluster API call is
  refused. An unconfigured kube-run refuses every call too (KR02 with no registry, KR06 with no policy).
  Wiring the hook therefore changes agent behaviour at once. It is a deployment decision with its own plan,
  not part of this change.
- **An authorization record is a declaration of scope, not tamper-proof authority.** kube-run checks a
  record's shape, cluster, expiry and scope against the request. It does not check who wrote the record: a
  caller who can write a file can write one. KR06, the refusal of every call to an entry with no policy
  configured, is a default-deny, not authentication of a configured record. Who may issue records, and how
  they are protected, is a decision for any install plan; signing is out of scope here.
- The rules that need a decision before any install are compatibility proposals, not approved policies:
  static credentials only, the direct-client and helm/flux refusals, which clusters are registered and who
  writes authorization records.

## Event shapes: guarded, unsupported, not installed

| Shape | Status |
|---|---|
| Claude Code PreToolUse, `tool_name == "Bash"`, `tool_input.command` a string | **Guarded.** Parsed by the hook's lexer and checked by H01 to H13 and H15. Tested with synthetic events in Claude Code's documented shape. Not yet observed in a live harness |
| Any other tool or harness with a command-like field (`tool_input.command` or `tool_input.cmd`, a string or an argv list), for example a Codex shell call | **Unsupported, NOT guarded.** It is refused (H14) when the text names a cluster client, and allowed otherwise. Nothing in it is parsed, so a kube-run call in this shape passes unchecked by the hook (kube-run still runs its own checks). No Codex payload has been captured or tested; the shapes in the tests are hand-written |
| Events with no command-like field (Read, Edit, MCP tools, ...) | Allowed, not guarded. MCP cluster tools are out of scope (TXE-7874) |
| Script files (`bash ops/x.sh` that runs kubectl inside), client-go programs, and interpreter code that builds a client's name at run time (`python3 -c '...execlp("kube"+"ctl", ...)'`) | **Not visible to the hook.** It is a heuristic over command text, and it refuses interpreter payloads only when they name a client. Keeping such calls off a production cluster needs the agent's environment to hold no usable default credential. That is a deployment decision, not something this hook can enforce |
| Any harness where the hook is not wired | **Not installed**: no protection at all |

Only the first row is positive protection. An H14 refusal is a fail-closed stop, not a claim of coverage.

## Shell parsing: its scope and its cost

The hook reads Bash command text with its own lexer. That covers quoting, `$(...)`, backticks, `<(...)`,
here-documents and here-strings, `sh -c`/`eval`/stdin fed to a shell, and wrappers. Here-document delimiters
follow Bash's quote removal (`<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<-EOF`). It is **not** a full Bash
parser, and it does not parse interpreter code.

**A command the hook cannot parse is refused (H05), whatever it names.** That is the conservative choice for
an unwired prototype, and its effect is broad. Once wired, some legitimate NON-cluster Bash commands that this
lexer cannot read would be refused as well, for example a partly quoted here-document delimiter (`<<"E"OF`) or
other constructs outside the forms above. Such a refusal says H05; the remedy is to write the command in a
form the lexer reads. The extra raw-text check is a second line only, never the parser.

**Mentions are read quote-decoded.** Every mention check (`mentions`, through `mention_forms`) reads the text
as it is, with backslashes removed (`kube\ctl`), and QUOTE-DECODED: line continuations removed, `$'...'`
ANSI-C decoded (both as decoded and with each quoted segment ended at its first decoded NUL, as Bash does:
`$'kubectl\0ignored'` is `kubectl`), `$"..."` read as `"..."`, then every quote and backslash removed. So a name that quote removal
assembles (`echo kube''ctl get secrets | bash`, `cat <<'EOF' | bash` over `kube"c"tl`, `$'\x6bubectl'`) marks
the line client-relevant, and the pipe receiver is refused (H03). The decoding parses nothing, so it also covers
text the lexer cannot read, such as here-document bodies and raw event JSON. Deleting every quote
over-approximates quote removal; that can only refuse more.

**Brace alternatives are expanded, bounded.** Bash expands `kube{ctl,x}` to `kubectl kubex` before it runs
anything, with no variable or file involved. So `mention_forms` also reads each base with its brace words
expanded STRUCTURALLY (`brace_expanded`). Deleting the braces instead would read `kubectlx`.
- The expansion follows Bash's matching. A `{` opens a group at its matching unquoted `}` when it has a
  top-level comma or is a sequence `{x..y[..incr]}`. Otherwise it is literal, and the groups inside it still
  expand.
- Alternatives may be empty, nested or adjacent, and they compose with any prefix and suffix.
- Quoted and escaped braces and `${...}` are literal for this shell. They are expanded once more with the quotes
  removed, because a downstream shell may expand them (`echo kube\{ctl,x\} | bash`, `bash -c 'echo kube{ctl,x} |
  bash'`).
- A numeric sequence contributes only its single unpadded digits, plus one inert sentinel, because no client name
  holds two adjacent digits. So `k{1..500}s` is 10 alternatives, not 500.
- **Fail closed past a bound.** The word count AND the expanded length are computed from the parsed groups
  (`_brace_cost`) before any string is built, so an over-budget word never reaches the builder. These count as
  naming a client:
  - more than 1 Mi units examined by sequence checks in one text (deeply nested literal braces);
  - a word with more than 256 expansions, or a text with more than 4096 in all;
  - more than 1 MiB of expanded text;
  - nesting deeper than 16;
  - a character sequence of more than 256 members;
  - an integer endpoint too long to convert.
- **Expected false refusals from the bound:** an over-budget brace word in a line where a mention matters is
  refused. Examples: `touch {a..z}{a..z}` (676 words; an unclassified command, H15), `echo {a,b}{a,b}... | bash`,
  and an inline JSON object with more than 256 top-level keys passed to an unclassified command. In a data
  command with no code receiver (`echo {a..z}{a..z}`), nothing changes.

A name built at RUN TIME (`printf %s%s kube ctl`, `kube${x}ctl`, `$(echo kube)ctl`, a glob) is not quote
removal or brace expansion, and is not claimed to be caught.

**The parser boundary is a limit.** The input-channel classifier refuses the shapes it models: script and file
operands, input redirections, pipes, startup-file and unknown options, more than one channel, and non-literal
ones. It does NOT show that every way a shell, `source`, `eval` or an interpreter can obtain code is covered. An
input channel this lexer does not represent (one it does not see as a word, a redirection or a here-document) is
not claimed to be caught.

## Positive classification: where a client's name is accepted

Every cluster-client name in a guarded command must sit in a context the hook understands. Any other mention is
refused:
- H15 in an unclassified command;
- H03 in an interpreter, or in a shell or interpreter that reads a pipe or generated text;
- H02 after a run-time command word.

| Accepted context | Exact conditions |
|---|---|
| A client's own argv (`kubectl`, `helm`, `flux`) | It matches one closed, evidenced LOCAL form with only its listed options (see the local-forms table above). oc, kubecolor, microk8s.kubectl, k9s and stern have no local forms. Any other form is H01 or H07 |
| The installed kube-run's argv | H09 to H11 hold, and kube-run repeats every check at run time |
| The SMALL closed data set (`DATA_OPTIONS`) | `echo` with `-n` `-e` `-E` only; `printf` and `cat` with NO options; `grep` with `-r` `-R` `-n` `-i` `-l` `-c` `-v` `-w` `-x` `-E` `-F` `-o` and `-e <pattern>` (`egrep`/`fgrep` the same, without `-E`/`-F`); `which` with `-a`; `test`, `true`, `false` and `:` with any token; `[` ... `]`, the EXACT word `[` with `]` as its last argument, classified before the glob check with the rules of `test` (a `[` without its `]` is H05; words merely containing `[`, such as `[a-z]` or `x[`, stay run-time command words, H02). Operands and input are then data, but only while that output does not reach code: a shell or interpreter reading its pipe is refused, and so is an output process substitution `>(...)` (checked as a pipe receiver) or a redirection into a process substitution |
| `command -v` / `command -V` | A lookup, not a run |
| The inner text of `$(...)`, backticks and `<(...)` | It is classified recursively by these same rules |

Why no operand of the data set carries execution: `echo`, `printf` and `cat` print text or file contents;
`grep` matches a pattern over files (this set has no pager, preprocessor or exec option); `which` prints paths;
`test`/`[` evaluate an expression; `true`/`false`/`:` ignore their arguments. Rejected forms: any option not
listed, any attached or clustered short form outside the listed letters, `--long=value` for an unlisted name, and
every other command.

**Unsupported, and refused when a client is named:** every other command, including `man` (it runs a pager:
`man -P`, `--pager`, `MANPAGER`), `git` (configured hooks, pagers, diff drivers and textconv helpers run without any
flag in the command, and `grep -O`/`--open-files-in-pager`, `--ext-diff` and `--textconv` run programs), `head`,
`tail`, `tee`, `rg`, `ag`, `sort`, `less`, `more`, `gh`, `orca`, `awk`, `sed`, `make` and scripts. A prefix
assignment whose value names a client (`MANPAGER='kubectl ...' man ls`, `GIT_PAGER=...`) is refused as H04.
Also:
- `source` or `.` of generated text;
- an interpreter whose code, arguments or input name a client;
- `watch` (its words are shell text unless `--exec` is given);
- a shell or interpreter reading a pipe;
- **every `xargs` in a line that names a client.** xargs completes its command from its input at run time
  (`printf 'kubectl delete secrets -A' | xargs env` runs `env kubectl delete secrets -A`), so it is an input
  consumer, not a wrapper. Its input may be inherited through a group, a loop or the tool's own stdin
  (`... | ( xargs env )`, `... | while read x; do xargs env; done`, `( xargs env ) < f`), so the hook does not try
  to detect it. In a client line, every xargs is refused (H03), whatever it runs. A client named in the text after
  it (`... | xargs kubectl get`) is still classified, but never allowed:
  - a specific refusal is kept (H08 for `config view --raw`);
  - every other kind is refused as an API call (H01/H07), including a local form and a config write
    (`echo 'view --raw' | xargs kubectl --kubeconfig=/tmp/k config`), because xargs can extend its argv.

  **Conservative, and broad, by design:** `printf kubectl | xargs echo`, a bare `... | xargs`, and an xargs with
  no visible input anywhere in a client line (`echo kubectl; xargs -a list.txt echo`) are all refused. Without a
  client in the line, xargs is unchanged (`ls | xargs echo`);
- the forms the lexer cannot parse (H05).

**Sub-grammars: one inventory, and refusal where a grammar is not modelled.** The hook never classifies one
grammar by treating it as another. The text that a recognized wrapper or code receiver runs is read in exactly one
of four ways (the inventory is in the source, above `UNMODELLED_SHELLS`):
- **POSIX/Bash shell text**, read by the lexer. This covers `sh`/`bash`/`zsh`/`dash`/`ksh` with `-c`, stdin or a
  here-document; `eval`; substitutions; `watch` (which runs `sh -c`); and an `env -S` payload with no `\` or `$`.
- **Refused (H03), because the grammar is not modelled:**
  - text that `fish` would run. Only a plain script file is accepted: one or more LITERAL words, with no option,
    substitution, process substitution or expansion, and no pipe, stdin or input redirection. So `fish -c ...`,
    `fish <(printf ...)`, `fish "$S"` and a bare `fish` are refused;
  - an `env -S`/`--split-string` payload holding a backslash or `$` (env's `\_` separator, `\c`, escapes and
    `${NAME}`), in every spelling, whether or not a client is visible;
  - an `env` split-string option in a spelling the hook does not read: a getopt abbreviation (`--sp=...`,
    `--split ...`) or an `S` inside a short-option cluster (`-iS ...`). A cluster whose attached value merely
    contains an `S` (`-uSOME`) is refused too;
  - every `xargs` in a client line.
- **Opaque, refused when its text names a client (H03/H15):** interpreters, OPAQUE executors, and every
  unclassified command, including the languages inside `awk`, `sed` and `jq`. Their own escapes and run-time
  construction are the documented limit.
- **Argv passthrough with closed option tables:** `env` (without `-S`), `timeout`, `nice`, `nohup`, `sudo`,
  `doas`, `command`, `exec` and the rest of `WRAPPERS`, and `k3s`/`microk8s`/`minikube kubectl`.

Expected false refusals from this rule: `fish -c 'echo hi'`, `echo x | fish`, and `env -S 'date\tx'` or
`env -S '$HOME/bin/tool'`.

**Expected false refusals, documented:** text that only QUOTES a client name, inside a command that is not a data
context, is refused too. Examples: an orchestration message (`orca orchestration ask --question 'run kubectl get
pods?'`), a `gh` comment, an `rg` search, a `git commit -m` message, `git log --grep` and `man kubectl`. Write such
text with a data command (`echo`, `cat` to a file), or without the client's name.

**Scope and prerequisites:** this is not containment of arbitrary scripts or interpreters. The hook cannot infer
commands that are absent from the command text: a script file's contents, or a program that builds a client's
name at run time. Its classification also ASSUMES things it cannot see:
- that the command words resolve to the standard programs, so no shell alias or function and no `PATH` entry
  shadows `echo`, `cat`, `grep` and the rest;
- that no external configuration turns them into launchers (an alias file, a `BASH_ENV`, a pager or driver
  setting).
These are deployment prerequisites, not things the hook proves. It does not guard every way a shell can execute a
command: it refuses the ones it can see that it does not understand.

**H16's expected false refusals, documented:** every kube-run use that is not a single bare literal
invocation. That includes:
- `cd /tmp && kube-run ...`, `if kube-run ...; then ...`, `kube-run ... | grep Running`;
- `set -euo pipefail; kube-run ...` and `kubectl config current-context; kube-run ...`;
- `bash -c 'kube-run ...'`;
- `kube-run ... 2>&1` and `kube-run ... > out.txt`;
- `kube-run ... -n "$NS"`, and `-o jsonpath={.items}` unquoted (quote it: `-o 'jsonpath={.items}'`);
- `timeout 60 kube-run ...` (use kube-run's own `--timeout`);
- a path written with `~`.
Run kube-run alone, by its absolute path, with literal arguments, in its own tool call. Filter or combine its
output in a later call. The Bash tool already returns both stdout and stderr.


**Installation contract for kube-run (a prerequisite of any install; nothing here installs it):** the installed
kube-run must start through an ABSOLUTE, pinned interpreter in isolated mode. For example, it can be a small
launcher at the installed path that execs `<absolute python3.13> -I -B <absolute kube_run.py> "$@"`. The
`#!/usr/bin/env python3` shebang is for running it from source. Through `env`, it lets the caller's `PATH` choose
the interpreter, and a program posing as Python would receive kube-run's full argv before any check. H16 keeps
the hook from accepting any line other than one bare literal kube-run invocation. But the hook cannot see an
environment the agent's shell already inherited, which is why the pinned interpreter is the install's job. Relative entries in an inherited
`PATH` (which `cd` would then change) are excluded by the same contract.

## Platform and syscall constraints

- B5 needs **macOS**. It reads group membership through libproc `proc_listpids(PROC_PGRP_ONLY)` and observes
  the leader without reaping it through `os.waitid(..., WNOWAIT)`, which needs Python 3.13 on macOS. It
  spawns with `posix_spawn(setsid=True)` and blocks TERM, INT and HUP with `pthread_sigmask` around the
  spawn.
- On any other platform (Linux included), B5's `bounded_run` refuses **before it creates any pipe or child**,
  and kube-run refuses the call as **KR26** (exit 3). The argument, registry, authorization and pin checks still
  run first. A Linux implementation would need a reviewed `/proc`-based membership reader: new code and a new
  pin, not a change to the copied section.
- **B5's stated limit:** it settles the owned process group only. A descendant that calls `setsid()` leaves
  the group, and is neither seen nor signalled. That is why kube-run refuses credential helpers (exec,
  auth-provider, impersonation: KR23). kube-run is not containment for arbitrary exec plugins or client-go
  programs, and it is not ready for real auth plugins.
- The hook never runs a client, never opens a kubeconfig and never contacts a cluster.

## Provenance of `b5_custody.py`

Everything from the line `# ---------- B5` to the end of `b5_custody.py` is copied byte for byte from:
- **Source:** `runner-final.py`, the reviewed container-stage-1 runner of TXE-7974 (file sha256 `c7c97084…`,
  lines 294-640). TXE wrote it, and it is kept as TXE-7974 evidence rather than in this repository.
- **Pin:** the section's sha256 is `074c8f65f57b987118079e99ef92c9ec86929111679605a2552c9c8fd1ff94d8`.
  `test_kube_run.py` fails when it differs.
- **Whole file:** `kube_run.py` pins the whole file's sha256 (`B5_SHA256`), and refuses to run (KR25) on any
  other copy.
- **Licence:** the same as this repository (`GPL-3.0-or-later`).

Do not edit below the marker. A change is a new reviewed revision, then new pins in both places.

## Tests

`go test ./txe/kubeguard/` runs both suites with `python3 -I -B`, in pure mode (`kubeguard_test.go`). They are
skipped on Windows.

- **`test_kube_run.py`.**
  - kube-run is driven through `main()` with a stub transport, a fixed clock and inert fixtures.
  - The tests cover the pre-contact pins, authorization, overrides, value-free diagnostics, settlement
    outcomes, credential helpers and the B5 pins.
  - Off macOS they also check that the real transport refuses with KR26 before any child.
  - On macOS with `KUBEGUARD_REAL_CHILDREN=1`, run directly (`python3 -I -B test_kube_run.py -v
    RealChildrenThroughB5`), 8 more cases run real, bounded, self-expiring children through B5. The fixtures
    signal no child; B5 runs its own TERM/KILL cleanup. That mode keeps its fixture root as evidence. CI never
    runs it.
- **`test_kubectl_context_guard.py`.**
  - Synthetic events on stdin cover the refusals, the allowed local and kube-run forms, value-free
    diagnostics, and the event shapes above.
  - **PairingWithKubeRun** checks the hook against this directory's `kube_run.py`:
    - every kube-run form the hook allows parses in kube-run;
    - an argument form the hook refuses is refused by kube-run too;
    - the two override lists are the same list.
