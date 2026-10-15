// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
)

// recordLockDirectoryName is the file collection's per-record lock
// directory (internal/persis/file).
const recordLockDirectoryName = ".dagu_record_locks"

// hasModeBits is false where the file system has no Unix permission bits.
const hasModeBits = runtime.GOOS != "windows"

// Root is a directory to scan, as one area.
type Root struct {
	Area string
	Path string
	// Label names the root in the inventory. It must be the same in every
	// inventory that is compared, wherever the root is mounted.
	Label string
	// Mount is where the service that wrote the root sees it, when the scan
	// reads a copy or another mount: for a hub data directory, the hub's
	// data directory path. Paths stored in records are resolved through it.
	Mount string
}

// Options configure a scan.
type Options struct {
	Roots []Root
	// ExpectedOwner is the installation's stable owner. Required.
	ExpectedOwner string
	Label         string
	Tool          string
	Now           func() time.Time
	// Keep names entries that no writer owns but that are kept exactly as
	// they are (DecodeKeep).
	Keep *KeepManifest
}

// Hub data directory areas. Each top-level entry of the data directory is
// one of these, or the scan reports it as unclassified and blocks.
var hubDataAreas = map[string]string{
	// Retained execution history and state: present later, may change.
	"dag-runs":          PolicyMutable,
	"dag-state":         PolicyMutable,
	"artifacts":         PolicyImmutable,
	"suspend":           PolicyMutable,
	"workspaces":        PolicyMutable,
	"views":             PolicyMutable,
	"incidents":         PolicyMutable,
	"notifications":     PolicyMutable,
	"wiki":              PolicyMutable,
	"docs":              PolicyMutable,
	"workspace-bundles": PolicyMutable,
	// Collections of the file backend (internal/persis/file/backend.go):
	// per-DAG settings, the scheduler's watermarks and pause state, and
	// profiles, whose values are plain and whose secrets are references.
	"dag-settings": PolicyMutable,
	"scheduler":    PolicyMutable,
	"profiles":     PolicyMutable,
	// Operational state that is rebuilt or consumed.
	"queue":            PolicyOperational,
	"proc":             PolicyOperational,
	"service-registry": PolicyOperational,
	"tunnel_url":       PolicyOperational,
	// The upgrade check's cache; the distributed dispatch tasks, leases,
	// active-run records and worker heartbeats; the agent-session cleanup
	// queue.
	"upgrade":                PolicyOperational,
	"distributed":            PolicyOperational,
	"agent-session-cleanups": PolicyOperational,
}

// Areas of the data directory that are never read.
var hubDataExcluded = map[string]string{
	"users":            "holds login credentials; not read",
	"apikeys":          "holds API key material; not read",
	"webhooks":         "holds webhook secrets; not read",
	"contexts":         "holds remote context credentials; not read",
	"remote-nodes":     "holds remote node credentials; not read",
	"auth":             "holds the encryption key; not read",
	"tailscale":        "holds tailscale node keys; not read",
	"license":          "holds license material; not read",
	"secrets":          "the secret store; not read",
	"oidc_sessions":    "OIDC session records with their tokens; not read",
	"dag-run-work":     "per-run scratch working directories; operational, not retained",
	"tools":            "downloaded tool binaries; reinstalled, not retained data",
	"materializations": "derived caches; rebuilt",
	"cache":            "derived caches (the DAG index); rebuilt",
}

// Areas of the data directory classified entry by entry: they hold both
// retained state and something that is rebuilt or holds credentials. An
// entry not listed blocks as unclassified. A value is a file policy, or
// "exclude: <reason>".
var hubDataSubAreas = map[string]map[string]string{
	// The sync state records each item's last synced hash and local
	// modification; the clone's git config can carry remote credentials and
	// the clone is reproducible from the remote.
	"gitsync": {
		"state.json": PolicyMutable,
		"repo":       "exclude: a clone of a remote whose git config can carry credentials; reproducible from the remote, not read",
	},
	// Host session records are what a paused step resumes from; the replay
	// cache is rebuilt.
	"browser":  {"sessions": PolicyMutable, "cache": "exclude: browser host replay cache; rebuilt"},
	"computer": {"sessions": PolicyMutable, "cache": "exclude: computer host replay cache; rebuilt"},
	"xlsx":     {"sessions": PolicyMutable, "cache": "exclude: workbook replay cache; rebuilt"},
}

// Entry kinds a rule can require.
const (
	kindDir = iota + 1
	kindFile
	kindLink
)

// rule classifies an entry of a machine's TXE home, by exact name or by a
// name pattern: as a file policy for everything under it, as an exclusion
// that is never read, or as a directory whose entries are classified in
// turn. An entry no rule matches blocks.
type rule struct {
	name    string
	pattern *regexp.Regexp
	// kind, when set, is the entry's required type.
	kind int
	// target is the required target of a link.
	target  *regexp.Regexp
	policy  string
	exclude string
	dir     []rule
	// check, when set, reads a file the rule retains and refuses one its
	// writer would not have written.
	check func(name string, data []byte) error
}

func (r *rule) matches(name string) bool {
	if r.pattern != nil {
		return r.pattern.MatchString(name)
	}
	return r.name == name
}

const (
	machineIDPattern   = `mch_[0-9A-HJKMNP-TV-Z]{26}`
	daguVersionPattern = `[0-9]+\.[0-9]+\.[0-9]+-txe\.[0-9]+`
)

// machineHomeRules is a machine's TXE home as the worker installer
// (txe/worker/install.sh) and the CLI write it; machine.json and packages
// are read separately.
var machineHomeRules = []rule{
	{name: "receipts", kind: kindDir, policy: PolicyMutable},
	{name: "outputs", kind: kindDir, policy: PolicyImmutable},
	{name: "client", kind: kindDir, exclude: "the CLI's Dagu home holds its hub credential; not read"},
	{name: "skill", kind: kindDir, exclude: "unpacked skill revisions; reinstalled, not retained data"},
	{name: "tunnel", kind: kindDir, exclude: "the tunnel's port-forward credential (a ServiceAccount kubeconfig and its expiry), renewed by tunnel-credential.sh; not read"},
	// The worker's machine credential at its default path, with its lock
	// and the temporary file a rotation is saved through
	// (internal/cmd/txe_enrol.go, internal/txe/transportauth/credential.go).
	{name: "worker-credential.json", kind: kindFile, exclude: "the worker's machine credential (dagu txe enrol); not read"},
	{name: "worker-credential.json.lock", kind: kindFile, exclude: "the machine credential's lock; not read"},
	{pattern: regexp.MustCompile(`^\.worker-credential\.json\.[0-9]+$`), kind: kindFile, exclude: "a machine credential being saved; not read"},
	// The CLI's sign-ins, one sealed entry per hub with its lock, and the
	// temporary file an entry is written through (internal/txe/cliauth
	// entryPaths, fileutil.WriteFileAtomic).
	{name: "signin", kind: kindDir, dir: []rule{
		{pattern: regexp.MustCompile(`^[0-9a-f]{32}\.json$`), kind: kindFile, exclude: "a sealed CLI sign-in; not read"},
		{pattern: regexp.MustCompile(`^[0-9a-f]{32}\.lock$`), kind: kindFile, exclude: "a CLI sign-in's lock; not read"},
		{pattern: regexp.MustCompile(`^[0-9a-f]{32}\.json\.tmp\.[0-9]+$`), kind: kindFile, exclude: "a CLI sign-in being saved; not read"},
	}},
	// Every installed binary with its build record, and the link to the
	// current one: rebuilt from a release tag, and an upgrade moves the
	// link, so they are counted, not compared.
	{name: "bin", kind: kindDir, dir: []rule{
		{name: "dagu", kind: kindLink, target: regexp.MustCompile(`^dagu-` + daguVersionPattern + `$`), policy: PolicyOperational},
		{pattern: regexp.MustCompile(`^dagu-` + daguVersionPattern + `$`), kind: kindFile, policy: PolicyOperational},
		{pattern: regexp.MustCompile(`^dagu-` + daguVersionPattern + `\.json$`), kind: kindFile, policy: PolicyOperational},
	}},
	// The launchd agents' output: diagnostics that grow while the agents
	// run, not job data.
	{name: "logs", kind: kindDir, dir: []rule{
		{name: "tunnel.log", kind: kindFile, policy: PolicyOperational},
		{name: "worker.log", kind: kindFile, policy: PolicyOperational},
	}},
	// The worker's DAGU_HOME. Its data directory holds only credentials so
	// far; anything else it gains blocks until it is classified.
	{name: "worker-home", kind: kindDir, dir: []rule{
		{name: "data", kind: kindDir, dir: []rule{
			{name: "auth", kind: kindDir, exclude: "the worker's encryption key; not read"},
			{name: "contexts", kind: kindDir, exclude: "remote context credentials; not read"},
		}},
	}},
	{name: "state", kind: kindDir, dir: []rule{
		// dagu txe hub install's lock (internal/cmd/txe_hub.go).
		{pattern: regexp.MustCompile(`^hub-install-` + machineIDPattern + `\.lock$`), kind: kindFile, policy: PolicyOperational},
		// The resource probe's journal: reports the registry has not
		// acknowledged yet (internal/txe/probe/journal.go).
		{name: "probe", kind: kindDir, dir: []rule{
			{pattern: regexp.MustCompile(`^journal-` + machineIDPattern + `\.json$`), kind: kindFile, policy: PolicyMutable},
			{pattern: regexp.MustCompile(`^journal-` + machineIDPattern + `\.json\.lock$`), kind: kindFile, policy: PolicyOperational},
			{pattern: regexp.MustCompile(`^\.journal-[0-9]+$`), kind: kindFile, policy: PolicyOperational},
		}},
		// The reviewer's --state-dir as the reviewer is installed here: each
		// run's hand-off between its steps (internal/txe/review/steps.go).
		{name: "review", kind: kindDir, dir: []rule{
			{name: "reviews", kind: kindDir, dir: []rule{
				{pattern: regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`), kind: kindDir, dir: []rule{
					{name: "prepared.json", kind: kindFile, policy: PolicyMutable},
					{name: "prepared.json.tmp", kind: kindFile, policy: PolicyOperational},
				}},
			}},
		}},
	}},
}

// hubStores are the stores of the records read from a hub data directory
// (Record.Store); a machine home stores its records under its root label.
var hubStores = map[string]bool{"registry": true, "authz": true}

// hubDataRules classify, entry by entry, areas of the data directory whose
// names must stay exact: a credential beside other files, or entries only
// their writer's names and contents may have.
var hubDataRules = []rule{
	// The coordinator's hub key at its default path, and the temporary file
	// it is created through (internal/cmn/config defaultHubKeyFile,
	// internal/txe/transportauth/hubkey.go).
	{name: "coordinator", kind: kindDir, dir: []rule{
		{name: "hub.key", kind: kindFile, exclude: "the coordinator's hub key; not read"},
		{pattern: regexp.MustCompile(`^\.hub\.key\.[0-9]+$`), kind: kindFile, exclude: "a hub key being created; not read"},
	}},
	// The attempt preparation journal beside the run tree
	// (internal/persis/file/dagrun/preparation.go): an entry for each
	// attempt prepared for a worker and not yet handed to one, which the
	// coordinator reads after a restart to abandon an attempt it never
	// dispatched (internal/service/coordinator/abandoned_preparation.go).
	// Entries are retained; the temporary file one is written through
	// (fileutil.WriteFileAtomic) is not.
	{name: "dag-runs.preparations", kind: kindDir, dir: []rule{
		{pattern: regexp.MustCompile(`^[0-9a-f]{64}(-[0-9a-f]{32})?\.json$`), kind: kindFile, policy: PolicyMutable, check: preparationEntry},
		{pattern: regexp.MustCompile(`^[0-9a-f]{64}(-[0-9a-f]{32})?\.json\.tmp\.[0-9]+$`), kind: kindFile, policy: PolicyOperational},
	}},
}

// preparationEntry accepts a preparation journal entry the journal reads:
// one it decodes, stored under its own name (ListAttemptPreparations skips
// any other, so its attempt would never be abandoned).
func preparationEntry(name string, data []byte) error {
	p, err := dagrun.DecodePreparation(data)
	if err != nil {
		return err
	}
	if want := dagrun.PreparationEntryName(*p); want != name {
		return fmt.Errorf("its contents name the entry %s", want)
	}
	return nil
}

func ruleFor(rules []rule, name string) *rule {
	for i := range rules {
		if rules[i].matches(name) {
			return &rules[i]
		}
	}
	return nil
}

// Scan inventories the roots. It only reads; a root that cannot be read is
// an error, and anything it does not understand is a blocking issue.
func Scan(ctx context.Context, opts Options) (*Inventory, error) {
	if opts.ExpectedOwner == "" {
		return nil, errors.New("continuity: an expected owner is required")
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	inv := &Inventory{
		Format:        FormatV1,
		Label:         opts.Label,
		ScannedAt:     now().UTC(),
		Tool:          opts.Tool,
		ExpectedOwner: opts.ExpectedOwner,
		ModeBits:      hasModeBits,
		Machines:      map[string]string{},
	}
	keep, err := keepIndex(opts.Keep)
	if err != nil {
		return nil, err
	}
	keepSeen := map[string]bool{}
	labels := map[string]bool{}
	for _, r := range opts.Roots {
		if r.Label == "" {
			return nil, fmt.Errorf("continuity: root %s needs a label", r.Path)
		}
		if labels[r.Label] {
			return nil, fmt.Errorf("continuity: root label %q is used twice", r.Label)
		}
		if hubStores[r.Label] {
			// A machine home's records are stored under its label, so a
			// label that names a hub store would mix them with the hub's.
			return nil, fmt.Errorf("continuity: root label %q names a hub store; choose another", r.Label)
		}
		labels[r.Label] = true
		info, err := os.Stat(r.Path)
		if err != nil {
			return nil, fmt.Errorf("continuity: root %s: %w", r.Label, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("continuity: root %s is not a directory", r.Label)
		}
		inv.Roots = append(inv.Roots, RootInfo{Area: r.Area, Label: r.Label, Path: r.Path, Mount: r.Mount})
		s := &scanner{ctx: ctx, inv: inv, root: r, keep: keep, keepSeen: keepSeen}
		switch r.Area {
		case AreaHubData:
			err = s.hubData()
		case AreaDAGs, AreaLogs, AreaArtifacts:
			policy := PolicyMutable
			if r.Area == AreaArtifacts {
				policy = PolicyImmutable
			}
			err = s.files("", policy)
		case AreaMachineHome:
			err = s.machineHome()
		default:
			return nil, fmt.Errorf("continuity: root %s has unknown area %q", r.Label, r.Area)
		}
		if err != nil {
			return nil, err
		}
	}
	keptMissing(inv, keep, keepSeen)
	if err := inv.Seal(); err != nil {
		return nil, err
	}
	return inv, nil
}

type scanner struct {
	ctx  context.Context
	inv  *Inventory
	root Root
	// keep holds the keep manifest's entries by root label and path, and
	// keepSeen those the scan found.
	keep     map[string]*KeepEntry
	keepSeen map[string]bool
}

func (s *scanner) issue(code, class, id, format string, args ...any) {
	s.inv.Issues = append(s.inv.Issues, Issue{Code: code, Severity: SeverityBlock, Class: class, ID: id, Detail: fmt.Sprintf(format, args...)})
}

func (s *scanner) exclude(rel, reason string) {
	s.inv.Excluded = append(s.inv.Excluded, Excluded{Root: s.root.Label, Path: rel, Reason: reason})
}

func (s *scanner) hubData() error {
	entries, err := os.ReadDir(s.root.Path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if s.symlink(name, e) {
			continue
		}
		switch {
		case name == "txe":
			if err := s.txe(); err != nil {
				return err
			}
		case hubDataExcluded[name] != "":
			s.exclude(name, hubDataExcluded[name])
		case hubDataAreas[name] != "":
			if err := s.files(name, hubDataAreas[name]); err != nil {
				return err
			}
		case hubDataSubAreas[name] != nil:
			if err := s.subAreas(name, hubDataSubAreas[name]); err != nil {
				return err
			}
		case ruleFor(hubDataRules, name) != nil:
			if err := s.entry(name, e, hubDataRules); err != nil {
				return err
			}
		default:
			if ok, err := s.kept(name); err != nil || ok {
				if err != nil {
					return err
				}
				continue
			}
			s.issue("unclassified_area", "", name, "%s/%s is not a known area of the data directory; classify it before a transition, it was not read", s.root.Label, name)
		}
	}
	return nil
}

// subAreas scans an area of the data directory entry by entry.
func (s *scanner) subAreas(area string, entries map[string]string) error {
	if info, err := os.Lstat(filepath.Join(s.root.Path, area)); err != nil || !info.IsDir() {
		if err != nil {
			return err
		}
		s.issue("unclassified_area", "", area, "%s/%s is not a directory; it was not read", s.root.Label, area)
		return nil
	}
	list, err := os.ReadDir(filepath.Join(s.root.Path, area))
	if err != nil {
		return err
	}
	for _, e := range list {
		rel := area + "/" + e.Name()
		if s.symlink(rel, e) {
			continue
		}
		class, ok := entries[e.Name()]
		switch {
		case !ok:
			if kept, err := s.kept(rel); err != nil || kept {
				if err != nil {
					return err
				}
				continue
			}
			s.issue("unclassified_area", "", rel, "%s/%s is not a known part of the data directory; classify it before a transition, it was not read", s.root.Label, rel)
		case strings.HasPrefix(class, "exclude: "):
			s.exclude(rel, strings.TrimPrefix(class, "exclude: "))
		default:
			if err := s.files(rel, class); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *scanner) txe() error {
	dir := filepath.Join(s.root.Path, "txe")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if s.symlink("txe/"+e.Name(), e) {
			continue
		}
		switch name := e.Name(); name {
		case "v1":
			if err := s.store("registry", filepath.Join(dir, "v1"), classifyRegistry); err != nil {
				return err
			}
		case "authz":
			sub, err := os.ReadDir(filepath.Join(dir, "authz"))
			if err != nil {
				return err
			}
			for _, a := range sub {
				if s.symlink("txe/authz/"+a.Name(), a) {
					continue
				}
				if a.Name() == "v1" {
					if err := s.store("authz", filepath.Join(dir, "authz", "v1"), classifyAuthz); err != nil {
						return err
					}
					continue
				}
				s.issue("unclassified_area", "", "txe/authz/"+a.Name(), "txe/authz/%s is not a known authorization store version; it was not read", a.Name())
			}
		case "locks":
			s.exclude("txe/locks", "lock files; operational")
		default:
			s.issue("unclassified_area", "", "txe/"+name, "txe/%s is not a known TXE store; it was not read", name)
		}
	}
	return nil
}

// store reads every record of a file collection rooted at dir.
func (s *scanner) store(store, dir string, classify func(id string, data []byte) (*Record, []Issue)) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// The file collection's own lock directories, as it skips them.
			if rel != "." && lockDirectoryName(d.Name()) {
				return s.lockDirectory(p, d.Name(), store+"/"+rel, "collection lock directory; operational")
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			s.issue("unsupported_record", ClassUnknown, store+"/"+rel, "%s/%s is not a regular file", store, rel)
			return nil
		}
		if !strings.HasSuffix(rel, ".json") {
			if strings.Contains(path.Base(rel), ".tmp") {
				s.exclude(store+"/"+rel, "interrupted atomic write; not a record")
				return nil
			}
			s.issue("unsupported_record", ClassUnknown, store+"/"+rel, "%s/%s is not a JSON record", store, rel)
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // a path under the scanned root
		if err != nil {
			return err
		}
		id := strings.TrimSuffix(rel, ".json")
		rec, issues := classify(id, data)
		rec.Store = store
		rec.ID = id
		if rec.SHA256 == "" {
			rec.SHA256 = recordDigest(data)
		}
		rec.Raw = rawDigest(data)
		for i := range issues {
			if issues[i].ID == "" {
				issues[i].ID = store + "/" + id
			}
		}
		s.inv.Records = append(s.inv.Records, *rec)
		s.inv.Issues = append(s.inv.Issues, issues...)
		return nil
	})
}

// files digests every file under rel as one area.
func (s *scanner) files(rel, policy string) error {
	base := filepath.Join(s.root.Path, filepath.FromSlash(rel))
	return filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		r, err := filepath.Rel(s.root.Path, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			// A process's lock directory (a file collection's record locks,
			// or a directory lock such as the scheduler's) belongs to the
			// process that holds it, and goes when it is released.
			if p != base && lockDirectoryName(d.Name()) {
				return s.lockDirectory(p, d.Name(), filepath.ToSlash(r), "lock directory; operational")
			}
			return nil
		}
		f := File{Root: s.root.Label, Path: filepath.ToSlash(r), Policy: policy}
		if hasModeBits {
			info, err := d.Info()
			if err != nil {
				return err
			}
			f.Mode = uint32(info.Mode().Perm())
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			f.Link = target
			s.inv.Files = append(s.inv.Files, f)
			return nil
		}
		if !d.Type().IsRegular() {
			s.issue("unsupported_file", "", s.root.Label+"/"+f.Path, "%s is not a regular file", f.Path)
			return nil
		}
		f.Size, f.SHA256, err = fileDigest(p)
		if err != nil {
			return err
		}
		s.inv.Files = append(s.inv.Files, f)
		return nil
	})
}

func (s *scanner) machineHome() error {
	entries, err := os.ReadDir(s.root.Path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if s.symlink(name, e) {
			continue
		}
		switch {
		case name == "machine.json":
			if err := s.machineIdentity(); err != nil {
				return err
			}
		case name == "packages":
			if err := s.packages(); err != nil {
				return err
			}
		default:
			if err := s.entry(name, e, machineHomeRules); err != nil {
				return err
			}
		}
	}
	if s.inv.Machines[s.root.Label] == "" {
		s.issue("machine_identity_missing", ClassMachineIdentity, s.root.Label+"/machine.json", "%s has no readable machine identity, so its packages cannot be checked against the jobs it runs; a worker cannot use it", s.root.Label)
	}
	return nil
}

// place names the kind of root being scanned, for issue details.
func (s *scanner) place() string {
	if s.root.Area == AreaHubData {
		return "the data directory"
	}
	return "a machine's TXE home"
}

// entry classifies one entry of a machine's TXE home, or of a rule-classified
// area of the data directory, by the first rule that matches it.
func (s *scanner) entry(rel string, e fs.DirEntry, rules []rule) error {
	r := ruleFor(rules, e.Name())
	if r == nil {
		if kept, err := s.kept(rel); err != nil || kept {
			return err
		}
		s.issue("unclassified_area", "", s.root.Label+"/"+rel, "%s/%s is not a known part of %s; classify it before a transition, it was not read", s.root.Label, rel, s.place())
		return nil
	}
	isLink := e.Type()&fs.ModeSymlink != 0
	if r.kind != kindLink && s.symlink(rel, e) {
		return nil
	}
	// The type comes from the directory entry, so an excluded entry is
	// checked without being opened.
	switch {
	case r.kind == kindDir && !e.IsDir(),
		r.kind == kindFile && !e.Type().IsRegular(),
		r.kind == kindLink && !isLink:
		s.issue("unsupported_file", "", s.root.Label+"/"+rel, "%s/%s is not the kind of entry its place in %s holds; it was not read", s.root.Label, rel, s.place())
		return nil
	}
	if r.exclude != "" {
		s.exclude(rel, r.exclude)
		return nil
	}
	if r.target != nil {
		target, err := os.Readlink(filepath.Join(s.root.Path, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if !r.target.MatchString(target) {
			s.issue("unsupported_file", "", s.root.Label+"/"+rel, "%s/%s links to %q, which is not where it may point", s.root.Label, rel, target)
			return nil
		}
	}
	if r.check != nil {
		data, err := os.ReadFile(filepath.Join(s.root.Path, filepath.FromSlash(rel))) //nolint:gosec // a path under the scanned root
		if err != nil {
			return err
		}
		if err := r.check(e.Name(), data); err != nil {
			s.issue("unsupported_file", "", s.root.Label+"/"+rel, "%s/%s is not what its place in %s holds (%v); it was not inventoried", s.root.Label, rel, s.place(), err)
			return nil
		}
	}
	if r.dir == nil {
		return s.files(rel, r.policy)
	}
	list, err := os.ReadDir(filepath.Join(s.root.Path, filepath.FromSlash(rel)))
	if err != nil {
		return err
	}
	for _, c := range list {
		if err := s.entry(rel+"/"+c.Name(), c, r.dir); err != nil {
			return err
		}
	}
	return nil
}

// lockDirectoryName reports whether name is reserved for a lock directory:
// a file collection's record locks (internal/persis/file/collection.go,
// recordLockDirectoryName) or a directory lock (internal/cmn/dirlock,
// LockDirectoryName and its releasing form).
func lockDirectoryName(name string) bool {
	return name == recordLockDirectoryName || dirlock.IsLockDirectoryName(name)
}

var lockBucketPattern = regexp.MustCompile(`^[0-9a-f]{2}$`)

// lockDirectory excludes a directory with a reserved lock name only when it
// has exactly the shape the backend writes, so a reserved name cannot hide
// retained data. A directory lock holds at most its owner file; record
// locks are two-hex-digit buckets of directory locks. Only names and types
// are listed, nothing is read. A directory of another shape blocks, unread.
// It returns filepath.SkipDir either way.
func (s *scanner) lockDirectory(p, name, rel, reason string) error {
	ok, err := lockShape(p, name)
	if err != nil {
		return err
	}
	if ok {
		s.exclude(rel, reason)
	} else {
		s.issue("unsupported_file", "", s.root.Label+"/"+rel, "%s/%s has a lock directory's name but not its shape; it was not read", s.root.Label, rel)
	}
	return filepath.SkipDir
}

func lockShape(p, name string) (bool, error) {
	entries, err := os.ReadDir(p)
	if err != nil {
		return false, err
	}
	if name == recordLockDirectoryName {
		for _, bucket := range entries {
			if !bucket.IsDir() || !lockBucketPattern.MatchString(bucket.Name()) {
				return false, nil
			}
			locks, err := os.ReadDir(filepath.Join(p, bucket.Name()))
			if err != nil {
				return false, err
			}
			for _, l := range locks {
				if !l.IsDir() || !dirlock.IsLockDirectoryName(l.Name()) {
					return false, nil
				}
				if ok, err := lockShape(filepath.Join(p, bucket.Name(), l.Name()), l.Name()); err != nil || !ok {
					return false, err
				}
			}
		}
		return true, nil
	}
	for _, e := range entries {
		// The lock's owner token (dirlock lockOwnerFileName).
		if e.Name() != "owner" || !e.Type().IsRegular() {
			return false, nil
		}
	}
	return true, nil
}

func fileDigest(p string) (int64, string, error) {
	f, err := os.Open(p) //nolint:gosec // a path under the scanned root
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// symlink reports, and refuses to follow, a directory entry that is a
// symbolic link: a link could lead the scan into a credential-bearing area.
func (s *scanner) symlink(rel string, e fs.DirEntry) bool {
	if e.Type()&fs.ModeSymlink == 0 {
		return false
	}
	s.issue("unsupported_file", "", s.root.Label+"/"+rel, "%s/%s is a symbolic link; links are not followed, so what it points to was not inventoried", s.root.Label, rel)
	return true
}

// regular reports whether p is a regular file, without following a link.
func regular(p string) (bool, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}
