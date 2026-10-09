// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// SpecSchema is the version of the job spec file format.
const SpecSchema = 1

// JobSpec is the file a creator writes to register or update a job. It holds
// everything a fresh reviewer needs to understand the job without the
// conversation that created it, and everything needed to package and run it.
type JobSpec struct {
	Schema int `yaml:"schema"`
	// JobKey is the creator's stable name for the logical job, unique within
	// the project. Registering the same key twice is refused as a duplicate.
	JobKey  string `yaml:"job_key"`
	Title   string `yaml:"title"`
	Purpose string `yaml:"purpose"`

	Project SpecProject `yaml:"project"`
	// ChatRef optionally points at the originating conversation. The job
	// must be understandable without it.
	ChatRef string `yaml:"chat_ref"`

	Targets  []Target     `yaml:"targets"`
	Schedule SpecSchedule `yaml:"schedule"`
	Package  SpecPackage  `yaml:"package"`
	// Env are literal, non-secret settings for the job's script.
	Env            map[string]string      `yaml:"env"`
	CredentialRefs []txepkg.CredentialRef `yaml:"credential_refs"`

	ExpectedOutcome ExpectedOutcome `yaml:"expected_outcome"`
	Lifetime        SpecLifetime    `yaml:"lifetime"`
	RetirementRules RetirementRules `yaml:"retirement_rules"`
	ReviewPolicy    ReviewPolicy    `yaml:"review_policy"`

	// dir is the directory of the file the spec was read from.
	dir string
}

// SpecProject overrides the project a job belongs to. By default the project
// is the repository the package is built from.
type SpecProject struct {
	Key  string `yaml:"key"`
	Name string `yaml:"name"`
}

// SpecSchedule is when and within what bounds the job runs.
type SpecSchedule struct {
	Cron             string `yaml:"cron"`
	Timezone         string `yaml:"timezone"`
	TimeoutSec       int    `yaml:"timeout_sec"`
	Overlap          string `yaml:"overlap"`
	Retry            int    `yaml:"retry"`
	RetryIntervalSec int    `yaml:"retry_interval_sec"`
	CatchupWindow    string `yaml:"catchup_window"`
}

// SpecPackage names the files the job needs and the command it runs.
type SpecPackage struct {
	// SourceRoot is the directory Include paths are relative to. A relative
	// value is resolved against the spec file's directory, which is also the
	// default.
	SourceRoot string   `yaml:"source_root"`
	Include    []string `yaml:"include"`
	Entrypoint []string `yaml:"entrypoint"`
	Runtimes   []string `yaml:"runtimes"`
}

// SpecLifetime bounds the job in time. Exactly one field is set: an expiry,
// or an explicit statement that the job has none.
type SpecLifetime struct {
	ExpiresAt string `yaml:"expires_at"`
	OpenEnded bool   `yaml:"open_ended"`
}

// LoadJobSpec reads and validates a job spec file. Unknown keys are refused,
// so a misspelt field is not silently dropped.
func LoadJobSpec(path string) (*JobSpec, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the caller names the spec file
	if err != nil {
		return nil, fmt.Errorf("read job spec: %w", err)
	}
	var spec JobSpec
	if err := yaml.UnmarshalWithOptions(data, &spec, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("parse job spec %s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	spec.dir = filepath.Dir(abs)
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return &spec, nil
}

// SourceRoot returns the absolute directory the package is built from.
func (s *JobSpec) SourceRoot() string {
	root := s.Package.SourceRoot
	if root == "" {
		return s.dir
	}
	if filepath.IsAbs(root) {
		return filepath.Clean(root)
	}
	return filepath.Join(s.dir, root)
}

// MissingContextError lists everything a job spec lacks. Registration is
// refused until the list is empty.
type MissingContextError struct {
	Problems []string
}

func (e *MissingContextError) Error() string {
	return "the job spec is incomplete:\n  - " + strings.Join(e.Problems, "\n  - ")
}

var (
	jobKeyPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,62}$`)
	deliverableNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	// deliverableSegmentPattern is one directory or file name of a
	// deliverable's path. It cannot start with a dot, so "." and ".." and
	// the names the publish step copies under are all outside it.
	deliverableSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	// deviceNamePattern is a name Windows reserves, with or without an
	// extension. The hub may store its copies on any filesystem.
	deviceNamePattern = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`)
)

// maxDeliverablePath is the longest deliverable path, in bytes.
const maxDeliverablePath = 1024

// CheckDeliverablePath accepts only the exact name of a file inside the run's
// output directory. It is the registry's rule, so a spec the CLI accepts is
// not refused by the hub for its paths: "/"-separated names of letters,
// digits, dot, dash and underscore that start with a letter, digit or
// underscore. The cases both sides agree on are in
// txe/contract/fixtures/registration/deliverable-paths.json.
func CheckDeliverablePath(path string) error {
	switch {
	case path == "":
		return errors.New("a file name relative to the run's output directory is required")
	case len(path) > maxDeliverablePath:
		return fmt.Errorf("the path is %d bytes long; the limit is %d", len(path), maxDeliverablePath)
	case strings.HasPrefix(path, "/") || strings.HasPrefix(path, "~"):
		return fmt.Errorf("%q must be relative to the run's output directory", path)
	}
	if first, _, _ := strings.Cut(path, "/"); strings.EqualFold(first, HubAttemptsDir) {
		return fmt.Errorf("%q: the name %q is reserved for the hub's copies", path, HubAttemptsDir)
	}
	for part := range strings.SplitSeq(path, "/") {
		switch {
		case part == "" || part == "." || part == "..":
			return fmt.Errorf("%q must not contain empty, \".\" or \"..\" components", path)
		case !deliverableSegmentPattern.MatchString(part):
			return fmt.Errorf("%q: each name must start with a letter, digit or underscore, use only letters, digits, dot, dash and underscore, and be at most 128 characters", path)
		case strings.HasSuffix(part, "."):
			return fmt.Errorf("%q: a name must not end with a dot", path)
		case deviceNamePattern.MatchString(part):
			return fmt.Errorf("%q: %q is a reserved device name", path, part)
		}
	}
	return nil
}

// Validate checks that the spec carries the context a job needs to outlive
// its creating session. It reports every problem at once.
func (s *JobSpec) Validate() error {
	var problems []string
	need := func(ok bool, format string, args ...any) {
		if !ok {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}

	need(s.Schema == SpecSchema, "schema must be %d", SpecSchema)
	need(jobKeyPattern.MatchString(s.JobKey),
		"job_key is required: a stable lowercase name for this job within its project, 3 to 63 characters of a-z, 0-9, dot, dash or underscore")
	need(strings.TrimSpace(s.Title) != "", "title is required")
	need(strings.TrimSpace(s.Purpose) != "",
		"purpose is required: say what the job is for, so a reviewer who never saw this conversation can judge its results")

	need(len(s.Targets) > 0,
		"targets needs at least one entry: the resource this job watches or acts on, by kind and stable_id")
	for i, t := range s.Targets {
		need(t.Kind != "", "targets[%d].kind is required", i)
		need(len(t.StableID) > 0,
			"targets[%d].stable_id is required: an identity that does not change when a resource is renamed or recreated, such as a UID", i)
		for key, value := range t.StableID {
			need(key != "" && value != "", "targets[%d].stable_id has an empty key or value", i)
		}
	}

	need(s.Schedule.Cron != "", "schedule.cron is required")
	need(s.Schedule.Timezone != "", "schedule.timezone is required")
	need(s.Schedule.TimeoutSec > 0, "schedule.timeout_sec is required")

	need(len(s.Package.Include) > 0, "package.include is required: the files the job needs, uncommitted ones included")
	need(len(s.Package.Entrypoint) > 0, "package.entrypoint is required")

	need(len(s.ExpectedOutcome.SuccessCriteria) > 0,
		"expected_outcome.success_criteria needs at least one entry: what a good result looks like")

	names := map[string]bool{}
	for i, d := range s.ExpectedOutcome.Deliverables {
		need(deliverableNamePattern.MatchString(d.Name),
			"expected_outcome.deliverables[%d].name is required: lowercase letters, digits, dot, dash or underscore", i)
		need(!names[d.Name], "expected_outcome.deliverables[%d].name %q is used twice", i, d.Name)
		names[d.Name] = true
		if err := CheckDeliverablePath(d.Path); err != nil {
			need(false, "expected_outcome.deliverables[%d].path: %v", i, err)
		}
		need(d.Delivery == "" || d.Delivery == DeliveryMachine || d.Delivery == DeliveryHub,
			"expected_outcome.deliverables[%d].delivery must be %q or %q, got %q", i, DeliveryMachine, DeliveryHub, d.Delivery)
	}

	switch {
	case s.Lifetime.ExpiresAt != "" && s.Lifetime.OpenEnded:
		need(false, "lifetime sets both expires_at and open_ended; choose one")
	case s.Lifetime.ExpiresAt != "":
		_, err := time.Parse(time.RFC3339, s.Lifetime.ExpiresAt)
		need(err == nil, "lifetime.expires_at %q is not an RFC 3339 time such as 2027-01-31T00:00:00Z", s.Lifetime.ExpiresAt)
	case !s.Lifetime.OpenEnded:
		need(false, "lifetime is required: set expires_at, or open_ended: true if the job really has no end date")
	}

	need(strings.TrimSpace(s.ReviewPolicy.Brief) != "",
		"review_policy.brief is required: what a reviewer should look for and what it may do")
	need(s.ReviewPolicy.Cadence != "", "review_policy.cadence is required: how often results are reviewed, as a cron expression")
	for i, a := range s.ReviewPolicy.PermittedActions {
		need(a.Name != "", "review_policy.permitted_actions[%d].name is required", i)
		need(a.TimeoutSec > 0, "review_policy.permitted_actions[%d].timeout_sec is required", i)
	}

	if len(problems) > 0 {
		return &MissingContextError{Problems: problems}
	}
	return nil
}

// expiresAt returns the lifetime's expiry, or nil for an open-ended job.
func (s *JobSpec) expiresAt() (*time.Time, error) {
	if s.Lifetime.ExpiresAt == "" {
		return nil, nil //nolint:nilnil // no expiry is a valid lifetime
	}
	t, err := time.Parse(time.RFC3339, s.Lifetime.ExpiresAt)
	if err != nil {
		return nil, errors.New("lifetime.expires_at is not an RFC 3339 time")
	}
	return &t, nil
}

// missedRun describes the missed-run policy for a reviewer to read.
func (s SpecSchedule) missedRun() string {
	if s.CatchupWindow == "" {
		return "skip"
	}
	return "catch up within " + s.CatchupWindow
}
