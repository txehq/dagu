// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Command txe-review-fixture runs the reviewer's steps against a file-backed
// fixture registry. It exists so the reviewer DAGs can be exercised with a
// real Dagu and a real agent CLI before, and independently of, a deployed
// TXE registry. It is test tooling and is not shipped in the dagu binary.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/review/reviewtest"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "txe-review-fixture:", err)
		os.Exit(1)
	}
}

type options struct {
	registry, stateDir, machine, dagu, runID      string
	job, proposal, decision, verdict, instruction string
	file, agentClient, agentLog, authCheck        string
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: txe-review-fixture <prepare|apply|execute|render|put-job|add-run|decide|dump> [flags]")
	}
	var o options
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.StringVar(&o.registry, "registry", os.Getenv("TXE_FIXTURE_REGISTRY"), "fixture registry file")
	fs.StringVar(&o.stateDir, "state-dir", os.Getenv("TXE_FIXTURE_STATE_DIR"), "durable local state directory")
	fs.StringVar(&o.machine, "machine", os.Getenv("TXE_FIXTURE_MACHINE"), "machine id")
	fs.StringVar(&o.dagu, "dagu", os.Getenv("TXE_FIXTURE_DAGU"), "dagu binary used to enqueue decision runs")
	fs.StringVar(&o.agentClient, "agent-client", os.Getenv("TXE_FIXTURE_AGENT_CLIENT"), "agent CLI name and version")
	fs.StringVar(&o.runID, "run-id", "", "DAG run id")
	fs.StringVar(&o.job, "job", "", "job id")
	fs.StringVar(&o.proposal, "proposal", "", "proposal id")
	fs.StringVar(&o.decision, "decision", "", "decision id")
	fs.StringVar(&o.verdict, "verdict", "", "human verdict")
	fs.StringVar(&o.instruction, "instructions", "", "human instructions")
	fs.StringVar(&o.file, "file", "", "JSON input file")
	fs.StringVar(&o.agentLog, "agent-log", "", "agent step stderr log")
	fs.StringVar(&o.authCheck, "auth-check", "", "agent login status command")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if remote := os.Getenv("TXE_FIXTURE_REMOTE"); remote != "" {
		return runRemote(ctx, args[0], o, remote)
	}
	if o.registry == "" {
		return errors.New("--registry or TXE_FIXTURE_REGISTRY is required")
	}
	reg := reviewtest.Open(o.registry)
	steps := &review.Steps{
		MachineID:   o.machine,
		StateDir:    o.stateDir,
		AuthCheck:   strings.Fields(o.authCheck),
		ArtifactDir: os.Getenv("DAG_RUN_ARTIFACTS_DIR"),
		Reviewer: &review.Reviewer{
			Registry:    reg,
			Effector:    &review.CommandEffector{},
			Opener:      &review.RunOpener{Enqueue: enqueue(o.dagu), Complete: complete(o.dagu)},
			Holder:      fmt.Sprintf("%s/%s", o.machine, o.runID),
			AgentClient: o.agentClient,
			DecideDAG:   review.DecideDAGName(o.machine),
		},
	}

	switch args[0] {
	case "prepare":
		return steps.Prepare(ctx, o.runID, os.Stdout)
	case "apply":
		return steps.Apply(ctx, o.runID, os.Stdin, o.agentLog, os.Stdout)
	case "execute":
		return steps.Execute(ctx, o.job, o.proposal, o.decision, os.Stdout)
	case "render":
		return render(o)
	case "put-job":
		var job review.Job
		if err := readJSON(o.file, &job); err != nil {
			return err
		}
		return reg.PutJob(job)
	case "add-run":
		var runEvidence review.RunEvidence
		if err := readJSON(o.file, &runEvidence); err != nil {
			return err
		}
		return reg.AddRun(o.job, runEvidence)
	case "decide":
		d, err := reg.Decide(o.job, o.proposal, review.Verdict(o.verdict), o.instruction, "fixture-human")
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(d)
	case "dump":
		var out []byte
		reg.View(func(s *reviewtest.State) { out, _ = json.MarshalIndent(s, "", "  ") })
		_, err := os.Stdout.Write(append(out, '\n'))
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func render(o options) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dags, err := review.RenderDAGs(review.DAGConfig{
		MachineID:     o.machine,
		StateDir:      o.stateDir,
		ReviewCommand: self,
		Schedule:      "0 0 1 1 *",
		Env: map[string]string{
			"TXE_FIXTURE_REGISTRY":     o.registry,
			"TXE_FIXTURE_STATE_DIR":    o.stateDir,
			"TXE_FIXTURE_MACHINE":      o.machine,
			"TXE_FIXTURE_DAGU":         o.dagu,
			"TXE_FIXTURE_AGENT_CLIENT": o.agentClient,
			"DAGU_HOME":                os.Getenv("TXE_FIXTURE_DAGU_HOME"),
			"TXE_FIXTURE_REMOTE":       os.Getenv("TXE_FIXTURE_REMOTE"),
		},
		AgentConfigDir: os.Getenv("CLAUDE_CONFIG_DIR"),
		AgentModel:     os.Getenv("TXE_FIXTURE_AGENT_MODEL"),
	})
	if err != nil {
		return err
	}
	for name, doc := range map[string]string{dags.ReviewerName: dags.Reviewer, dags.DecideName: dags.Decide} {
		path := filepath.Join(o.file, name+".yaml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			return err
		}
		fmt.Println(path)
	}
	return nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// complete completes a waiting human task through the dagu CLI of the
// fixture home.
func complete(dagu string) review.CompleteFunc {
	return func(ctx context.Context, task review.TaskLocator, input map[string]string) error {
		if dagu == "" {
			return nil
		}
		args := []string{"human-task", "complete", "--run-id", task.RunID, "--step", task.StepID}
		names := make([]string, 0, len(input))
		for name := range input {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			args = append(args, "--input", name+"="+input[name])
		}
		args = append(args, task.DAG)
		// #nosec G204 -- fixture tooling; the binary path is the operator's.
		out, err := exec.CommandContext(ctx, dagu, args...).CombinedOutput()
		if err != nil {
			text := string(out)
			if strings.Contains(text, "different input") {
				return review.ErrTaskAnswered
			}
			if strings.Contains(text, "not found") {
				return review.ErrRunMissing
			}
			return fmt.Errorf("dagu human-task complete: %w: %s", err, out)
		}
		return nil
	}
}

// enqueue opens a decision run through the dagu CLI of the fixture home.
func enqueue(dagu string) review.EnqueueFunc {
	return func(ctx context.Context, dag, runID string, params map[string]string) error {
		if dagu == "" {
			return errors.New("--dagu or TXE_FIXTURE_DAGU is required to open a decision")
		}
		args := []string{"enqueue", "--run-id", runID, dag, "--"}
		names := make([]string, 0, len(params))
		for name := range params {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			args = append(args, name+"="+params[name])
		}
		// #nosec G204 -- fixture tooling; the binary path is the operator's.
		out, err := exec.CommandContext(ctx, dagu, args...).CombinedOutput()
		if strings.Contains(string(out), "already exists") {
			return review.ErrRunExists
		}
		if err != nil {
			return fmt.Errorf("dagu enqueue: %w: %s", err, out)
		}
		return nil
	}
}

// runRemote runs a review step against a real service: the TXE registry and
// the run history behind its HTTP API. Only the step commands exist in this
// mode; the job is registered and decided through the service itself.
func runRemote(ctx context.Context, command string, o options, base string) error {
	t := httpTransport{base: strings.TrimRight(base, "/")}
	remote := &review.Remote{Transport: t, MachineID: o.machine, RunID: o.runID, AgentClient: o.agentClient}
	steps := &review.Steps{
		MachineID:   o.machine,
		StateDir:    o.stateDir,
		AuthCheck:   strings.Fields(o.authCheck),
		ArtifactDir: os.Getenv("DAG_RUN_ARTIFACTS_DIR"),
		Reviewer: &review.Reviewer{
			Registry:    remote,
			Effector:    &review.CommandEffector{},
			Opener:      &review.RunOpener{Enqueue: review.RemoteEnqueue(t), Complete: review.RemoteComplete(t)},
			Holder:      fmt.Sprintf("%s/%s", o.machine, o.runID),
			AgentClient: o.agentClient,
			DecideDAG:   review.DecideDAGName(o.machine),
		},
	}
	switch command {
	case "prepare":
		return steps.Prepare(ctx, o.runID, os.Stdout)
	case "apply":
		return steps.Apply(ctx, o.runID, os.Stdin, o.agentLog, os.Stdout)
	case "execute":
		return steps.Execute(ctx, o.job, o.proposal, o.decision, os.Stdout)
	case "render":
		return render(o)
	default:
		return fmt.Errorf("command %q is not available against a real service", command)
	}
}

// httpTransport is a plain JSON client for a service without authentication,
// as a disposable local hub runs.
type httpTransport struct {
	base string
}

func (h httpTransport) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		var e struct {
			Message string `json:"message"`
			Details struct {
				Code string `json:"code"`
			} `json:"details"`
		}
		_ = json.Unmarshal(raw, &e)
		return &review.TransportError{Status: resp.StatusCode, Code: e.Details.Code, Message: e.Message}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}
