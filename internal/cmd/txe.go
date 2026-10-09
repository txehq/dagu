// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// txeContextName is the CLI context the worker installer creates for the hub.
const txeContextName = "txe"

// txeLocalAnnotation marks a subcommand that works without the hub.
const txeLocalAnnotation = "txe.local"

var (
	txeJSONFlag = commandLineFlag{
		name:   "json",
		usage:  "Print the result as JSON",
		isBool: true,
	}
	txeSessionFlag = commandLineFlag{
		name:  "session",
		usage: "Coding session making the change, such as cc2-s855054 (default: derived from the environment, or TXE_SESSION)",
	}
	txeSpecFlag = commandLineFlag{
		name:      "file",
		shorthand: "f",
		usage:     "Job spec file",
		required:  true,
	}
)

// txeSubcommands builds subcommands owned by other parts of the integration.
// A file adds its command here from an init function, so the root does not
// change when one is added.
var txeSubcommands []func() *cobra.Command

// TXE returns the command for the TXE job registry: durable jobs that outlive
// the coding session and worktree that created them.
func TXE() *cobra.Command {
	root := NewCommand(&cobra.Command{
		Use:   "txe",
		Short: "Register and inspect durable jobs that outlive a coding session",
		Long: `Register and inspect durable jobs in the TXE job registry.

A job is a script packaged outside any worktree, a schedule, and the context a
later reviewer needs: purpose, targets, expected outcome, lifetime and review
policy. The hub schedules it; this machine's worker runs it.

These commands use the "txe" context in the TXE home's own context store
(~/.local/share/txe-dagu/client) unless --context or --dagu-home says otherwise.`,
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	root.PersistentPreRunE = txeDefaults

	for _, sub := range []*cobra.Command{
		txeDoctorCommand(),
		txeRegisterCommand(),
		txeUpdateCommand(),
		txeResumeCommand(),
		txeListCommand(),
		txeInspectCommand(),
		txePackageCommand(),
	} {
		root.AddCommand(sub)
	}
	for _, build := range txeSubcommands {
		root.AddCommand(build())
	}
	return root
}

// isTXECommand reports whether cmd is the txe command or one beneath it.
func isTXECommand(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Name() == "txe" && current.Parent() != nil && current.Parent().Parent() == nil {
			return true
		}
	}
	return false
}

// txeDefaults points a txe command at the TXE home's context store and the
// hub's context, unless the caller chose otherwise.
func txeDefaults(cmd *cobra.Command, _ []string) error {
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	if flag := cmd.Flags().Lookup("dagu-home"); flag != nil && !flag.Changed && os.Getenv("DAGU_HOME") == "" {
		if err := cmd.Flags().Set("dagu-home", home.ClientDir()); err != nil {
			return err
		}
	}
	if cmd.Annotations[txeLocalAnnotation] != "" {
		return nil
	}
	if flag := cmd.Flags().Lookup("context"); flag != nil && !flag.Changed {
		if err := cmd.Flags().Set("context", txeContextName); err != nil {
			return err
		}
	}
	return nil
}

// txeClient returns a registry client for the command's remote context. Other
// txe subcommands build their own calls on its Do method.
func txeClient(ctx *Context) (*txeclient.Client, error) {
	remote, err := txeRemote(ctx)
	if err != nil {
		return nil, err
	}
	return txeclient.New(remote.baseURL, remote.apiKey, remote.client), nil
}

// txeRemote returns the hub connection: the command's remote context, or for
// a command that also works without the hub, the "txe" context if it exists.
func txeRemote(ctx *Context) (*remoteClient, error) {
	if ctx.IsRemote() {
		return ctx.Remote, nil
	}
	if ctx.Command.Annotations[txeLocalAnnotation] == "" || ctx.ContextStore == nil {
		return nil, fmt.Errorf("this command talks to the hub: use the %q context (the default) or name another with --context", txeContextName)
	}
	hub, err := ctx.ContextStore.Get(ctx, txeContextName)
	if err != nil {
		return nil, fmt.Errorf("no %q context in %s: %w", txeContextName, ctx.Config.Paths.ContextsDir, err)
	}
	return newRemoteClient(hub)
}

var claudeConfigDir = regexp.MustCompile(`^\.claude([0-9]*)$`)

// txeSession returns the coding session to record as the author of a change:
// the --session flag, TXE_SESSION, or cc<n>-<workspace> derived for a Claude
// Code session. It is never guessed: when none applies the result is empty.
func txeSession(ctx *Context) string {
	if value, err := ctx.StringParam("session"); err == nil && value != "" {
		return value
	}
	if value := os.Getenv("TXE_SESSION"); value != "" {
		return value
	}
	match := claudeConfigDir.FindStringSubmatch(filepath.Base(filepath.Clean(os.Getenv("CLAUDE_CONFIG_DIR"))))
	if match == nil {
		return ""
	}
	workspace := ""
	if os.Getenv("TMUX") != "" {
		if out, err := exec.CommandContext(ctx, "tmux", "display-message", "-p", "#S").Output(); err == nil {
			workspace = strings.ToLower(strings.TrimSpace(string(out)))
		}
	} else if id := os.Getenv("CLAUDE_CODE_SESSION_ID"); len(id) >= 6 {
		workspace = "s" + id[:6]
	}
	if workspace == "" {
		return ""
	}
	return "cc" + match[1] + "-" + workspace
}

// txeRegistrar builds the registrar for a command that changes a job. The
// session must be known: every change records who made it, apart from who
// owns the job.
func txeRegistrar(ctx *Context) (*txeclient.Registrar, error) {
	client, err := txeClient(ctx)
	if err != nil {
		return nil, err
	}
	home, err := txepkg.DefaultHome()
	if err != nil {
		return nil, err
	}
	session := txeSession(ctx)
	if session == "" {
		return nil, errors.New("cannot tell which session is making this change; pass --session or set TXE_SESSION")
	}
	machine, err := home.Machine()
	if err != nil {
		return nil, err
	}
	return &txeclient.Registrar{
		Client:  client,
		Home:    home,
		Store:   txepkg.NewStore(home),
		Journal: txepkg.NewJournal(home),
		Actor: txeclient.Actor{
			Kind: txeclient.ActorKindCLI, ID: "cli", Session: session,
			MachineID: machine.MachineID, Client: "dagu " + config.Version,
		},
		NewID: txeclient.NewID,
	}, nil
}

// txePrinter writes human-readable output and keeps the first write error.
//
// Every value it formats is cleaned first. Much of what these commands show
// was stored by another session, and none of it may reach the terminal as
// control characters or pass for a line of the command's own output.
type txePrinter struct {
	w   io.Writer
	err error
}

// f formats like fmt.Fprintf, with every argument cleaned. The format string
// is the command's own text.
func (p *txePrinter) f(format string, args ...any) {
	if p.err != nil {
		return
	}
	for i, arg := range args {
		args[i] = txeCleanValue(arg)
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

// block prints text the command laid out itself, such as a rendered DAG:
// line breaks are kept, anything else unsafe is still escaped.
func (p *txePrinter) block(text string) {
	if p.err == nil {
		_, p.err = io.WriteString(p.w, txeclient.CleanText(text, true))
	}
}

func txeCleanValue(v any) any {
	switch value := v.(type) {
	case string:
		return txeclient.CleanText(value, false)
	case []string:
		out := make([]string, len(value))
		for i, s := range value {
			out[i] = txeclient.CleanText(s, false)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(value))
		for k, s := range value {
			out[txeclient.CleanText(k, false)] = txeclient.CleanText(s, false)
		}
		return out
	case error:
		return txeclient.CleanText(value.Error(), false)
	case fmt.Stringer:
		return txeclient.CleanText(value.String(), false)
	default:
		return v
	}
}

// txeOutput prints a result: as indented JSON with --json, otherwise through
// the given function.
func txeOutput(ctx *Context, value any, human func(p *txePrinter)) error {
	out := ctx.Command.OutOrStdout()
	asJSON, err := ctx.Command.Flags().GetBool("json")
	if err != nil {
		return err
	}
	if !asJSON {
		p := &txePrinter{w: out}
		human(p)
		return p.err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(value)
}

// txeFailure describes a refused or unfinished change for --json output, so a
// caller can tell the cases apart without reading prose.
type txeFailure struct {
	OK        bool            `json:"ok"`
	Kind      string          `json:"kind"`
	Message   string          `json:"message"`
	RequestID string          `json:"request_id,omitempty"`
	JobID     string          `json:"job_id,omitempty"`
	Problems  []string        `json:"problems,omitempty"`
	Current   json.RawMessage `json:"current,omitempty"`
}

// txeReportFailure prints err in structured form when --json is set, and
// returns it so the command still exits non-zero.
func txeReportFailure(ctx *Context, err error) error {
	asJSON, flagErr := ctx.Command.Flags().GetBool("json")
	if flagErr != nil || !asJSON {
		return err
	}
	failure := txeFailure{Kind: "error", Message: err.Error()}
	var (
		missing    *txeclient.MissingContextError
		exists     *txeclient.ErrJobExists
		rejected   *txeclient.ErrRejected
		incomplete *txeclient.ErrIncomplete
	)
	switch {
	case errors.As(err, &missing):
		failure.Kind, failure.Problems = "missing_context", missing.Problems
	case errors.As(err, &exists):
		failure.Kind, failure.JobID, failure.Current = "duplicate", exists.Job.JobID, exists.Job.Raw
	case errors.As(err, &rejected):
		failure.Kind, failure.RequestID, failure.Current = rejected.Refusal.Code, rejected.RequestID, rejected.Refusal.Current
		if failure.Kind == "" {
			failure.Kind = "rejected"
		}
	case errors.As(err, &incomplete):
		failure.Kind, failure.RequestID = "incomplete", incomplete.RequestID
	case errors.Is(err, txeclient.ErrReviewerSession):
		failure.Kind = "reviewer_session"
	}
	enc := json.NewEncoder(ctx.Command.OutOrStdout())
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(failure)
	return err
}
