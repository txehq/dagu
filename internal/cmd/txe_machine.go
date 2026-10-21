// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

var (
	txeMachineDisplayNameFlag = commandLineFlag{name: "display-name",
		usage: "The machine's name in the hub (default: this computer's name). Used only when the machine has no identity yet"}
	txeMachineOwnerFlag = commandLineFlag{name: "owner-id",
		usage: "The owner the machine must belong to: the command stops unless it is this sign-in's owner"}
)

func init() {
	txeSubcommands = append(txeSubcommands, txeMachineCommand)
}

func txeMachineCommand() *cobra.Command {
	command := NewCommand(&cobra.Command{
		Use:   "machine",
		Short: "This machine's record in the hub",
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "create",
		Short: "Record this machine in the hub for the signed-in owner",
		Long: `Record this machine in the hub, for the owner of the person signed in with
"dagu txe login". Run it once per machine, before "dagu txe enrol" and before
registering a job: both need the hub to know the machine.

The owner is the sign-in's, as the hub reports it (GET /api/v1/txe/identity).
--owner-id only checks it: the command stops if it names another owner.

The machine's identity is machine.json in the TXE home. If it exists, its
machine id is used and it is never changed; if it belongs to another owner,
the command stops. If it does not exist, a new machine id is minted and
machine.json is written first, the way the worker installer writes it, so the
worker installer later keeps it. Then the hub is asked to create the record.
Running the command again is safe: the hub returns the existing record of the
same machine and owner.

Only the sign-in is sent, never the context's API key.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeMachineDisplayNameFlag, txeMachineOwnerFlag, txeJSONFlag}, runTXEMachineCreate))
	return command
}

// txeMachineCreated is what machine create shows.
type txeMachineCreated struct {
	MachineID   string `json:"machine_id"`
	OwnerID     string `json:"owner_id"`
	DisplayName string `json:"display_name,omitempty"`
	// IdentityFile is machine.json, and IdentityWritten whether this run wrote it.
	IdentityFile    string `json:"identity_file"`
	IdentityWritten bool   `json:"identity_written"`
}

func runTXEMachineCreate(ctx *Context, _ []string) error {
	if txeInDAGStep() {
		return errors.New("a machine is recorded by a person of its owner; it is never done from a DAG step")
	}
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	assertOwner, err := ctx.StringParam("owner-id")
	if err != nil {
		return err
	}
	if assertOwner != "" {
		if err := registry.ValidateID(registry.PrefixOwner, assertOwner); err != nil {
			return fmt.Errorf("--owner-id: %w", err)
		}
	}
	displayName, err := ctx.StringParam("display-name")
	if err != nil {
		return err
	}
	remote, err := txeRemoteContext(ctx)
	if err != nil {
		return err
	}
	signedIn, err := txeMachineSignIn(ctx, remote)
	if err != nil {
		return err
	}
	owner, err := txeMachineOwner(ctx, signedIn)
	if err != nil {
		return err
	}
	if assertOwner != "" && assertOwner != owner {
		return fmt.Errorf("--owner-id %s is not this sign-in's owner (%s): sign in as a person of %s", assertOwner, owner, assertOwner)
	}

	machine, written, err := txeMachineIdentity(ctx, home, owner, displayName)
	if err != nil {
		return err
	}
	body := map[string]any{
		"machine_id": machine.MachineID, "owner_id": machine.OwnerID, "display_name": machine.DisplayName,
		"actor": txeclient.Actor{Kind: txeclient.ActorKindCLI, ID: "cli", Session: txeSession(ctx),
			MachineID: machine.MachineID, Client: txeClientVersion()},
	}
	var out struct {
		MachineID   string `json:"machine_id"`
		OwnerID     string `json:"owner_id"`
		DisplayName string `json:"display_name"`
	}
	err = signedIn.do(ctx, http.MethodPost, "/txe/machines", body, &out, nil)
	if rerr, ok := errors.AsType[*remoteError](err); ok {
		switch {
		case rerr.StatusCode == http.StatusConflict:
			return fmt.Errorf("the hub refused machine %s: its id is already in use (%s); machine.json was not changed", machine.MachineID, rerr.Message)
		case rerr.StatusCode == http.StatusForbidden && rerr.Detail == "unbound":
			return fmt.Errorf("the hub refused machine %s: it now takes this sign-in as acting for no owner, though it said a moment ago it acts for %s; run \"dagu txe whoami\", and ask an administrator to bind you if it says unbound", machine.MachineID, owner)
		case rerr.StatusCode == http.StatusForbidden:
			return fmt.Errorf("the hub refused to record machine %s for owner %s, though it binds this sign-in to that owner (%s); run \"dagu txe whoami\" and report the mismatch", machine.MachineID, owner, rerr.Message)
		}
	}
	if err != nil {
		return fmt.Errorf("create machine %s in the hub: %w", machine.MachineID, err)
	}
	if out.MachineID != machine.MachineID || out.OwnerID != machine.OwnerID {
		return fmt.Errorf("the hub answered with machine %s of owner %s, not machine %s of owner %s", out.MachineID, out.OwnerID, machine.MachineID, machine.OwnerID)
	}
	view := txeMachineCreated{MachineID: out.MachineID, OwnerID: out.OwnerID, DisplayName: out.DisplayName,
		IdentityFile: filepath.Join(home.Root, "machine.json"), IdentityWritten: written}
	return txeOutput(ctx, view, func(p *txePrinter) {
		if written {
			p.f("wrote %s\n", view.IdentityFile)
		}
		p.f("machine %s is recorded in the hub for owner %s\n", view.MachineID, view.OwnerID)
		p.f("Next: install the worker, then enrol it with: dagu txe enrol --client-id <this machine's worker client>\n")
	})
}

// txeMachineSignIn returns the hub connection carrying the person's sign-in
// on the machine routes. A machine is created only with a sign-in, never the
// context's API key: a legacy key acts for no owner, so the record would not
// be tied to one. With no sign-in, or one the hub takes only to say who it
// is, nothing is sent. The returned connection holds no API key, so no route
// can fall back to it.
func txeMachineSignIn(ctx *Context, remote *remoteClient) (*remoteClient, error) {
	authed, err := txeHubAuth(ctx, remote)
	if err != nil {
		return nil, err
	}
	if authed == remote {
		return nil, errors.New(`this machine is not signed in to the hub: run "dagu txe login --hub <the hub's address>" first`)
	}
	if authed.signInUse != cliauth.HubUseTxe && authed.signInUse != cliauth.HubUseAll {
		return nil, fmt.Errorf("the hub takes this CLI's sign-in only to say who it is (use %q), so it cannot record a machine with it", authed.signInUse)
	}
	signedIn := *authed
	signedIn.apiKey = ""
	return &signedIn, nil
}

// txeMachineOwner is the owner the hub binds this sign-in to. Only a
// person's sign-in, through the browser or this CLI, bound to exactly one
// owner can record a machine: those are the classes the hub lets author an
// owner's data. A machine's own worker or reviewer credential cannot.
//
// This check spares a request the hub would refuse; it is not what refuses
// it. The hub holds a person and a provider token to their owner in every
// mode.
func txeMachineOwner(ctx *Context, signedIn *remoteClient) (string, error) {
	var who txeHubIdentity
	if err := signedIn.do(ctx, http.MethodGet, cliauth.HubIdentityPath, nil, &who, nil); err != nil {
		return "", fmt.Errorf("ask the hub who this sign-in is: %w", err)
	}
	if class := who.Principal.Class; class != "person" && class != "cli" {
		return "", fmt.Errorf(`the hub takes this sign-in as a %q caller, not a person: sign in with "dagu txe login" as a person of the machine's owner`, class)
	}
	if who.State != "bound" || len(who.Owners) != 1 {
		reason := who.Scope.UnboundReason
		if reason == "" {
			reason = who.State
		}
		return "", fmt.Errorf("the hub binds this sign-in to no single owner (%s): ask an administrator to add you to your owner, then run this again", reason)
	}
	owner := who.Owners[0].OwnerID
	if err := registry.ValidateID(registry.PrefixOwner, owner); err != nil {
		return "", fmt.Errorf("the hub named owner %q: %w", owner, err)
	}
	return owner, nil
}

// txeMachineIdentity returns this machine's identity for owner, and whether
// this call wrote it. An existing identity is used as it is, and only if it
// is the owner's; a missing one is minted and published, and when another
// process publishes first, that one is used.
func txeMachineIdentity(ctx context.Context, home txepkg.Home, owner, displayName string) (*txepkg.Machine, bool, error) {
	machine, err := home.Machine()
	written := false
	if errors.Is(err, txepkg.ErrNoMachine) {
		if displayName == "" {
			displayName = txeComputerName(ctx)
		}
		id, mintErr := registry.NewID(registry.PrefixMachine, time.Now())
		if mintErr != nil {
			return nil, false, mintErr
		}
		err = home.PublishMachine(txepkg.Machine{Schema: 1, MachineID: id, OwnerID: owner, DisplayName: displayName}, time.Now())
		written = err == nil
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, false, err
		}
		machine, err = home.Machine()
	}
	if err != nil {
		return nil, false, err
	}
	if err := registry.ValidateID(registry.PrefixMachine, machine.MachineID); err != nil {
		return nil, false, fmt.Errorf("machine.json in %s: %w", home.Root, err)
	}
	if machine.OwnerID != owner {
		return nil, false, fmt.Errorf("this machine (%s) belongs to owner %s, not this sign-in's owner %s: sign in as a person of %s; machine.json was not changed",
			machine.MachineID, machine.OwnerID, owner, machine.OwnerID)
	}
	if machine.DisplayName == "" {
		machine.DisplayName = txeComputerName(ctx)
	}
	return machine, written, nil
}

// txeComputerName is the name the worker installer gives a machine: the
// computer name on macOS, the host name elsewhere.
func txeComputerName(ctx context.Context) string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.CommandContext(ctx, "scutil", "--get", "ComputerName").Output(); err == nil {
			if name := strings.TrimSpace(string(out)); name != "" {
				return name
			}
		}
	}
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "machine"
	}
	return name
}
