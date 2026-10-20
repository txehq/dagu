// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/viper"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// txeStepStore decides which context store a registration's job steps read,
// and returns a client that reads the hub through it when it is not the
// session's own.
//
// A step runs unattended as this machine and never presents a person's
// sign-in (txeInDAGStep). A session whose context holds a credential of its
// own keeps rendering that context, as before. A session signed in through a
// sign-in-only context gives its steps this machine's own store instead, and
// only when:
//   - the hub says the sign-in is bound to the owner of this machine;
//   - this machine's store has the hub's context, with a credential in it;
//   - the registrar finds both contexts reach the same registry (see
//     txeclient.Registrar.StepClient).
//
// Anything else refuses the registration. The machine's credential is used
// here only to read the hub as a step would; it is never printed, copied or
// written into the job.
func txeStepStore(ctx *Context, home txepkg.Home, machine *txepkg.Machine) (txeclient.HubContext, *txeclient.Client, error) {
	session := txeHubContext(ctx)
	if !ctx.IsRemote() || ctx.Remote.apiKey != "" {
		return session, nil, nil
	}

	who, err := txeAskHubIdentity(ctx, ctx.Remote)
	if err != nil {
		return txeclient.HubContext{}, nil, fmt.Errorf("this session reaches the hub with a sign-in only, and the hub cannot say whose it is (%w): run \"dagu txe whoami\"", err)
	}
	if who.State != "bound" || !slices.Contains(txeOwnerIDs(who), machine.OwnerID) {
		return txeclient.HubContext{}, nil, fmt.Errorf("this sign-in is %s for %s, not bound to owner %s, the owner of machine %s: jobs registered here would run as that owner's machine",
			who.State, txeOwnerList(who), machine.OwnerID, machine.MachineID)
	}

	steps, stepContext, err := txeMachineStore(ctx, home)
	if err != nil {
		return txeclient.HubContext{}, nil, err
	}
	stepClient, err := txeMachineStepClient(ctx, home, stepContext)
	if err != nil {
		return txeclient.HubContext{}, nil, err
	}
	return steps, stepClient, nil
}

// txeMachineStepClient reads the hub as this machine's job steps will: with
// the machine store's API key, or, for a machine whose store holds none,
// with the machine's enrolled worker credential (TXE-4707), which is then
// what those steps present. A machine with neither has nothing its jobs
// could run with, and is refused; so is a reviewer-only enrolment, which no
// job step presents.
func txeMachineStepClient(ctx context.Context, home txepkg.Home, stepContext *cliContext) (*txeclient.Client, error) {
	remote, err := newRemoteClient(stepContext)
	if err != nil {
		return nil, err
	}
	if !stepContext.SignInOnly && stepContext.APIKey != "" {
		return txeclient.New(remote.baseURL, remote.apiKey, remote.client), nil
	}
	auth, err := home.StepAuth()
	if err != nil {
		return nil, fmt.Errorf("this machine's own %q context holds no API key, and how its steps reach the hub cannot be read: %w", txeContextName, err)
	}
	entry, enrolled := auth.Enrolled(string(authn.ClassWorker))
	if !enrolled {
		return nil, fmt.Errorf("this machine's own %q context holds no API key, and this machine is not enrolled for the worker class, so a job's steps would have nothing to run with: enrol this machine's worker (dagu txe enrol) and register again",
			txeContextName)
	}
	worker, err := txeEnrolledRemote(ctx, home, authn.ClassWorker, entry, remote)
	if err != nil {
		return nil, err
	}
	return txeclient.New(worker.baseURL, "", worker.client), nil
}

// txeOwnerIDs lists the owners a hub identity answer names.
func txeOwnerIDs(who *txeHubIdentity) []string {
	ids := make([]string, 0, len(who.Owners))
	for _, o := range who.Owners {
		ids = append(ids, o.OwnerID)
	}
	return ids
}

// txeOwnerList names the owners a hub identity answer lists.
func txeOwnerList(who *txeHubIdentity) string {
	if len(who.Owners) == 0 {
		return "no owner"
	}
	return strings.Join(txeOwnerIDs(who), ", ")
}

// txeMachineStore opens this machine's own context store: the TXE home's
// client store, resolved as a step resolves it when given only --dagu-home,
// and its hub context. Whether its steps have a credential to present is
// txeMachineStepClient's to decide.
func txeMachineStore(ctx context.Context, home txepkg.Home) (txeclient.HubContext, *cliContext, error) {
	daguHome := home.ClientDir()
	cfg, err := txeStoreConfig(daguHome)
	if err != nil {
		return txeclient.HubContext{}, nil, fmt.Errorf("read this machine's own context store at %s: %w", daguHome, err)
	}
	store, err := newCLIContextStore(cfg.Paths.DataDir, cfg.Paths.ContextsDir)
	if err != nil {
		return txeclient.HubContext{}, nil, fmt.Errorf("open this machine's own context store at %s: %w", cfg.Paths.ContextsDir, err)
	}
	stored, err := store.Get(ctx, txeContextName)
	if errors.Is(err, errCLIContextNotFound) {
		return txeclient.HubContext{}, nil, fmt.Errorf("this machine's own context store (%s) has no %q context, so a job registered with a sign-in would have nothing to run with: install this machine's worker first (txe/worker/install.sh)",
			cfg.Paths.ContextsDir, txeContextName)
	}
	if err != nil {
		return txeclient.HubContext{}, nil, fmt.Errorf("read the %q context in this machine's own store (%s): %w", txeContextName, cfg.Paths.ContextsDir, err)
	}
	return txeclient.HubContext{DaguHome: daguHome, Name: txeContextName, ContextsDir: cfg.Paths.ContextsDir, DataDir: cfg.Paths.DataDir}, stored, nil
}

// txeStoreConfig reads the configuration of the Dagu home a step is given.
// txeDefaults has replaced this process's DAGU_* variables with the ones this
// session's flags name; a step has neither, so they are set aside while it
// is read.
func txeStoreConfig(daguHome string) (*config.Config, error) {
	saved := map[string]string{}
	for _, variable := range os.Environ() {
		if name, value, _ := strings.Cut(variable, "="); strings.HasPrefix(name, "DAGU_") {
			saved[name] = value
			if err := os.Unsetenv(name); err != nil {
				return nil, err
			}
		}
	}
	defer func() {
		for name, value := range saved {
			_ = os.Setenv(name, value)
		}
	}()
	return config.NewConfigLoader(viper.New(), config.WithAppHomeDir(daguHome), config.WithService(config.ServiceNone)).Load()
}
