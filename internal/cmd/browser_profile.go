// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"path/filepath"

	"github.com/dagucloud/dagu/v2/internal/browserhost"
	"github.com/dagucloud/dagu/v2/internal/runtime/builtin/browser"
	"github.com/spf13/cobra"
)

// browserProfileCommand is the command group for the named browser
// profiles steps and sessions use.
func browserProfileCommand() *cobra.Command {
	cmd := NewCommand(&cobra.Command{
		Use:   "profile",
		Short: "Manage the named browser profiles steps and sessions use",
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	cmd.AddCommand(browserProfileClaimCommand(), browserProfileUnclaimCommand())
	return cmd
}

func browserProfileClaimCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "claim <name>",
		Short: "Let Dagu's browsers use a named profile made before they marked their profiles",
		Long: `Claim a named browser profile that was made before Dagu marked the profiles
its browsers may change. A step or session refuses such a profile and leaves
it as it is, with its logins and cookies, until it is claimed.

Dagu's browsers set incognito.mode_availability = 1 in the profile's
Default/Preferences each time they start, so the browser opens no window off
the record; nothing else in the profile is changed. The claim keeps a copy
of the preferences beside them (Preferences.dagu-before-claim) and the
value it found, and prints both.

The profile must be the directory <data dir>/browser/profiles/<name> itself,
this user's alone, and not in use by a step, a session or a browser.

Undo with: dagu browser profile unclaim <name>

Example:
  dagu browser profile claim shop
`,
		Args: cobra.ExactArgs(1),
	}, nil, runBrowserProfileClaim)
}

func browserProfileUnclaimCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "unclaim <name>",
		Short: "Undo a profile claim",
		Long: `Undo "dagu browser profile claim": Dagu's browsers no longer use the profile,
and incognito.mode_availability is put back as it was before the claim,
every other preference staying as the browser left it. The copy of the
preferences the claim kept stays, and is printed.

Example:
  dagu browser profile unclaim shop
`,
		Args: cobra.ExactArgs(1),
	}, nil, runBrowserProfileUnclaim)
}

func browserDataDir(ctx *Context) string {
	return filepath.Join(ctx.Config.Paths.DataDir, browserhost.DataDirName)
}

func runBrowserProfileClaim(ctx *Context, args []string) error {
	report, err := browser.ClaimProfile(browserDataDir(ctx), args[0])
	if err != nil {
		return err
	}
	return writeIndentedJSON(ctx.Command.OutOrStdout(), report)
}

func runBrowserProfileUnclaim(ctx *Context, args []string) error {
	report, err := browser.UnclaimProfile(browserDataDir(ctx), args[0])
	if err != nil {
		return err
	}
	return writeIndentedJSON(ctx.Command.OutOrStdout(), report)
}
