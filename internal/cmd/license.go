// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/license"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/spf13/cobra"
)

// License returns the parent command for license management.
func License() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "license",
		Short: "Manage Dagu license",
		Long:  "Activate, deactivate, and check Dagu license status.",
	}

	cmd.AddCommand(licenseActivate())
	cmd.AddCommand(licenseDeactivate())
	cmd.AddCommand(licenseCheck())

	return cmd
}

func licenseActivate() *cobra.Command {
	return NewCommand(
		&cobra.Command{
			Use:   "activate <key>",
			Short: "Activate a license key",
			Args:  cobra.ExactArgs(1),
		}, nil, func(ctx *Context, args []string) error {
			key := args[0]

			mgr, err := newLicenseManager(ctx, key)
			if err != nil {
				return err
			}

			result, err := mgr.ActivateWithKey(ctx, key)
			if err != nil {
				return fmt.Errorf("activation failed: %w", err)
			}
			defer mgr.Stop()

			fmt.Printf("License activated successfully!\n")
			fmt.Printf("  Plan:     %s\n", result.Plan)
			fmt.Printf("  Features: %s\n", strings.Join(result.Features, ", "))
			if !result.Expiry.IsZero() {
				fmt.Printf("  Expires:  %s\n", result.Expiry.Format("2006-01-02"))
			}

			return nil
		},
	)
}

func licenseDeactivate() *cobra.Command {
	return NewCommand(
		&cobra.Command{
			Use:   "deactivate",
			Short: "Remove the local license activation",
		}, nil, func(ctx *Context, _ []string) error {
			mgr, err := newLicenseManager(ctx, ctx.Config.License.Key)
			if err != nil {
				return err
			}

			if err := mgr.Start(ctx); err != nil {
				return err
			}
			defer mgr.Stop()

			if err := mgr.Deactivate(ctx); err != nil {
				return fmt.Errorf("deactivation failed: %w", err)
			}

			fmt.Println("License deactivated. Running in community mode.")
			return nil
		},
	)
}

func licenseCheck() *cobra.Command {
	return NewCommand(
		&cobra.Command{
			Use:   "check",
			Short: "Display current license status",
		}, nil, func(ctx *Context, _ []string) error {
			mgr, err := newLicenseManager(ctx, ctx.Config.License.Key)
			if err != nil {
				return err
			}

			if err := mgr.Start(ctx); err != nil {
				return err
			}
			defer mgr.Stop()

			checker := mgr.Checker()
			if policy := mgr.ForkPolicy(); !policy.IsZero() {
				defer printForkPolicy(policy)
			}
			if checker.IsCommunity() {
				fmt.Println("License: Community mode (no license)")
				return nil
			}

			fmt.Printf("License Status\n")
			fmt.Printf("  Plan:         %s\n", checker.Plan())
			if claims := checker.Claims(); claims != nil {
				fmt.Printf("  Features:     %s\n", strings.Join(claims.Features, ", "))
				if claims.ExpiresAt != nil {
					fmt.Printf("  Expires:      %s\n", claims.ExpiresAt.Format("2006-01-02"))
				}
			}
			if checker.IsGracePeriod() {
				fmt.Printf("  Status:       EXPIRED (grace period active)\n")
			} else {
				fmt.Printf("  Status:       Active\n")
			}

			return nil
		},
	)
}

func newLicenseManager(ctx *Context, configKey string) (*license.Manager, error) {
	pubKey, err := license.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load license public key: %w", err)
	}

	licenseDir := file.LicenseDir(ctx.Config)
	store := file.NewLicenseStore(ctx, ctx.backend.Collection(persis.CollectionLicense))
	forkPolicy := licenseForkPolicy(ctx.Config)
	if err := forkPolicy.Validate(); err != nil {
		return nil, err
	}
	return license.NewManager(license.ManagerConfig{
		LicenseDir: licenseDir,
		ConfigKey:  configKey,
		CloudURL:   ctx.Config.License.CloudURL,
		ForkPolicy: forkPolicy,
	}, pubKey, store, slog.Default()), nil
}

// licenseForkPolicy converts the configured fork policy for the license
// package, which the config package cannot import.
func licenseForkPolicy(cfg *config.Config) license.ForkPolicy {
	policy := license.ForkPolicy{Features: slices.Clone(cfg.License.ForkPolicy.Features)}
	if cfg.License.ForkPolicy.MaxAPIKeys != nil {
		limit := *cfg.License.ForkPolicy.MaxAPIKeys
		policy.MaxAPIKeys = &limit
	}
	return policy
}

func forkPolicyAPIKeyLimitText(policy license.ForkPolicy) string {
	switch {
	case policy.MaxAPIKeys == nil:
		return "community limit"
	case *policy.MaxAPIKeys == 0:
		return "no limit"
	default:
		return strconv.Itoa(*policy.MaxAPIKeys)
	}
}

// printForkPolicy reports the fork policy beside the license status, so the
// output never reads as if a license enabled what the policy enabled.
func printForkPolicy(policy license.ForkPolicy) {
	features := "none"
	if len(policy.Features) > 0 {
		features = strings.Join(policy.Features, ", ")
	}
	fmt.Printf("Fork policy (not a license)\n")
	fmt.Printf("  Features:     %s\n", features)
	fmt.Printf("  API keys:     %s\n", forkPolicyAPIKeyLimitText(policy))
}
