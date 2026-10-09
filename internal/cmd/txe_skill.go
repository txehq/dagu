// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	txeskill "github.com/dagucloud/dagu/v2/txe/skill"
)

var txeSkillLinkFlag = commandLineFlag{
	name:          "link",
	usage:         "A coding agent's skills directory to link the skill into, such as ~/.claude/skills; repeatable",
	isStringArray: true,
}

func init() {
	txeSubcommands = append(txeSubcommands, txeSkillCommand)
}

func txeSkillCommand() *cobra.Command {
	local := map[string]string{txeLocalAnnotation: "true"}
	command := NewCommand(&cobra.Command{
		Use:         "skill",
		Short:       "Install the coding-agent skill for durable jobs",
		Annotations: local,
	}, nil, func(ctx *Context, _ []string) error {
		return ctx.Command.Help()
	})
	command.AddCommand(NewCommand(&cobra.Command{
		Use:   "install",
		Short: "Unpack this binary's skill and link it into agent profiles",
		Long: `Unpack the skill carried in this binary under the TXE home and point the
"current" link at it. Each --link directory gets a link to that current copy,
so every profile reads the same revision and an upgrade reaches all of them.

Earlier revisions are kept. A real directory already at a link's place is left
alone and reported.`,
		Args:        cobra.NoArgs,
		Annotations: local,
	}, []commandLineFlag{txeSkillLinkFlag, txeJSONFlag}, func(ctx *Context, _ []string) error {
		return runTXESkill(ctx, true)
	}))
	command.AddCommand(NewCommand(&cobra.Command{
		Use:         "status",
		Short:       "Show which skill revision is unpacked and linked, against this binary's",
		Args:        cobra.NoArgs,
		Annotations: local,
	}, []commandLineFlag{txeSkillLinkFlag, txeJSONFlag}, func(ctx *Context, _ []string) error {
		return runTXESkill(ctx, false)
	}))
	return command
}

func runTXESkill(ctx *Context, install bool) error {
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	links, err := ctx.Command.Flags().GetStringArray("link")
	if err != nil {
		return err
	}

	unpacked := home.SkillDir() + "/current"
	if install {
		if unpacked, err = txeskill.Unpack(home.SkillDir()); err != nil {
			return fmt.Errorf("unpack the skill: %w", err)
		}
	}
	states := []txeskill.State{txeskill.Inspect(unpacked)}
	for _, dir := range links {
		link := dir + "/" + txeskill.Name
		if install {
			if link, err = txeskill.Link(unpacked, dir); err != nil {
				return fmt.Errorf("link the skill into %s: %w", dir, err)
			}
		}
		states = append(states, txeskill.Inspect(link))
	}

	stale := 0
	for _, s := range states {
		if !s.Current {
			stale++
		}
	}
	if err := txeOutput(ctx, map[string]any{
		"ok": stale == 0, "skill": txeskill.Name, "revision": txeskill.Revision(), "locations": states,
	}, func(p *txePrinter) {
		p.f("Skill %s, revision %s in this binary.\n\n", txeskill.Name, txeskill.Revision())
		for _, s := range states {
			if s.Current {
				p.f("ok    %s\n", s.Path)
			} else {
				p.f("STALE %s: %s\n", s.Path, s.Problem)
			}
		}
	}); err != nil {
		return err
	}
	if stale > 0 {
		return fmt.Errorf("%d location(s) do not hold this binary's skill revision; run dagu txe skill install", stale)
	}
	return nil
}
