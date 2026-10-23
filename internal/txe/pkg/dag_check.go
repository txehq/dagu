// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/token"
)

// renderedTopLevel are the keys RenderDAG writes at the top of a job's DAG.
// A DAG with any other key, such as a handler or a precondition, does more
// than RenderDAG's and is not the generated one.
var renderedTopLevel = []string{
	"type", "description", "group", "labels", "worker_selector", "schedule", "catchup_window", "overlap_policy",
	"max_active_runs", "hist_retention_days", "timeout_sec", "working_dir", "artifacts", "env", "secrets", "steps",
}

// Tokens the renderer never writes: document markers and directives, and
// the anchors, aliases, tags and merge keys YAML readers resolve differently.
var (
	structural = map[token.Type]bool{token.DocumentHeaderType: true, token.DocumentEndType: true, token.DirectiveType: true}
	divergent  = map[token.Type]bool{token.AnchorType: true, token.AliasType: true, token.TagType: true, token.MergeKeyType: true}
)

// renderedRunStep are the keys RenderDAG writes on the job's step.
var renderedRunStep = []string{"name", "command", "retry_policy"}

// CheckGeneratedPublish checks that spec, a job's DAG as stored, has exactly
// the publish step RenderDAG writes for it: one document; nothing but the
// keys RenderDAG writes; the job's step, then the publish step with only a
// name and one command; and that command exactly the CLI's "txe artifacts
// publish" with the same binary and store flags as the job step's resource
// check, written as RenderDAG writes it. A republish (TXE-5067) runs that
// step alone, so it may run only when the step can do nothing else.
func CheckGeneratedPublish(spec []byte) error {
	// The renderer writes plain mappings, lists and quoted scalars. A
	// document marker, an anchor, an alias, a tag or a merge key is where one
	// YAML reader and another can read the same bytes differently, so none
	// is accepted; duplicate keys are refused by the decoder.
	for _, tok := range lexer.Tokenize(string(spec)) {
		if structural[tok.Type] {
			return errors.New("the DAG has a document marker or directive, which the TXE renderer does not write")
		}
		if divergent[tok.Type] {
			return fmt.Errorf("the DAG uses %q, which the TXE renderer does not write", tok.Value)
		}
	}
	var dag map[string]any
	if err := yaml.Unmarshal(spec, &dag); err != nil {
		return fmt.Errorf("the DAG does not parse: %w", err)
	}
	for key := range dag {
		if !slices.Contains(renderedTopLevel, key) {
			return fmt.Errorf("the DAG sets %q, which the TXE renderer does not write", key)
		}
	}
	// RenderDAG writes "artifacts" only as "enabled: true", for a job with a
	// hub deliverable; any other setting is not its.
	if artifacts, set := dag["artifacts"]; set {
		if m, ok := artifacts.(map[string]any); !ok || len(m) != 1 || m["enabled"] != true {
			return errors.New("the DAG's artifacts setting is not the one the TXE renderer writes")
		}
	}
	if dag["type"] != "chain" {
		return errors.New("the DAG is not the chain the TXE renderer writes")
	}
	steps, ok := dag["steps"].([]any)
	if !ok || len(steps) != 2 {
		return errors.New("the DAG does not have the job's step and the publish step alone")
	}
	run, ok := steps[0].(map[string]any)
	if !ok || run["name"] != RunStepName {
		return fmt.Errorf("the DAG's first step is not %q", RunStepName)
	}
	for key := range run {
		if !slices.Contains(renderedRunStep, key) {
			return fmt.Errorf("the %q step sets %q, which the TXE renderer does not write", RunStepName, key)
		}
	}
	commands, ok := run["command"].([]any)
	if !ok || len(commands) == 0 {
		return fmt.Errorf("the %q step has no list of commands", RunStepName)
	}
	check, ok := commands[0].(string)
	if !ok {
		return fmt.Errorf("the %q step's first command is not a command line", RunStepName)
	}
	argv, err := shellSplit(check)
	if err != nil {
		return fmt.Errorf("the %q step's resource check: %w", RunStepName, err)
	}
	if len(argv) < 10 || !slices.Equal(argv[1:4], []string{"txe", "resource", "check"}) ||
		argv[4] != "--job" || argv[6] != "--job-version" || argv[8] != "--machine" {
		return fmt.Errorf("the %q step does not start with the CLI's resource check", RunStepName)
	}
	cli := CLI{Dagu: argv[0], StoreFlags: argv[10:]}

	publish, ok := steps[1].(map[string]any)
	if !ok || publish["name"] != PublishStepName {
		return fmt.Errorf("the DAG's second step is not %q", PublishStepName)
	}
	for key := range publish {
		if key != "name" && key != "command" {
			return fmt.Errorf("the %q step sets %q, which the TXE renderer does not write", PublishStepName, key)
		}
	}
	command, ok := publish["command"].(string)
	if !ok {
		return fmt.Errorf("the %q step's command is not one command line", PublishStepName)
	}
	if want := shellJoin(cli.command("artifacts", "publish")); command != want {
		return fmt.Errorf("the %q step's command is not the CLI's artifacts publish the TXE renderer writes", PublishStepName)
	}
	return nil
}

// shellSplit is the inverse of shellJoin for what shellJoin writes: words of
// shellSafe characters, or single-quoted words in which a quote is written
// '\”. Anything else is refused, so a line that splits is one shellJoin
// could have written, and has no shell syntax of its own.
func shellSplit(line string) ([]string, error) {
	var argv []string
	for i := 0; i < len(line); {
		if line[i] == ' ' {
			if i == 0 || i == len(line)-1 || line[i+1] == ' ' {
				return nil, errors.New("not one space between words")
			}
			i++
			continue
		}
		var word strings.Builder
		for i < len(line) && line[i] != ' ' {
			switch c := line[i]; {
			case c == '\'':
				end := strings.IndexByte(line[i+1:], '\'')
				if end < 0 {
					return nil, errors.New("an unterminated quote")
				}
				word.WriteString(line[i+1 : i+1+end])
				i += end + 2
				if strings.HasPrefix(line[i:], `\''`) {
					word.WriteByte('\'')
					i += 2 // the escaped quote, then back into the quoted part
					continue
				}
			case strings.IndexByte(shellSafe, c) >= 0:
				word.WriteByte(c)
				i++
			default:
				return nil, fmt.Errorf("the character %q, which is shell syntax", c)
			}
		}
		argv = append(argv, word.String())
	}
	// Only what shellJoin writes for these words splits: same words, same
	// quoting.
	if shellJoin(argv) != line {
		return nil, errors.New("not written as the TXE renderer writes a command line")
	}
	return argv, nil
}
