// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// specWithActions writes the collector's worktree with permitted actions
// added to its review policy and returns the path of the spec.
func specWithActions(t *testing.T, actions string) string {
	t.Helper()
	_, dir := worktree(t, credentialFile(t))
	path := filepath.Join(dir, "job.yaml")
	data, err := os.ReadFile(path) //nolint:gosec // test file
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(data, []byte("  permitted_actions:\n"+actions)...), 0o644)) //nolint:gosec // test file
	return path
}

const boundedAction = `    - name: reopen-ticket
      command: ./reopen.sh
      timeout_sec: 60
      param_schema:
        type: object
        properties:
          reason: {type: string, maxLength: 200, pattern: "^[a-z <&]+$"}
        required: [reason]
        additionalProperties: false
`

const unboundedAction = `    - name: recount
      command: ./recount.sh
      timeout_sec: 30
`

// sentActions returns the permitted actions of the version in a request body.
func sentActions(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var sent struct {
		Version struct {
			ReviewPolicy struct {
				PermittedActions []map[string]any `json:"permitted_actions"`
			} `json:"review_policy"`
		} `json:"version"`
	}
	require.NoError(t, json.Unmarshal(body, &sent))
	return sent.Version.ReviewPolicy.PermittedActions
}

// A parameter schema a job spec declares reaches the registry with the value
// the spec gave it, and the request filed beside the receipt holds the same.
// An action that declares none sends none.
func TestParamSchemaIsSentAsDeclared(t *testing.T) {
	f := newFakeRegistry(t)
	f.capabilities = []string{CapabilityParamSchema}
	home := machineHome(t, f)
	spec, err := LoadJobSpec(specWithActions(t, boundedAction+unboundedAction))
	require.NoError(t, err)

	out, err := newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
	require.NoError(t, err)

	want := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string", "maxLength": float64(200), "pattern": "^[a-z <&]+$"},
		},
		"required":             []any{"reason"},
		"additionalProperties": false,
	}
	check := func(where string, actions []map[string]any) {
		require.Len(t, actions, 2, where)
		assert.Equal(t, "reopen-ticket", actions[0]["name"], where)
		assert.Equal(t, want, actions[0]["param_schema"], where)
		assert.Equal(t, "recount", actions[1]["name"], where)
		assert.NotContains(t, actions[1], "param_schema", where)
	}

	var sent []byte
	for _, r := range f.requests {
		if r.Method == http.MethodPost && r.Path == "/txe/jobs" {
			sent = r.Body
		}
	}
	require.NotNil(t, sent, "no registration was sent")
	check("the request sent", sentActions(t, sent))

	filed, err := os.ReadFile(filepath.Join(home.ReceiptsDir(), out.Receipt.JobID, "requests", out.Receipt.RequestID+".json")) //nolint:gosec // test directory
	require.NoError(t, err)
	var entry struct {
		Request json.RawMessage `json:"request"`
	}
	require.NoError(t, json.Unmarshal(filed, &entry))
	check("the request filed", sentActions(t, entry.Request))
}

// A registry that does not say it enforces parameter schemas would store a
// declared bound and check nothing against it. Registering, planning and
// updating a spec that declares one are refused before anything is built or
// sent; the same job without the schema registers.
func TestParamSchemaNeedsARegistryThatEnforcesIt(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	bounded, err := LoadJobSpec(specWithActions(t, boundedAction+unboundedAction))
	require.NoError(t, err)
	unbounded, err := LoadJobSpec(specWithActions(t, unboundedAction))
	require.NoError(t, err)
	ctx := context.Background()

	untouched := func(what string) {
		assert.Zero(t, f.calls(http.MethodPost, "/txe/jobs"), what)
		assert.Empty(t, pendingSteps(t, cc1.Journal), what)
		staged, _ := filepath.Glob(filepath.Join(home.PackagesDir(), "*", "*"))
		assert.Empty(t, staged, what)
	}
	_, err = cc1.Register(ctx, bounded)
	require.ErrorIs(t, err, ErrParamSchemaUnenforced)
	assert.ErrorContains(t, err, "reopen-ticket")
	assert.NotContains(t, err.Error(), "recount")
	untouched("after a refused registration")
	_, err = cc1.Plan(ctx, bounded)
	require.ErrorIs(t, err, ErrParamSchemaUnenforced)
	untouched("after a refused plan")

	out, err := cc1.Register(ctx, unbounded)
	require.NoError(t, err)
	_, err = cc1.Update(ctx, out.Receipt.JobID, 1, bounded)
	require.ErrorIs(t, err, ErrParamSchemaUnenforced)
	assert.Equal(t, 1, f.job(out.Receipt.JobID).Version)
	assert.Empty(t, pendingSteps(t, cc1.Journal))

	// Once the registry says it enforces schemas, the same update goes through.
	f.mu.Lock()
	f.capabilities = []string{CapabilityParamSchema}
	f.mu.Unlock()
	_, err = cc1.Update(ctx, out.Receipt.JobID, 1, bounded)
	require.NoError(t, err)
	assert.Equal(t, 2, f.job(out.Receipt.JobID).Version)
}

// A hub that cannot be asked is not taken to enforce anything.
func TestParamSchemaHubThatCannotBeAsked(t *testing.T) {
	f := newFakeRegistry(t)
	f.capabilities = []string{CapabilityParamSchema}
	home := machineHome(t, f)
	spec, err := LoadJobSpec(specWithActions(t, boundedAction))
	require.NoError(t, err)
	f.mu.Lock()
	f.fail["GET /txe/installation"] = 1
	f.mu.Unlock()

	_, err = newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
	require.ErrorContains(t, err, "ask the hub whether its registry checks action parameters")
	assert.Zero(t, f.calls(http.MethodPost, "/txe/jobs"))
}

// A param_schema that is not a mapping is refused with its action named,
// whether it is a list, a scalar, or a key left with no value. The last
// would otherwise register an action with no bounds on its parameters.
func TestParamSchemaMustBeAMapping(t *testing.T) {
	for name, value := range map[string]string{
		"a list":        " [reason]",
		"a scalar":      " reason",
		"no value":      "",
		"explicit null": " null",
		"a tilde":       " ~",
	} {
		t.Run(name, func(t *testing.T) {
			path := specWithActions(t, unboundedAction+"    - name: reopen-ticket\n      timeout_sec: 60\n      param_schema:"+value+"\n")
			_, err := LoadJobSpec(path)
			var missing *MissingContextError
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, []string{"review_policy.permitted_actions[1].param_schema must be a mapping (a JSON Schema)"}, missing.Problems)
		})
	}

	// An empty mapping is a schema: the one that admits any parameters.
	spec, err := LoadJobSpec(specWithActions(t, "    - name: reopen-ticket\n      timeout_sec: 60\n      param_schema: {}\n"))
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(spec.ReviewPolicy.PermittedActions[0].ParamSchema))
}

// A spec built in memory never passed through the spec file's checks. A
// schema that is not exactly one JSON object is refused there too, before a
// package is staged, a journal entry written or the hub asked to change
// anything, even on a hub that enforces schemas.
func TestParamSchemaIsCheckedForASpecBuiltInMemory(t *testing.T) {
	f := newFakeRegistry(t)
	f.capabilities = []string{CapabilityParamSchema}
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	ctx := context.Background()
	registered, err := LoadJobSpec(specWithActions(t, unboundedAction))
	require.NoError(t, err)
	out, err := cc1.Register(ctx, registered)
	require.NoError(t, err)
	posts := f.calls(http.MethodPost, "/txe/jobs")

	for name, schema := range map[string]string{
		"a list":            `[]`,
		"null":              `null`,
		"a string":          `"object"`,
		"an unclosed brace": `{`,
		"two values":        `{} []`,
		"only whitespace":   ` `,
	} {
		t.Run(name, func(t *testing.T) {
			spec, err := LoadJobSpec(specWithActions(t, unboundedAction+boundedAction))
			require.NoError(t, err)
			spec.JobKey = "built-in-memory"
			spec.ReviewPolicy.PermittedActions[1].ParamSchema = ParamSchema(schema)
			var missing *MissingContextError
			require.ErrorAs(t, spec.Validate(), &missing)

			_, err = cc1.Register(ctx, spec)
			require.ErrorContains(t, err, `permitted action "reopen-ticket": param_schema must be a mapping`)
			_, err = cc1.Plan(ctx, spec)
			require.ErrorContains(t, err, `permitted action "reopen-ticket": param_schema must be a mapping`)
			spec.JobKey = registered.JobKey
			_, err = cc1.Update(ctx, out.Receipt.JobID, 1, spec)
			require.ErrorContains(t, err, `permitted action "reopen-ticket": param_schema must be a mapping`)

			assert.Equal(t, posts, f.calls(http.MethodPost, "/txe/jobs"))
			assert.Zero(t, f.calls(http.MethodPost, "/txe/jobs/"+out.Receipt.JobID+"/versions"))
			assert.Equal(t, 1, f.job(out.Receipt.JobID).Version)
			assert.Empty(t, pendingSteps(t, cc1.Journal))
		})
	}
}

// A YAML merge key lets a merged entry replace a bound written beside it:
// maxLength 10 would be sent as 200. A schema that uses one is refused. A
// property that is really named "<<" is not a merge, and neither is an alias.
func TestParamSchemaRefusesMergeKeys(t *testing.T) {
	action := "    - name: reopen-ticket\n      timeout_sec: 60\n      param_schema:\n        type: object\n        properties:\n"
	_, err := LoadJobSpec(specWithActions(t, action+"          reason:\n            maxLength: 10\n            <<: {type: string, maxLength: 200}\n"))
	require.ErrorContains(t, err, "merge key")

	spec, err := LoadJobSpec(specWithActions(t, action+"          \"<<\": &text {type: string, maxLength: 10}\n          reason: *text\n"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"object","properties":{"<<":{"type":"string","maxLength":10},"reason":{"type":"string","maxLength":10}}}`,
		string(spec.ReviewPolicy.PermittedActions[0].ParamSchema))
}

// What YAML can say and JSON cannot is refused when the spec is read, not
// sent as something else.
func TestParamSchemaRefusesWhatJSONCannotHold(t *testing.T) {
	for name, tc := range map[string]struct{ schema, want string }{
		"a number that is not one": {"        maximum: .nan\n", "param_schema cannot be written as JSON"},
		"a keyword given twice":    {"        type: object\n        type: string\n", `"type" already defined`},
	} {
		t.Run(name, func(t *testing.T) {
			path := specWithActions(t, "    - name: reopen-ticket\n      timeout_sec: 60\n      param_schema:\n"+tc.schema)
			_, err := LoadJobSpec(path)
			require.ErrorContains(t, err, tc.want)
			var missing *MissingContextError
			assert.NotErrorAs(t, err, &missing)
		})
	}
}

// A schema the registry answers is kept as it was answered, and a version
// with none reads and writes none.
func TestParamSchemaJSON(t *testing.T) {
	var action PermittedAction
	require.NoError(t, json.Unmarshal([]byte(`{"name":"a","timeout_sec":1,"routine":false,"param_schema":{"type":"object","maximum":1.50}}`), &action))
	assert.Equal(t, `{"type":"object","maximum":1.50}`, string(action.ParamSchema))
	out, err := json.Marshal(action)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"param_schema":{"type":"object","maximum":1.50}`)

	for _, body := range []string{`{"name":"a","timeout_sec":1,"routine":false}`, `{"name":"a","timeout_sec":1,"routine":false,"param_schema":null}`} {
		var none PermittedAction
		require.NoError(t, json.Unmarshal([]byte(body), &none))
		assert.Empty(t, none.ParamSchema)
		out, err := json.Marshal(none)
		require.NoError(t, err)
		assert.False(t, strings.Contains(string(out), "param_schema"), "%s", out)
	}
}
