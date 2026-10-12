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

	"github.com/goccy/go-yaml"
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

	spec, err := LoadJobSpec(specWithActions(t, action+"          \"<<\": {type: string, maxLength: 10}\n"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"object","properties":{"<<":{"type":"string","maxLength":10}}}`,
		string(spec.ReviewPolicy.PermittedActions[0].ParamSchema))
}

// What YAML can say and JSON cannot is refused when the spec is read, not
// sent as something else.
func TestParamSchemaRefusesWhatJSONCannotHold(t *testing.T) {
	for name, tc := range map[string]struct{ schema, want string }{
		"a number that is not one": {"        maximum: .nan\n", "is not a number JSON can hold"},
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

// A number in a schema is a bound. One that would be sent as a different
// number, or as text, is refused when the spec is read: the registry checks
// what it is sent, and cannot know what was written.
func TestParamSchemaRefusesWhatWouldNotArriveAsWritten(t *testing.T) {
	const (
		changed = "a different number"
		spelled = "must be written in plain decimal"
		tagged  = "uses a YAML tag"
		text    = "looks like a number but would be sent as text"
		notOne  = "is not a number JSON can hold"
		key     = "is not text"
	)
	for src, want := range map[string]string{
		// Rounded by the decoder: each was sent as the number in the comment
		// before this was refused.
		"maximum: 0.49999999999999999":     "the number 0.49999999999999999 would be sent as 0.5, " + changed,
		"minimum: -0.50000000000000001":    "would be sent as -0.5, " + changed,
		"maximum: 4503599627370496.2":      "would be sent as 4503599627370496, " + changed,
		"maximum: 9007199254740993.0":      "would be sent as 9007199254740992, " + changed,
		"enum: [0.49999999999999999, 1]":   changed,
		`{"maximum": 0.49999999999999999}`: changed,
		// Exactly a float64, and still not what would be sent: 2^-30.
		"maximum: 0.000000000931322574615478515625": "would be sent as 9.313225746154785e-10, " + changed,
		// Read as another number, or by a rule JSON does not have.
		"maxLength: 012":                        spelled, // 10
		"maxLength: 0x10":                       spelled,
		"maxLength: 0o17":                       spelled,
		"maxLength: 0b11":                       spelled,
		"maxLength: 1_000":                      spelled,
		"maxLength: +5":                         spelled,
		"maximum: .5":                           spelled,
		"maximum: 5.":                           spelled,
		"maximum: 0." + strings.Repeat("0", 70): "is longer than 64 characters",
		"maximum: 1.0e-401":                     "has an exponent beyond 400",
		"maximum: 1.0e-99999999999999999999":    "has an exponent beyond 400",
		// A tag changes what a value is after it is written.
		`maximum: !!float "0.49999999999999999"`: tagged, // 0.5
		`maxLength: !!int "7"`:                   tagged,
		"maximum: !!float 0.5":                   tagged,
		"const: !!str 5":                         tagged,
		// Sent as text where a number was written.
		"maximum: 1e3":                    text,
		"maximum: 1E2":                    text,
		"maximum: 1.0e+401":               text, // too large to be read as a number at all
		"maxLength: 18446744073709551616": text,
		"enum: [0x10000000000000000]":     text,
		"enum: [1.0e4_01]":                text, // the parser drops the "_" and then cannot hold it
		"enum: [1.0_0e401]":               text,
		"enum: [0x1.8p3]":                 text,
		"enum: [1e3]":                     text,
		"1e3: {type: string}":             text,
		"maximum: .inf":                   notOne,
		"minimum: -.inf":                  notOne,
		"maximum: .nan":                   notOne,
		// A key is sent as text. One that is not written as text can come
		// out as another key, and replace the bound written under it.
		"properties:\n  0.50: {type: string, maxLength: 1}\n  \"0.5\": {type: string, maxLength: 100}": key,
		"properties:\n  True: {maxLength: 1}\n  \"true\": {maxLength: 100}":                            key,
		"0.49999999999999999: {type: string}":                                                          key, // the key "0.5"
		"1: {type: string}":                                                                            key,
		"1.0: {type: string}":                                                                          key, // the key "1"
		"null: {type: string}":                                                                         key,
		"? 1.0\n: {type: string}":                                                                      "writes a key with",
		"? a\n: {type: string}":                                                                        "writes a key with",

		"{1: {type: string}}": key,
		// A reference can be read as nothing, or as something else.
		"const: &obj\n  a: &x 1\n  b: *x": "uses an anchor or a reference", // b was sent as null
		"const: &x [*x]":                  "uses an anchor or a reference", // sent as [null]
		"a: &n 0.5\nb: *n":                "uses an anchor or a reference",
		"description: &1e3 hello":         "uses an anchor or a reference",
	} {
		t.Run(src, func(t *testing.T) {
			var schema ParamSchema
			require.ErrorContains(t, yaml.Unmarshal([]byte(src), &schema), want)
			assert.Empty(t, schema)
		})
	}

	// A spec file is refused as a whole, and the number is named.
	_, err := LoadJobSpec(specWithActions(t, "    - name: reopen-ticket\n      timeout_sec: 60\n      param_schema:\n"+
		"        type: object\n        properties:\n          share:\n            type: number\n            maximum: 0.49999999999999999\n"))
	require.ErrorContains(t, err, "the number 0.49999999999999999 would be sent as 0.5")
	// The line is the line of the spec file, and the advice is to choose a
	// bound, never to shorten this one.
	require.Regexp(t, `line \d\d+: param_schema: the number`, err.Error())
	require.ErrorContains(t, err, "Rounding it would change the bound")
}

// What is written plainly is sent with the value it was written with. A
// number may be respelled (0.50 is sent as 0.5), never changed. What is sent
// is compared here as text, because comparing it as a number would round it
// the way the fault did. Whether a registry can check a number is the
// registry's rule, not this one: 0.1 is sent as 0.1.
func TestParamSchemaSendsNumbersAndTextAsWritten(t *testing.T) {
	for src, want := range map[string]string{
		"maximum: 0.5":                  `{"maximum":0.5}`,
		"maximum: 0.1":                  `{"maximum":0.1}`,
		"maximum: 0.50":                 `{"maximum":0.5}`,
		"maximum: 2.5e-1":               `{"maximum":0.25}`,
		"maximum: 1.5e-1":               `{"maximum":0.15}`,
		"maximum: 1.0e+2":               `{"maximum":100}`,
		"maximum: 123456789.012345":     `{"maximum":123456789.012345}`,
		"maximum: 2251799813685248.5":   `{"maximum":2251799813685248.5}`,
		"minimum: -3":                   `{"minimum":-3}`,
		"minimum: -0":                   `{"minimum":0}`,
		"maxLength: 10":                 `{"maxLength":10}`,
		"maxLength: 9007199254740993":   `{"maxLength":9007199254740993}`, // sent as written; the registry refuses it as beyond 2^53
		"enum: [0.25, 1, -2]":           `{"enum":[0.25,1,-2]}`,
		`{"maximum": 0.5, "x": [1, 2]}`: `{"maximum":0.5,"x":[1,2]}`,
		// Text written as text stays the text it was.
		`enum: ["1", "0.5", "012", "1e3", "true", "null", "0x10"]`: `{"enum":["1","0.5","012","1e3","true","null","0x10"]}`,
		"enum: [soft, hard, on, off, yes, no]":                     `{"enum":["soft","hard","on","off","yes","no"]}`,
		`const: "0.49999999999999999"`:                             `{"const":"0.49999999999999999"}`,
		"const: '012'":                                             `{"const":"012"}`,
		"const: 1.2.3":                                             `{"const":"1.2.3"}`,
		"const: 2001-01-01":                                        `{"const":"2001-01-01"}`,
		"pattern: |-\n  012":                                       `{"pattern":"012"}`,
		"pattern: >-\n  1e3":                                       `{"pattern":"1e3"}`,
		"const: |\n  012\n":                                        `{"const":"012\n"}`,
		"const: _1":                                                `{"const":"_1"}`,
		"pattern: 0x..":                                            `{"pattern":"0x.."}`,
		"const: 0xZZ":                                              `{"const":"0xZZ"}`,
		"const: true":                                              `{"const":true}`,
		"default: null":                                            `{"default":null}`,
		// A key written as text is the key sent.
		`properties: {"1": {type: string}, "0.50": {type: string}, "true": {type: string}}`: `{"properties":{"0.50":{"type":"string"},"1":{"type":"string"},"true":{"type":"string"}}}`,
	} {
		t.Run(src, func(t *testing.T) {
			var schema ParamSchema
			require.NoError(t, yaml.Unmarshal([]byte(src), &schema))
			assert.Equal(t, want, string(schema))
		})
	}
}

// A reference is resolved before a param_schema is read, where no check can
// see it, and the decoder can resolve it to something other than what is
// written above it. So a spec that bounds an action's parameters uses none,
// anywhere. A spec that bounds nothing reads as it always did.
func TestParamSchemaSpecIsWrittenOutInFull(t *testing.T) {
	const full = "must be written out in full"
	for name, tc := range map[string]struct{ actions, want string }{
		"a whole schema by reference": {
			"    - name: first\n      timeout_sec: 60\n      param_schema: &bound {type: object, maxProperties: 0}\n" +
				"    - name: second\n      timeout_sec: 60\n      param_schema: *bound\n", full},
		// The second action was given the third's schema, which bounds nothing.
		"a reference read as a later anchor of the same name": {
			"    - name: first\n      timeout_sec: 60\n      param_schema:\n        type: object\n        $defs:\n          bound: &bound {type: object, maxProperties: 0}\n" +
				"    - name: second\n      timeout_sec: 60\n      param_schema: *bound\n" +
				"    - name: third\n      timeout_sec: 60\n      param_schema:\n        type: object\n        $defs:\n          bound: &bound {type: object}\n", "uses an anchor or a reference"},
		"a reference somewhere else in the file": {
			"    - name: first\n      timeout_sec: 60\n      command: &run ./first.sh\n" +
				"    - name: second\n      timeout_sec: 60\n      command: *run\n      param_schema: {type: object}\n", full},
		"a schema merged in": {
			"    - name: first\n      timeout_sec: 60\n      <<: &shared {param_schema: {type: object}}\n" +
				"    - name: second\n      timeout_sec: 60\n      <<: *shared\n", full},
		"a text value standing in for a schema": {
			"    - name: first\n      timeout_sec: 60\n      command: &text '{\"type\":\"object\"}'\n" +
				"    - name: second\n      timeout_sec: 60\n      param_schema: *text\n", full},
		"an empty schema by reference": {
			"    - name: first\n      timeout_sec: 60\n      command: &none ''\n" +
				"    - name: second\n      timeout_sec: 60\n      param_schema: *none\n", full},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadJobSpec(specWithActions(t, tc.actions))
			require.ErrorContains(t, err, tc.want)
		})
	}

	_, err := LoadJobSpec(specWithActions(t, "    - name: first\n      timeout_sec: 60\n      command: &run ./first.sh\n"+
		"    - name: second\n      timeout_sec: 60\n      command: *run\n      param_schema: {type: object}\n"))
	require.ErrorContains(t, err, "uses an anchor (&name). A job spec that gives an action a param_schema")
	require.Regexp(t, `line \d+ uses`, err.Error())

	spec, err := LoadJobSpec(specWithActions(t, "    - name: first\n      timeout_sec: 60\n      command: &run ./first.sh\n"+
		"    - name: second\n      timeout_sec: 60\n      command: *run\n"))
	require.NoError(t, err)
	assert.Equal(t, "./first.sh", spec.ReviewPolicy.PermittedActions[1].Command)
	// A second document is not read, so a schema declared in one would be
	// dropped, and the references above it never looked for.
	_, err = LoadJobSpec(specWithActions(t, "    - name: first\n      timeout_sec: 60\n      command: &run ./first.sh\n"+
		"    - name: second\n      timeout_sec: 60\n      command: *run\n"+
		"---\nreview_policy:\n  permitted_actions:\n    - name: restricted\n      timeout_sec: 60\n      param_schema: {type: object, maxProperties: 0}\n"))
	require.ErrorContains(t, err, "the file holds 2 YAML documents")

	// An anchor inside a schema is named with its line too.
	_, err = LoadJobSpec(specWithActions(t, "    - name: first\n      timeout_sec: 60\n      param_schema:\n        const: &value hello\n"))
	require.Regexp(t, `line \d\d+: param_schema uses an anchor or a reference`, err.Error())
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
