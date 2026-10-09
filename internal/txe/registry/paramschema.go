// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// A permitted action's param_schema is a JSON Schema (draft 2020-12) that
// the registry enforces on every attempt of that action
// before it is granted. It is checked when a version is registered: it must
// resolve with no remote reference, and it may use only keywords the
// validator enforces, so a schema never promises a restriction (a format,
// an unknown keyword) that nothing checks.

// enforcedKeywords are the schema keywords the validator enforces exactly or
// that carry no restriction (annotations, identifiers, local definitions).
// multipleOf is not among them: the validator divides in floating point, and
// a quotient beyond 2^53 rounds to an integer, so it is refused rather than
// enforced inexactly.
var enforcedKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "$defs": true, "definitions": true, "$comment": true, "$anchor": true,
	"title": true, "description": true, "default": true, "examples": true, "deprecated": true, "readOnly": true, "writeOnly": true,
	"type": true, "enum": true, "const": true,
	"maximum": true, "exclusiveMaximum": true, "minimum": true, "exclusiveMinimum": true,
	"maxLength": true, "minLength": true, "pattern": true,
	"maxItems": true, "minItems": true, "uniqueItems": true, "maxContains": true, "minContains": true,
	"maxProperties": true, "minProperties": true, "required": true, "dependentRequired": true,
	"properties": true, "patternProperties": true, "additionalProperties": true, "propertyNames": true,
	"items": true, "prefixItems": true, "contains": true,
	"allOf": true, "anyOf": true, "oneOf": true, "not": true, "if": true, "then": true, "else": true,
	"dependentSchemas": true, "unevaluatedItems": true, "unevaluatedProperties": true,
}

// Keywords whose value is a schema, an array of schemas, or a map of them.
var (
	subschemaKeywords = map[string]bool{"additionalProperties": true, "propertyNames": true, "items": true, "contains": true,
		"not": true, "if": true, "then": true, "else": true, "unevaluatedItems": true, "unevaluatedProperties": true}
	subschemaListKeywords = map[string]bool{"prefixItems": true, "allOf": true, "anyOf": true, "oneOf": true}
	subschemaMapKeywords  = map[string]bool{"properties": true, "patternProperties": true, "$defs": true, "definitions": true, "dependentSchemas": true}
)

// draft202012 is the only dialect admitted: its keywords are the ones the
// validator enforces as written (under draft-07 some are ignored).
const draft202012 = "https://json-schema.org/draft/2020-12/schema"

// maxExactNumber bounds every number in a schema or in parameters. Every
// number admitted is also exactly a float64 (an integer, or a binary
// fraction such as 0.5), so the validator, which compares float64 values,
// compares the numbers themselves.
var maxExactNumber = new(big.Rat).SetInt64(1 << 53)

// Limits on what is decoded, so a schema or parameters cannot make the
// check itself expensive.
const (
	maxNumberLiteral  = 64
	maxNumberExponent = 400
	maxJSONDepth      = 64
)

// compileParamSchema resolves a permitted action's param_schema, refusing a
// schema that is not strict JSON, is of another dialect than draft 2020-12,
// refers to a remote document, uses a keyword the validator does not
// enforce, or gives a keyword a value that is not valid for it.
func compileParamSchema(raw json.RawMessage) (*jsonschema.Resolved, error) {
	generic, err := strictJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("param_schema: %w", err)
	}
	root, ok := generic.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("param_schema must be a JSON Schema object")
	}
	if d, ok := root["$schema"]; ok && d != draft202012 {
		return nil, fmt.Errorf("param_schema must be JSON Schema draft 2020-12 (%s)", draft202012)
	}
	if err := checkSchemaKeywords(generic, "param_schema", true); err != nil {
		return nil, err
	}
	// The library reads integer-valued keywords as Go integers: give it
	// each one written as an integer (1.0 and 1e0 are 1), from the checked
	// value rather than the original bytes.
	normalized, err := json.Marshal(normalizeIntegerKeywords(generic))
	if err != nil {
		return nil, fmt.Errorf("param_schema: %w", err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(normalized, &schema); err != nil {
		return nil, fmt.Errorf("param_schema: %w", err)
	}
	if schema.Schema == "" {
		schema.Schema = draft202012
	}
	// No loader: a reference outside this schema is an error, never fetched.
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		return nil, fmt.Errorf("param_schema: %w", err)
	}
	return resolved, nil
}

func checkSchemaKeywords(v any, path string, root bool) error {
	switch s := v.(type) {
	case bool:
		return nil
	case map[string]any:
		keys := make([]string, 0, len(s))
		for k := range s {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !enforcedKeywords[k] {
				return fmt.Errorf("%s uses %q, which is not enforced", path, k)
			}
			if k == "$schema" && !root {
				return fmt.Errorf("%s changes the dialect; only the root may name it", path)
			}
			child := path + "." + k
			if err := checkKeywordValue(k, s[k], child); err != nil {
				return err
			}
			switch {
			case subschemaKeywords[k]:
				if err := checkSchemaKeywords(s[k], child, false); err != nil {
					return err
				}
			case subschemaListKeywords[k]:
				for i, e := range s[k].([]any) {
					if err := checkSchemaKeywords(e, fmt.Sprintf("%s[%d]", child, i), false); err != nil {
						return err
					}
				}
			case subschemaMapKeywords[k]:
				for name, e := range s[k].(map[string]any) {
					if err := checkSchemaKeywords(e, child+"."+name, false); err != nil {
						return err
					}
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("%s is not a schema", path)
	}
}

var schemaTypes = map[string]bool{"null": true, "boolean": true, "object": true, "array": true, "number": true, "string": true, "integer": true}

// checkKeywordValue checks that a keyword's value is valid for it, so a
// schema cannot register a constraint that fails every value or none.
func checkKeywordValue(k string, v any, path string) error {
	bad := func(want string) error { return fmt.Errorf("%s must be %s", path, want) }
	switch k {
	case "$schema", "$id", "$anchor", "$comment", "title", "description":
		if _, ok := v.(string); !ok {
			return bad("a string")
		}
	case "$ref":
		if ref, ok := v.(string); !ok || !strings.HasPrefix(ref, "#") {
			return fmt.Errorf("%s %v must refer inside the schema (start with #)", path, v)
		}
	case "type":
		switch t := v.(type) {
		case string:
			if !schemaTypes[t] {
				return bad("a JSON Schema type")
			}
		case []any:
			seen := map[string]bool{}
			for _, e := range t {
				n, ok := e.(string)
				if !ok || !schemaTypes[n] || seen[n] {
					return bad("distinct JSON Schema types")
				}
				seen[n] = true
			}
			if len(t) == 0 {
				return bad("a non-empty list of types")
			}
		default:
			return bad("a type or a list of types")
		}
	case "enum":
		if list, ok := v.([]any); !ok || len(list) == 0 {
			return bad("a non-empty array")
		}
	case "maximum", "minimum", "exclusiveMaximum", "exclusiveMinimum":
		if _, ok := v.(json.Number); !ok {
			return bad("a number")
		}
	case "maxLength", "minLength", "maxItems", "minItems", "maxContains", "minContains", "maxProperties", "minProperties":
		// By value, not spelling: 1, 1.0 and 1e0 are the same integer.
		n, ok := v.(json.Number)
		if !ok {
			return bad("a non-negative integer")
		}
		if r, _ := new(big.Rat).SetString(n.String()); r == nil || !r.IsInt() || r.Sign() < 0 {
			return bad("a non-negative integer")
		}
	// Patterns are Go RE2 (syntax and semantics, e.g. ASCII-only \s), the
	// dialect the validator applies; the API documents it, not ECMA-262.
	case "pattern":
		p, ok := v.(string)
		if !ok {
			return bad("a string")
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%s is not a valid pattern: %w", path, err)
		}
	case "patternProperties":
		m, ok := v.(map[string]any)
		if !ok {
			return bad("an object of schemas")
		}
		for p := range m {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("%s key %q is not a valid pattern: %w", path, p, err)
			}
		}
	case "uniqueItems", "deprecated", "readOnly", "writeOnly":
		if _, ok := v.(bool); !ok {
			return bad("a boolean")
		}
	case "required":
		if !distinctStrings(v) {
			return bad("an array of distinct strings")
		}
	case "dependentRequired":
		m, ok := v.(map[string]any)
		if !ok {
			return bad("an object of string arrays")
		}
		for _, e := range m {
			if !distinctStrings(e) {
				return bad("an object of arrays of distinct strings")
			}
		}
	case "examples":
		if _, ok := v.([]any); !ok {
			return bad("an array")
		}
	}
	switch {
	case subschemaListKeywords[k]:
		if list, ok := v.([]any); !ok || len(list) == 0 {
			return bad("a non-empty array of schemas")
		}
	case subschemaMapKeywords[k]:
		if _, ok := v.(map[string]any); !ok {
			return bad("an object of schemas")
		}
	}
	return nil
}

var integerKeywords = map[string]bool{"maxLength": true, "minLength": true, "maxItems": true, "minItems": true,
	"maxContains": true, "minContains": true, "maxProperties": true, "minProperties": true}

// normalizeIntegerKeywords rewrites integer-valued keywords, at any depth of
// subschemas, as integer literals. Their values were checked to be
// non-negative integers.
func normalizeIntegerKeywords(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if n, ok := e.(json.Number); ok && integerKeywords[k] {
				if r, _ := new(big.Rat).SetString(n.String()); r != nil && r.IsInt() {
					t[k] = json.Number(r.Num().String())
					continue
				}
			}
			t[k] = normalizeIntegerKeywords(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = normalizeIntegerKeywords(e)
		}
		return t
	}
	return v
}

func distinctStrings(v any) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	seen := map[string]bool{}
	for _, e := range list {
		s, ok := e.(string)
		if !ok || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// strictJSON decodes one JSON value, refusing duplicate object keys (which
// readers resolve differently) and numbers whose float64 value would not
// keep their magnitude or integrality. Numbers are returned as json.Number.
func strictJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := strictValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}

func strictValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("nested deeper than %d levels", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, _ := kt.(string)
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("duplicate key %q", k)
				}
				v, err := strictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			_, err := dec.Token()
			return m, err
		case '[':
			list := []any{}
			for dec.More() {
				v, err := strictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			_, err := dec.Token()
			return list, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	case json.Number:
		if err := checkExactNumber(t); err != nil {
			return nil, err
		}
		return t, nil
	default:
		return t, nil
	}
}

// checkExactNumber refuses a number beyond 2^53 in magnitude, or one that is
// not exactly a float64 (0.1 is not; 0.5 and 3 are): the validator compares
// float64 values, and only for these is that the number itself.
func checkExactNumber(n json.Number) error {
	// Bounded before any exact arithmetic: a long literal or a huge
	// exponent (1e1000000000) would make it arbitrarily expensive.
	lit := n.String()
	if len(lit) > maxNumberLiteral {
		return fmt.Errorf("number %.20s... is longer than %d characters", lit, maxNumberLiteral)
	}
	if i := strings.IndexAny(lit, "eE"); i >= 0 {
		exp, err := strconv.Atoi(strings.TrimPrefix(lit[i+1:], "+"))
		if err != nil || exp > maxNumberExponent || exp < -maxNumberExponent {
			return fmt.Errorf("number %s has an exponent beyond %d", lit, maxNumberExponent)
		}
	}
	r, ok := new(big.Rat).SetString(lit)
	if !ok {
		return fmt.Errorf("number %s is not valid", n)
	}
	if new(big.Rat).Abs(r).Cmp(maxExactNumber) > 0 {
		return fmt.Errorf("number %s is beyond 2^53 and cannot be checked exactly", n)
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		return fmt.Errorf("number %s is not valid", n)
	}
	if exact := new(big.Rat).SetFloat64(f); exact == nil || exact.Cmp(r) != 0 {
		return fmt.Errorf("number %s cannot be checked exactly; use an integer or a binary fraction such as 0.5", n)
	}
	return nil
}

// toFloats replaces json.Number with float64, the form the validator
// compares; checkExactNumber made that conversion faithful.
func toFloats(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, _ := strconv.ParseFloat(t.String(), 64)
		return f
	case map[string]any:
		for k, e := range t {
			t[k] = toFloats(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = toFloats(e)
		}
		return t
	}
	return v
}

// checkActionParams validates an action attempt's parameters against its
// permitted action's param_schema, if it declares one. Absent parameters are
// the empty object. The value checked is the parameters exactly as stored
// and passed to the action: duplicate keys and numbers that cannot be
// checked exactly are refused, and nothing is coerced.
func checkActionParams(pa PermittedAction, params json.RawMessage) error {
	if len(bytes.TrimSpace(pa.ParamSchema)) == 0 {
		return nil
	}
	resolved, err := compileParamSchema(pa.ParamSchema)
	if err != nil {
		return refuse(CodeInvalid, "action %q: %v", pa.Name, err)
	}
	raw := bytes.TrimSpace(params)
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	instance, err := strictJSON(raw)
	if err != nil {
		return refuse(CodeInvalid, "action %q params: %v", pa.Name, err)
	}
	if err := resolved.Validate(toFloats(instance)); err != nil {
		return refuse(CodeInvalid, "action %q params do not match its param_schema: %v", pa.Name, err)
	}
	return nil
}
