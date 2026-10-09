// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// A permitted action's param_schema is a JSON Schema (draft 2020-12 or
// draft-07) that the registry enforces on every attempt of that action
// before it is granted. It is checked when a version is registered: it must
// resolve with no remote reference, and it may use only keywords the
// validator enforces, so a schema never promises a restriction (a format,
// an unknown keyword) that nothing checks.

// enforcedKeywords are the schema keywords the validator enforces or that
// carry no restriction (annotations, identifiers, local definitions).
var enforcedKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "$defs": true, "definitions": true, "$comment": true, "$anchor": true,
	"title": true, "description": true, "default": true, "examples": true, "deprecated": true, "readOnly": true, "writeOnly": true,
	"type": true, "enum": true, "const": true,
	"multipleOf": true, "maximum": true, "exclusiveMaximum": true, "minimum": true, "exclusiveMinimum": true,
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

// compileParamSchema resolves a permitted action's param_schema, refusing a
// schema that is invalid, refers to a remote document, or uses a keyword the
// validator does not enforce.
func compileParamSchema(raw json.RawMessage) (*jsonschema.Resolved, error) {
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("param_schema is not JSON: %w", err)
	}
	if _, ok := generic.(map[string]any); !ok {
		return nil, fmt.Errorf("param_schema must be a JSON Schema object")
	}
	if err := checkSchemaKeywords(generic, "param_schema"); err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Errorf("param_schema: %w", err)
	}
	// No loader: a reference outside this schema is an error, never fetched.
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		return nil, fmt.Errorf("param_schema: %w", err)
	}
	return resolved, nil
}

func checkSchemaKeywords(v any, path string) error {
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
			if k == "$ref" {
				if ref, _ := s[k].(string); !strings.HasPrefix(ref, "#") {
					return fmt.Errorf("%s.$ref %q refers outside the schema", path, s[k])
				}
			}
			child := path + "." + k
			switch {
			case subschemaKeywords[k]:
				if err := checkSchemaKeywords(s[k], child); err != nil {
					return err
				}
			case subschemaListKeywords[k]:
				list, ok := s[k].([]any)
				if !ok {
					return fmt.Errorf("%s must be an array of schemas", child)
				}
				for i, e := range list {
					if err := checkSchemaKeywords(e, fmt.Sprintf("%s[%d]", child, i)); err != nil {
						return err
					}
				}
			case subschemaMapKeywords[k]:
				m, ok := s[k].(map[string]any)
				if !ok {
					return fmt.Errorf("%s must be an object of schemas", child)
				}
				for name, e := range m {
					if err := checkSchemaKeywords(e, child+"."+name); err != nil {
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

// checkActionParams validates an action attempt's parameters against its
// permitted action's param_schema, if it declares one. Absent parameters are
// the empty object. The value checked is the parameters exactly as stored
// and passed to the action; nothing is coerced.
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
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		return refuse(CodeInvalid, "action %q params are not JSON: %v", pa.Name, err)
	}
	if err := resolved.Validate(instance); err != nil {
		return refuse(CodeInvalid, "action %q params do not match its param_schema: %v", pa.Name, err)
	}
	return nil
}
