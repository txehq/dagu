// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// testdata/coordinator-txe-v2.18.2-19.pb is the descriptor of the coordinator
// service released as txe-v2.18.2-19, made with the repository's protoc from
// that tag's proto/coordinator/v1/coordinator.proto (sha256 44577b067d21…):
//
//	protoc --include_imports --descriptor_set_out=... proto/coordinator/v1/coordinator.proto
//
// A hub and a worker of different releases meet during an upgrade and a
// rollback, so every method -19 serves must still be served, under the same
// name and stream shape, and every field of every message it sends or reads
// must keep its number, kind and cardinality. A field one side does not know
// is skipped by the other, so added fields are allowed.
const releasedDescriptor = "testdata/coordinator-txe-v2.18.2-19.pb"

func loadReleasedService(t *testing.T) protoreflect.ServiceDescriptor {
	t.Helper()
	data, err := os.ReadFile(releasedDescriptor)
	require.NoError(t, err)
	var set descriptorpb.FileDescriptorSet
	require.NoError(t, proto.Unmarshal(data, &set))
	files, err := protodesc.NewFiles(&set)
	require.NoError(t, err)
	d, err := files.FindDescriptorByName("coordinator.v1.CoordinatorService")
	require.NoError(t, err)
	return d.(protoreflect.ServiceDescriptor)
}

func currentService(t *testing.T) protoreflect.ServiceDescriptor {
	t.Helper()
	svc := coordinatorv1.File_proto_coordinator_v1_coordinator_proto.Services().ByName("CoordinatorService")
	require.NotNil(t, svc)
	return svc
}

func TestWireCompatibleWithReleasedNineteen(t *testing.T) {
	old := loadReleasedService(t)
	cur := currentService(t)

	for i := range old.Methods().Len() {
		om := old.Methods().Get(i)
		t.Run(string(om.Name()), func(t *testing.T) {
			cm := cur.Methods().ByName(om.Name())
			require.NotNil(t, cm, "method %s is gone", om.Name())
			assert.Equal(t, om.IsStreamingClient(), cm.IsStreamingClient())
			assert.Equal(t, om.IsStreamingServer(), cm.IsStreamingServer())
			assertMessageCompatible(t, om.Input(), cm.Input(), map[protoreflect.FullName]bool{})
			assertMessageCompatible(t, om.Output(), cm.Output(), map[protoreflect.FullName]bool{})
		})
	}
}

func assertMessageCompatible(t *testing.T, old, cur protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[old.FullName()] {
		return
	}
	seen[old.FullName()] = true
	assert.Equal(t, old.FullName(), cur.FullName())
	for i := range old.Fields().Len() {
		of := old.Fields().Get(i)
		cf := cur.Fields().ByNumber(of.Number())
		if !assert.NotNil(t, cf, "%s field %d (%s) is gone", old.FullName(), of.Number(), of.Name()) {
			continue
		}
		assert.Equal(t, of.Kind(), cf.Kind(), "%s field %d kind", old.FullName(), of.Number())
		assert.Equal(t, of.Cardinality(), cf.Cardinality(), "%s field %d cardinality", old.FullName(), of.Number())
		assert.Equal(t, of.IsMap(), cf.IsMap(), "%s field %d map", old.FullName(), of.Number())
		if of.Message() != nil && cf.Message() != nil {
			assertMessageCompatible(t, of.Message(), cf.Message(), seen)
		}
		if of.Enum() != nil && cf.Enum() != nil {
			for j := range of.Enum().Values().Len() {
				ov := of.Enum().Values().Get(j)
				cv := cf.Enum().Values().ByNumber(ov.Number())
				assert.NotNil(t, cv, "%s value %d is gone", of.Enum().FullName(), ov.Number())
			}
		}
	}
}

// Every method the merged coordinator serves has a surface, so none is open
// or closed by accident after the upstream merge; the worker surface is the
// same eleven methods as in -19.
func TestEveryMethodHasASurface(t *testing.T) {
	cur := currentService(t)
	var worker []string
	for i := range cur.Methods().Len() {
		m := cur.Methods().Get(i)
		full := "/" + string(cur.FullName()) + "/" + string(m.Name())
		surface, ok := transportauth.SurfaceOf(full)
		require.True(t, ok, "%s has no surface", full)
		if surface == transportauth.SurfaceWorker {
			worker = append(worker, string(m.Name()))
		}
	}
	assert.Len(t, worker, 11, strings.Join(worker, ", "))
}
