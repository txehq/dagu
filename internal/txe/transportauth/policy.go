// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth

import (
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Surface says who may call a method.
type Surface string

const (
	// SurfacePublic needs no credential. Only the health service is public:
	// it tells a caller whether the coordinator is up and nothing else.
	SurfacePublic Surface = "public"
	// SurfaceWorker is what an enrolled worker machine calls to take and run
	// its work. The hub may call it too.
	SurfaceWorker Surface = "worker"
	// SurfaceScoped is a worker method that names a resource and carries no
	// attempt to fence it. A machine may call it only when a
	// ResourceAuthorizer allows that machine that resource.
	SurfaceScoped Surface = "scoped"
	// SurfaceHub is what only the hub's own processes call: dispatching,
	// listing workers, cancelling, state and sub-DAG support.
	SurfaceHub Surface = "hub"
)

// methodSurfaces is every method the coordinator serves. A method that is
// not listed is refused to every caller, so a method added to the service
// later is closed until someone decides who may call it.
var methodSurfaces = map[string]Surface{
	grpc_health_v1.Health_Check_FullMethodName: SurfacePublic,
	grpc_health_v1.Health_Watch_FullMethodName: SurfacePublic,
	grpc_health_v1.Health_List_FullMethodName:  SurfacePublic,

	coordinatorv1.CoordinatorService_Poll_FullMethodName:                        SurfaceWorker,
	coordinatorv1.CoordinatorService_Heartbeat_FullMethodName:                   SurfaceWorker,
	coordinatorv1.CoordinatorService_AckTaskClaim_FullMethodName:                SurfaceWorker,
	coordinatorv1.CoordinatorService_RunHeartbeat_FullMethodName:                SurfaceWorker,
	coordinatorv1.CoordinatorService_ReportStatus_FullMethodName:                SurfaceWorker,
	coordinatorv1.CoordinatorService_StreamLogs_FullMethodName:                  SurfaceWorker,
	coordinatorv1.CoordinatorService_StreamArtifacts_FullMethodName:             SurfaceWorker,
	coordinatorv1.CoordinatorService_ResolveSecretReference_FullMethodName:      SurfaceWorker,
	coordinatorv1.CoordinatorService_ResolveRuntimeProfile_FullMethodName:       SurfaceWorker,
	coordinatorv1.CoordinatorService_ClaimAgentSessionCleanup_FullMethodName:    SurfaceWorker,
	coordinatorv1.CoordinatorService_CompleteAgentSessionCleanup_FullMethodName: SurfaceWorker,

	coordinatorv1.CoordinatorService_GetWorkspaceBundle_FullMethodName: SurfaceScoped,

	coordinatorv1.CoordinatorService_Dispatch_FullMethodName:           SurfaceHub,
	coordinatorv1.CoordinatorService_GetWorkers_FullMethodName:         SurfaceHub,
	coordinatorv1.CoordinatorService_RequestCancel_FullMethodName:      SurfaceHub,
	coordinatorv1.CoordinatorService_GetDAGRunStatus_FullMethodName:    SurfaceHub,
	coordinatorv1.CoordinatorService_GetDAG_FullMethodName:             SurfaceHub,
	coordinatorv1.CoordinatorService_PutWorkspaceBundle_FullMethodName: SurfaceHub,
	coordinatorv1.CoordinatorService_HasWorkspaceBundle_FullMethodName: SurfaceHub,
	coordinatorv1.CoordinatorService_GetState_FullMethodName:           SurfaceHub,
	coordinatorv1.CoordinatorService_PutState_FullMethodName:           SurfaceHub,
	coordinatorv1.CoordinatorService_DeleteState_FullMethodName:        SurfaceHub,
	coordinatorv1.CoordinatorService_ListState_FullMethodName:          SurfaceHub,
}

// SurfaceOf returns the surface of a full method name, and false for a
// method that is not listed.
func SurfaceOf(fullMethod string) (Surface, bool) {
	surface, ok := methodSurfaces[fullMethod]
	return surface, ok
}

// workerIDCarrier is a request that names the worker sending it.
type workerIDCarrier interface{ GetWorkerId() string }

// labelCarrier is a request that declares the worker's labels.
type labelCarrier interface{ GetLabels() map[string]string }

// carriesWorkerID lists the worker-surface requests that must name their
// worker. Every one of them is checked against the caller's machine.
var carriesWorkerID = map[string]bool{
	coordinatorv1.CoordinatorService_Poll_FullMethodName:                        true,
	coordinatorv1.CoordinatorService_Heartbeat_FullMethodName:                   true,
	coordinatorv1.CoordinatorService_AckTaskClaim_FullMethodName:                true,
	coordinatorv1.CoordinatorService_RunHeartbeat_FullMethodName:                true,
	coordinatorv1.CoordinatorService_ReportStatus_FullMethodName:                true,
	coordinatorv1.CoordinatorService_StreamLogs_FullMethodName:                  true,
	coordinatorv1.CoordinatorService_StreamArtifacts_FullMethodName:             true,
	coordinatorv1.CoordinatorService_ResolveSecretReference_FullMethodName:      true,
	coordinatorv1.CoordinatorService_ResolveRuntimeProfile_FullMethodName:       true,
	coordinatorv1.CoordinatorService_ClaimAgentSessionCleanup_FullMethodName:    true,
	coordinatorv1.CoordinatorService_CompleteAgentSessionCleanup_FullMethodName: true,
}

// carriesLabels lists the requests whose labels are the worker's own and
// decide which tasks it is given.
var carriesLabels = map[string]bool{
	coordinatorv1.CoordinatorService_Poll_FullMethodName:      true,
	coordinatorv1.CoordinatorService_Heartbeat_FullMethodName: true,
}
