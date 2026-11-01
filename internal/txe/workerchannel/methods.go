// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// addMethods and its Conn counterpart are every method a machine may call,
// written out so that a method added to the coordinator is carried only when
// someone decides it should be. txe/worker/HTTPS-CHANNEL.md has the table.

func streamHandler(name string) grpc.StreamHandler {
	for _, s := range coordinatorv1.CoordinatorService_ServiceDesc.Streams {
		if s.StreamName == name {
			return s.Handler
		}
	}
	return nil
}

func (h *Handler) addMethods(svc coordinatorv1.CoordinatorServiceServer, hc grpc_health_v1.HealthServer) {
	addUnary(h, coordinatorv1.CoordinatorService_Poll_FullMethodName, svc.Poll)
	addUnary(h, coordinatorv1.CoordinatorService_Heartbeat_FullMethodName, svc.Heartbeat)
	addUnary(h, coordinatorv1.CoordinatorService_AckTaskClaim_FullMethodName, svc.AckTaskClaim)
	addUnary(h, coordinatorv1.CoordinatorService_RunHeartbeat_FullMethodName, svc.RunHeartbeat)
	addUnary(h, coordinatorv1.CoordinatorService_ReportStatus_FullMethodName, svc.ReportStatus)
	addUnary(h, coordinatorv1.CoordinatorService_ResolveSecretReference_FullMethodName, svc.ResolveSecretReference)
	addUnary(h, coordinatorv1.CoordinatorService_ResolveRuntimeProfile_FullMethodName, svc.ResolveRuntimeProfile)
	addUnary(h, coordinatorv1.CoordinatorService_ClaimAgentSessionCleanup_FullMethodName, svc.ClaimAgentSessionCleanup)
	addUnary(h, coordinatorv1.CoordinatorService_CompleteAgentSessionCleanup_FullMethodName, svc.CompleteAgentSessionCleanup)
	addUnary(h, grpc_health_v1.Health_Check_FullMethodName, hc.Check)

	addStream[coordinatorv1.LogChunk, coordinatorv1.StreamLogsResponse](h,
		coordinatorv1.CoordinatorService_StreamLogs_FullMethodName, svc, streamHandler("StreamLogs"))
	addStream[coordinatorv1.ArtifactChunk, coordinatorv1.StreamArtifactsResponse](h,
		coordinatorv1.CoordinatorService_StreamArtifacts_FullMethodName, svc, streamHandler("StreamArtifacts"))
}

func (c *Conn) addMethods() {
	addCall[coordinatorv1.PollRequest, coordinatorv1.PollResponse](c, coordinatorv1.CoordinatorService_Poll_FullMethodName)
	addCall[coordinatorv1.HeartbeatRequest, coordinatorv1.HeartbeatResponse](c, coordinatorv1.CoordinatorService_Heartbeat_FullMethodName)
	addCall[coordinatorv1.AckTaskClaimRequest, coordinatorv1.AckTaskClaimResponse](c, coordinatorv1.CoordinatorService_AckTaskClaim_FullMethodName)
	addCall[coordinatorv1.RunHeartbeatRequest, coordinatorv1.RunHeartbeatResponse](c, coordinatorv1.CoordinatorService_RunHeartbeat_FullMethodName)
	addCall[coordinatorv1.ReportStatusRequest, coordinatorv1.ReportStatusResponse](c, coordinatorv1.CoordinatorService_ReportStatus_FullMethodName)
	addCall[coordinatorv1.ResolveSecretReferenceRequest, coordinatorv1.ResolveSecretReferenceResponse](c, coordinatorv1.CoordinatorService_ResolveSecretReference_FullMethodName)
	addCall[coordinatorv1.ResolveRuntimeProfileRequest, coordinatorv1.ResolveRuntimeProfileResponse](c, coordinatorv1.CoordinatorService_ResolveRuntimeProfile_FullMethodName)
	addCall[coordinatorv1.ClaimAgentSessionCleanupRequest, coordinatorv1.ClaimAgentSessionCleanupResponse](c, coordinatorv1.CoordinatorService_ClaimAgentSessionCleanup_FullMethodName)
	addCall[coordinatorv1.CompleteAgentSessionCleanupRequest, coordinatorv1.CompleteAgentSessionCleanupResponse](c, coordinatorv1.CoordinatorService_CompleteAgentSessionCleanup_FullMethodName)
	addCall[grpc_health_v1.HealthCheckRequest, grpc_health_v1.HealthCheckResponse](c, grpc_health_v1.Health_Check_FullMethodName)

	addClientStream[coordinatorv1.LogChunk, coordinatorv1.StreamLogsResponse](c, coordinatorv1.CoordinatorService_StreamLogs_FullMethodName)
	addClientStream[coordinatorv1.ArtifactChunk, coordinatorv1.StreamArtifactsResponse](c, coordinatorv1.CoordinatorService_StreamArtifacts_FullMethodName)
}
