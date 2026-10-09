// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"encoding/json"
	"time"
)

// PacketSchemaVersion is the version of the context packet format.
const PacketSchemaVersion = 1

const (
	// maxPacketRuns bounds one review. Runs beyond it stay after the
	// checkpoint and are reviewed in the next episode.
	maxPacketRuns     = 50
	maxOutputValueLen = 4096
	maxRecentActions  = 20
)

// Packet is everything a fresh reviewer is given. It must be sufficient
// without the conversation that created the job.
type Packet struct {
	SchemaVersion int       `json:"schema_version"`
	ReviewID      string    `json:"review_id"`
	Episode       int       `json:"episode"`
	GeneratedAt   time.Time `json:"generated_at"`
	Job           Job       `json:"job"`
	// NewRuns are the job's results since the last checkpoint.
	NewRuns []RunEvidence `json:"new_runs"`
	// HumanFeedback are decisions made since the last checkpoint. Their
	// instructions are guidance; they never widen the job's declared actions.
	HumanFeedback []Decision `json:"human_feedback"`
	OpenProposals []Proposal `json:"open_proposals"`
	// UnresolvedActions have an external effect whose outcome is not settled.
	UnresolvedActions []Action `json:"unresolved_actions"`
	RecentActions     []Action `json:"recent_actions"`
	// MoreRunsPending is true when results beyond this packet exist.
	MoreRunsPending bool `json:"more_runs_pending,omitempty"`
}

// RunIDs returns the ids of the runs the packet covers.
func (p Packet) RunIDs() []string {
	ids := make([]string, 0, len(p.NewRuns))
	for _, r := range p.NewRuns {
		ids = append(ids, r.RunID)
	}
	return ids
}

// DecisionIDs returns the ids of the human decisions the packet covers.
func (p Packet) DecisionIDs() []string {
	ids := make([]string, 0, len(p.HumanFeedback))
	for _, d := range p.HumanFeedback {
		ids = append(ids, d.ID)
	}
	return ids
}

// size is the length of the packet as the agent receives it.
func (p Packet) size() int {
	b, err := json.Marshal(p)
	if err != nil {
		return 0
	}
	return len(b)
}

// artifactRefs returns the artifacts of the given runs.
func (p Packet) artifactRefs(runIDs []string) []string {
	var refs []string
	for _, r := range p.NewRuns {
		for _, id := range runIDs {
			if r.RunID == id {
				refs = append(refs, r.Artifacts...)
			}
		}
	}
	return refs
}

func (p Packet) hasRun(id string) bool {
	for _, r := range p.NewRuns {
		if r.RunID == id {
			return true
		}
	}
	return false
}

func buildPacket(now time.Time, job Job, cp Checkpoint, runs []RunEvidence, decisions []Decision, proposals []Proposal, actions []Action) Packet {
	p := Packet{
		SchemaVersion: PacketSchemaVersion,
		ReviewID:      ReviewID(job.ID, cp.Version),
		Episode:       cp.Version,
		GeneratedAt:   now,
		Job:           job,
		NewRuns:       []RunEvidence{},
		HumanFeedback: decisions,
		OpenProposals: proposals,
	}
	if len(runs) > maxPacketRuns {
		runs = runs[:maxPacketRuns]
		p.MoreRunsPending = true
	}
	for _, r := range runs {
		r.Outputs = truncateOutputs(r.Outputs)
		p.NewRuns = append(p.NewRuns, r)
	}
	for _, a := range actions {
		if a.State.Open() {
			p.UnresolvedActions = append(p.UnresolvedActions, a)
		}
	}
	if n := len(actions); n > maxRecentActions {
		actions = actions[n-maxRecentActions:]
	}
	p.RecentActions = actions
	if p.HumanFeedback == nil {
		p.HumanFeedback = []Decision{}
	}
	if p.OpenProposals == nil {
		p.OpenProposals = []Proposal{}
	}
	if p.UnresolvedActions == nil {
		p.UnresolvedActions = []Action{}
	}
	if p.RecentActions == nil {
		p.RecentActions = []Action{}
	}
	return p
}

func truncateOutputs(outputs map[string]string) map[string]string {
	if len(outputs) == 0 {
		return outputs
	}
	out := make(map[string]string, len(outputs))
	for k, v := range outputs {
		if len(v) > maxOutputValueLen {
			v = v[:maxOutputValueLen] + "...[truncated]"
		}
		out[k] = v
	}
	return out
}
