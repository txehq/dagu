// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ErrPacketTooLarge means a job's context cannot be reduced to the packet
// limit. The job is not reviewed until that is resolved.
var ErrPacketTooLarge = errors.New("txe review: context packet exceeds its size limit")

// PacketSchemaVersion is the version of the context packet format.
const PacketSchemaVersion = 1

// MaxPacketBytes bounds the whole packet, and what it must fit is not only
// the agent's context. The reviewer DAG hands the packet from the prepare
// step to the later steps as a step output, and the service puts a step's
// output into the environment of every later step's process. On Linux one
// environment string, name and terminator included, may be at most 128 KiB
// (MAX_ARG_STRLEN, 32 pages of 4 KiB); a process given a longer one is not
// started at all. A packet over that would stop the agent from starting on
// every tick, with the same evidence waiting each time. So the bound is
// 120 KiB, which leaves room for the variable's name and for the service
// to frame the value. Carrying more context than this means handing the
// packet over in a file instead, which is capacity work.
const MaxPacketBytes = 120 << 10

const (
	// maxPacketRuns bounds one review. Runs beyond it stay after the
	// checkpoint and are reviewed in the next episode.
	maxPacketRuns     = 50
	maxOutputValueLen = 4096
	// maxRunSteps bounds the steps of one run that carry their own output.
	maxRunSteps = 12
	// maxPacketBytes bounds the whole packet; see MaxPacketBytes.
	maxPacketBytes      = MaxPacketBytes
	maxPacketFeedback   = 50
	maxPacketProposals  = 50
	maxPacketUnresolved = 50
	maxRecentActions    = 20
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
	// EvidenceTrimmed is true when a run's step output had to be shortened
	// or its early steps left out. Runs that did not fit are not in the
	// packet at all and stay for the next review.
	EvidenceTrimmed bool `json:"evidence_trimmed,omitempty"`
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

// coveredExecutions names the packet's runs with the execution of each
// that it shows.
func (p Packet) coveredExecutions() []string {
	var out []string
	for _, r := range p.NewRuns {
		// Only an identified execution is named. A run is never recorded
		// under its id alone: that would cover its later executions too.
		if e := r.Execution(); e.known() {
			out = append(out, coveredKey(r.RunID, e.Ref()))
		}
	}
	return out
}

// trimmedExecutions names the packet's runs whose evidence was shortened to
// fit: steps left out, or step output cut to its end.
func (p Packet) trimmedExecutions() []string {
	var out []string
	for _, r := range p.NewRuns {
		if e := r.Execution(); r.EvidenceTrimmed && e.known() {
			out = append(out, coveredKey(r.RunID, e.Ref()))
		}
	}
	return out
}

// trimmedCaveat is what a recommendation to end a job must tell the owner
// about everything the review behind it was not shown. Evidence nobody saw
// cannot support the conclusion that a job is done or should stop, so each
// kind of it is named: runs shown with evidence left out, runs whose steps
// printed more than was shown, runs that were not shown at all, and other
// records that were left out to fit. It is empty only when the review was
// shown everything there was.
func (p Packet) trimmedCaveat() string {
	var trimmed, partial []string
	for _, r := range p.NewRuns {
		switch {
		case r.EvidenceTrimmed:
			trimmed = append(trimmed, r.RunID)
		case r.outputTruncated():
			partial = append(partial, r.RunID)
		}
	}
	var gaps []string
	if len(trimmed) > 0 {
		gaps = append(gaps, fmt.Sprintf("%d run(s) with part of their evidence left out to fit (%s)", len(trimmed), someOf(trimmed)))
	}
	if len(partial) > 0 {
		gaps = append(gaps, fmt.Sprintf("%d run(s) whose steps printed more than the end that was shown (%s)", len(partial), someOf(partial)))
	}
	if p.MoreRunsPending {
		gaps = append(gaps, "later runs or decisions that were not shown at all and wait for the next review")
	}
	if p.EvidenceTrimmed && len(trimmed) == 0 {
		gaps = append(gaps, "open proposals or unresolved actions that were left out to fit")
	}
	if len(gaps) == 0 {
		return ""
	}
	return " This review was not shown everything: " + strings.Join(gaps, "; ") +
		". What it was not shown is not evidence for this recommendation: check it yourself before deciding."
}

// someOf lists a few ids and counts the rest.
func someOf(ids []string) string {
	const shown = 5
	list := strings.Join(ids[:min(len(ids), shown)], ", ")
	if len(ids) > shown {
		list += fmt.Sprintf(" and %d more", len(ids)-shown)
	}
	return list
}

// run returns the finished run with this id that the packet shows.
func (p Packet) run(id string) (RunEvidence, bool) {
	for _, r := range p.NewRuns {
		if r.RunID == id {
			return r, true
		}
	}
	return RunEvidence{}, false
}

func buildPacket(now time.Time, job Job, cp Checkpoint, runs []RunEvidence, decisions []Decision, proposals []Proposal, actions []Action) (Packet, error) {
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
	// Every list in the packet is bounded, not only the runs. Feedback
	// beyond the bound stays after the cursor for the next review, the
	// same as runs; the oldest is kept so nothing is skipped.
	if len(p.HumanFeedback) > maxPacketFeedback {
		p.HumanFeedback = p.HumanFeedback[:maxPacketFeedback]
		p.MoreRunsPending = true
	}
	if n := len(p.OpenProposals); n > maxPacketProposals {
		p.OpenProposals = p.OpenProposals[n-maxPacketProposals:]
		p.EvidenceTrimmed = true
	}
	if len(runs) > maxPacketRuns {
		runs = runs[:maxPacketRuns]
		p.MoreRunsPending = true
	}
	for _, r := range runs {
		var cut bool
		if r.Outputs, cut = truncateOutputs(r.Outputs); cut {
			r.EvidenceTrimmed, p.EvidenceTrimmed = true, true
		}
		if len(r.Steps) > maxRunSteps {
			r.Steps, r.OmittedSteps = boundSteps(r.Steps)
			r.EvidenceTrimmed, p.EvidenceTrimmed = true, true
		}
		p.NewRuns = append(p.NewRuns, r)
	}
	awaiting := map[string]bool{}
	for _, proposal := range proposals {
		if proposal.RelatedAction != "" {
			awaiting[proposal.RelatedAction] = true
		}
	}
	for _, a := range actions {
		// An escalated action is still unresolved while its question to
		// the owner is open.
		if a.State.Open() || (a.State == ActionEscalated && awaiting[a.ID]) {
			p.UnresolvedActions = append(p.UnresolvedActions, a)
		}
	}
	// What the agent is shown of unresolved actions is bounded; what blocks
	// an action from running again is checked against the full journal.
	if n := len(p.UnresolvedActions); n > maxPacketUnresolved {
		p.UnresolvedActions = p.UnresolvedActions[n-maxPacketUnresolved:]
		p.EvidenceTrimmed = true
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
	p.trim()
	// A packet that still does not fit is not sent at all. Its size comes
	// from what the job itself registered or from one enormous record, and
	// a review of a truncated contract would be a review of something else.
	if size := p.size(); size > maxPacketBytes {
		return Packet{}, fmt.Errorf("%w: %d bytes, limit %d", ErrPacketTooLarge, size, maxPacketBytes)
	}
	return p, nil
}

// truncateOutputs bounds each output value and reports whether any was cut.
func truncateOutputs(outputs map[string]string) (bounded map[string]string, cut bool) {
	if len(outputs) == 0 {
		return outputs, false
	}
	out := make(map[string]string, len(outputs))
	for k, v := range outputs {
		if len(v) > maxOutputValueLen {
			v, cut = v[:maxOutputValueLen]+"...[truncated]", true
		}
		out[k] = v
	}
	return out, cut
}

// trim keeps the packet within its size limit without hiding evidence from
// a review that then covers it. Runs that do not fit are left out of the
// packet, newest first, so the checkpoint advances only over runs the agent
// was shown in full and the rest are reviewed in the next episode. Only when
// a single run is itself too large is its step output shortened, and the
// packet then says so.
// runCursor is the cursor that covers the packet's runs and nothing after
// them, or empty when the packet shows no new run. It is read while the
// runs still carry the cursors the registry adapter gave them, before the
// packet is handed on.
func (p Packet) runCursor() string {
	n := len(p.NewRuns)
	if n == 0 {
		return ""
	}
	if last := p.NewRuns[n-1]; last.Cursor != "" {
		return last.Cursor
	}
	return p.NewRuns[n-1].RunID
}

func (p *Packet) trim() {
	for p.size() > maxPacketBytes && len(p.NewRuns) > 1 {
		p.NewRuns = p.NewRuns[:len(p.NewRuns)-1]
		p.MoreRunsPending = true
	}
	for limit := stepTailFloor * 8; p.size() > maxPacketBytes && limit >= stepTailFloor; limit /= 2 {
		p.EvidenceTrimmed = true
		for i := range p.NewRuns {
			for j := range p.NewRuns[i].Steps {
				step := &p.NewRuns[i].Steps[j]
				before := len(step.Stdout) + len(step.Stderr)
				step.Stdout, step.Stderr = keepTail(step.Stdout, limit), keepTail(step.Stderr, limit)
				if len(step.Stdout)+len(step.Stderr) != before {
					step.Truncated, p.NewRuns[i].EvidenceTrimmed = true, true
				}
			}
		}
	}
}

// boundSteps keeps at most maxRunSteps of a run's steps, in their order,
// and counts by status the ones it leaves out.
//
// What is kept is chosen by what a review most needs to see, never by
// position alone, so a job cannot push a failure out of view by adding
// steps around it: failed, aborted and rejected steps first, the earliest
// of them always, since that is usually where the run went wrong, then the
// latest; next every status that is neither a plain success nor a step
// that did not run, which includes any status this code does not know;
// then steps that did not run; and steps that succeeded last. Within a
// class the latest steps are kept, which are where the run ended.
func boundSteps(steps []StepEvidence) (kept []StepEvidence, omitted map[string]int) {
	keep := make([]bool, len(steps))
	left := maxRunSteps
	take := func(i int) {
		if left > 0 && !keep[i] {
			keep[i] = true
			left--
		}
	}
	for i, step := range steps {
		if stepRank(step.Status) == 0 {
			take(i)
			break
		}
	}
	for rank := 0; rank <= stepRankSucceeded; rank++ {
		for i, step := range slices.Backward(steps) {
			if stepRank(step.Status) == rank {
				take(i)
			}
		}
	}
	kept = make([]StepEvidence, 0, maxRunSteps)
	for i, step := range steps {
		if keep[i] {
			kept = append(kept, step)
			continue
		}
		if omitted == nil {
			omitted = map[string]int{}
		}
		omitted[step.Status]++
	}
	return kept, omitted
}

// stepRankSucceeded is the rank of a step that simply succeeded: the last
// to be kept.
const stepRankSucceeded = 3

// stepRank orders step statuses by how much a review needs to see them;
// lower is kept first. A status that is not listed is ranked with the ones
// that need attention, not with the harmless ones.
func stepRank(status string) int {
	switch status {
	case "failed", "aborted", "rejected":
		return 0
	case "skipped", "not_started":
		return 2
	case "succeeded":
		return stepRankSucceeded
	default:
		return 1
	}
}

// stepTailFloor is the least step output kept per stream when one run alone
// exceeds the packet limit.
const stepTailFloor = 256

func keepTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
