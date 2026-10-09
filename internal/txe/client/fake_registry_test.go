// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeRegistry implements the part of /api/v1/txe that registration uses,
// with the rules the CLI relies on: a job key is unique within a project, a
// request sent again returns what was stored, an outdated expected_version or
// expected_revision is refused, and a job is ready only after its package is
// asserted.
type fakeRegistry struct {
	t      *testing.T
	server *httptest.Server

	mu       sync.Mutex
	machines map[string]Machine
	projects map[string]Project // by key
	jobs     map[string]*fakeJob
	byKey    map[string]string // project + "/" + job key -> job id
	requests []recordedRequest
	// manifests holds the manifest last accepted per job and run;
	// executions holds every accepted manifest, per job, run and execution
	// reference.
	manifests  map[string]ArtifactManifest
	executions map[string]ArtifactManifest
	// latest is the execution a run is in, as the hub knows it. A run not
	// listed accepts any execution.
	latest map[string]Execution

	// capabilities is what the installation record says the registry
	// enforces. A new fake lists none, as a registry that only stores does.
	capabilities []string

	// beforeList, when set, runs before a job listing is answered.
	beforeList func()
	// loseResponse makes the next matching request take effect and then
	// answer 502, as when a response is lost on the way back.
	loseResponse map[string]int
	// fail makes the next matching request answer 500 without taking effect.
	fail map[string]int
	// failNextReady fails the next ready call once, whatever its job.
	failNextReady bool
	// loseNextReady applies the next ready call and then loses its answer.
	loseNextReady bool
}

type fakeJob struct {
	Job
	requestID   string
	requestHash string
	versions    map[int]json.RawMessage
	// events is the job's history, oldest first.
	events []map[string]any
}

type recordedRequest struct {
	Method, Path string
	Body         []byte
	// Status and Response are what the fake answered.
	Status   int
	Response []byte
}

// capture records what a handler writes while passing it through.
type capture struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (c *capture) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *capture) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.body.Write(p)
	return c.ResponseWriter.Write(p)
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{
		t:            t,
		machines:     map[string]Machine{},
		projects:     map[string]Project{},
		jobs:         map[string]*fakeJob{},
		byKey:        map[string]string{},
		manifests:    map[string]ArtifactManifest{},
		executions:   map[string]ArtifactManifest{},
		latest:       map[string]Execution{},
		loseResponse: map[string]int{},
		fail:         map[string]int{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeRegistry) client() *Client {
	return New(f.server.URL, "dagu_test_key", f.server.Client())
}

// calls returns how many requests were made with the method and path.
func (f *fakeRegistry) calls(method, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func (f *fakeRegistry) job(id string) Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobs[id].Job
}

// versionCount is how many versions the registry holds for a job.
func (f *fakeRegistry) versionCount(jobID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if j, ok := f.jobs[jobID]; ok {
		return len(j.versions)
	}
	return 0
}

func (f *fakeRegistry) jobCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.jobs)
}

func refuse(w http.ResponseWriter, status int, code, message string, current any) {
	envelope := map[string]any{"code": "conflict", "message": message, "details": map[string]any{"code": code}}
	if current != nil {
		envelope["details"].(map[string]any)["current"] = current
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope)
}

func answer(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	recorded := &capture{ResponseWriter: w}
	w = recorded
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := len(f.requests) - 1; i >= 0; i-- {
			if f.requests[i].Status == 0 && f.requests[i].Method == r.Method && f.requests[i].Path == r.URL.Path {
				f.requests[i].Status, f.requests[i].Response = recorded.status, recorded.body.Bytes()
				break
			}
		}
	}()
	if r.Header.Get("Authorization") != "Bearer dagu_test_key" {
		answer(w, http.StatusUnauthorized, map[string]string{"code": "unauthorized", "message": "bad key"})
		return
	}
	key := r.Method + " " + r.URL.Path

	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{Method: r.Method, Path: r.URL.Path, Body: body})
	if f.fail[key] > 0 {
		f.fail[key]--
		f.mu.Unlock()
		answer(w, http.StatusInternalServerError, map[string]string{"code": "internal_error", "message": "injected failure"})
		return
	}
	if f.failNextReady && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ready") {
		f.failNextReady = false
		f.mu.Unlock()
		answer(w, http.StatusInternalServerError, map[string]string{"code": "internal_error", "message": "injected failure"})
		return
	}
	lose := f.loseResponse[key] > 0
	if f.loseNextReady && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ready") {
		f.loseNextReady, lose = false, true
	}
	if lose {
		f.loseResponse[key]--
	}
	hook := f.beforeList
	f.mu.Unlock()

	if lose {
		// Apply the request, then report a gateway error instead of the answer.
		f.route(httptest.NewRecorder(), r, body, hook)
		answer(w, http.StatusBadGateway, map[string]string{"code": "bad_gateway", "message": "response lost"})
		return
	}
	f.route(w, r, body, hook)
}

func (f *fakeRegistry) route(w http.ResponseWriter, r *http.Request, body []byte, beforeList func()) {
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/health":
		answer(w, 200, Health{Status: "healthy", Version: "2.18.2-txe.test"})
	case r.Method == http.MethodGet && path == "/txe/installation":
		f.mu.Lock()
		capabilities := slices.Clone(f.capabilities)
		f.mu.Unlock()
		answer(w, 200, Installation{Schema: 1, Owners: []Owner{{OwnerID: testOwner, DisplayName: "Connor Wang"}}, Capabilities: capabilities})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/txe/machines/"):
		f.mu.Lock()
		m, ok := f.machines[strings.TrimPrefix(path, "/txe/machines/")]
		f.mu.Unlock()
		if !ok {
			refuse(w, 404, "not_found", "no such machine", nil)
			return
		}
		answer(w, 200, m)
	case r.Method == http.MethodPost && path == "/txe/projects":
		f.ensureProject(w, body)
	case r.Method == http.MethodGet && path == "/txe/jobs":
		if beforeList != nil {
			beforeList()
		}
		f.listJobs(w, r)
	case r.Method == http.MethodPost && path == "/txe/jobs":
		f.register(w, body)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/ready"):
		f.ready(w, strings.TrimSuffix(strings.TrimPrefix(path, "/txe/jobs/"), "/ready"), body)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/versions"):
		f.update(w, strings.TrimSuffix(strings.TrimPrefix(path, "/txe/jobs/"), "/versions"), body)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/artifacts"):
		f.recordArtifacts(w, strings.TrimSuffix(strings.TrimPrefix(path, "/txe/jobs/"), "/artifacts"), body)
	case r.Method == http.MethodGet && strings.Contains(path, "/versions/"):
		jobID, number, _ := strings.Cut(strings.TrimPrefix(path, "/txe/jobs/"), "/versions/")
		f.mu.Lock()
		var version json.RawMessage
		if j, ok := f.jobs[jobID]; ok {
			var n int
			_, _ = fmt.Sscanf(number, "%d", &n)
			version = j.versions[n]
		}
		f.mu.Unlock()
		if version == nil {
			refuse(w, 404, "not_found", "no such version", nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(version)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/events"):
		f.mu.Lock()
		j, ok := f.jobs[strings.TrimSuffix(strings.TrimPrefix(path, "/txe/jobs/"), "/events")]
		var events []map[string]any
		if ok {
			events = slices.Clone(j.events)
			slices.Reverse(events) // newest first
		}
		f.mu.Unlock()
		if !ok {
			refuse(w, 404, "not_found", "no such job", nil)
			return
		}
		answer(w, 200, map[string]any{"events": events})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/txe/jobs/"):
		f.mu.Lock()
		j, ok := f.jobs[strings.TrimPrefix(path, "/txe/jobs/")]
		f.mu.Unlock()
		if !ok {
			refuse(w, 404, "not_found", "no such job", nil)
			return
		}
		answer(w, 200, j.Job)
	default:
		f.t.Errorf("fake registry: unexpected %s %s", r.Method, path)
		answer(w, 404, map[string]string{"code": "not_found", "message": "no route"})
	}
}

func (f *fakeRegistry) ensureProject(w http.ResponseWriter, body []byte) {
	var in struct {
		OwnerID string `json:"owner_id"`
		Key     string `json:"key"`
		Name    string `json:"name"`
	}
	_ = json.Unmarshal(body, &in)
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.projects[in.Key]
	if !ok {
		p = Project{ProjectID: fmt.Sprintf("prj_%026d", len(f.projects)+1), OwnerID: in.OwnerID, Key: in.Key, Name: in.Name}
		f.projects[in.Key] = p
	}
	answer(w, 200, p)
}

func (f *fakeRegistry) listJobs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	jobs := []Job{}
	for _, j := range f.jobs {
		if (q.Get("project") == "" || q.Get("project") == j.ProjectID) &&
			(q.Get("job_key") == "" || q.Get("job_key") == j.Registration.JobKey) &&
			(q.Get("owner") == "" || q.Get("owner") == j.OwnerID) {
			jobs = append(jobs, j.Job)
		}
	}
	answer(w, 200, map[string]any{"jobs": jobs})
}

func (f *fakeRegistry) register(w http.ResponseWriter, body []byte) {
	var in RegisterRequest
	if err := json.Unmarshal(body, &in); err != nil || in.JobID == "" || in.RequestID == "" || in.JobKey == "" || in.Version.DAG.Spec == "" {
		refuse(w, 400, "invalid", "job_id, request_id, job_key and version.dag.spec are required", nil)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.jobs[in.JobID]; ok {
		if existing.requestID == in.RequestID && existing.requestHash == hashOf(body) {
			answer(w, 200, existing.Job) // replay
			return
		}
		refuse(w, 409, "duplicate", "job id is already used by another request", existing.Job)
		return
	}
	unique := in.ProjectID + "/" + in.JobKey
	if id, ok := f.byKey[unique]; ok {
		refuse(w, 409, "duplicate", "job key "+in.JobKey+" is already registered in this project", f.jobs[id].Job)
		return
	}
	in.Version.DAG.SpecSHA256 = hashOf([]byte(in.Version.DAG.Spec))
	versionJSON, _ := json.Marshal(in.Version)
	j := &fakeJob{
		Job: Job{
			JobID: in.JobID, OwnerID: in.OwnerID, ProjectID: in.ProjectID, MachineID: in.MachineID,
			Revision: 1, Version: 1, PackageDigest: in.Version.Package.Digest, DAGSpecSHA256: hashOf([]byte(in.Version.DAG.Spec)),
			Registration: Registration{State: RegistrationIncomplete, JobKey: in.JobKey, RequestID: in.RequestID},
			Lifecycle:    "active", Availability: Availability{State: "ready"},
			Created: Stamp{By: in.Actor}, Updated: Stamp{By: in.Actor},
		},
		requestID: in.RequestID, requestHash: hashOf(body),
		versions: map[int]json.RawMessage{1: versionJSON},
	}
	f.jobs[in.JobID] = j
	f.byKey[unique] = in.JobID
	answer(w, 201, j.Job)
}

func (f *fakeRegistry) update(w http.ResponseWriter, jobID string, body []byte) {
	var in VersionRequest
	if err := json.Unmarshal(body, &in); err != nil || in.RequestID == "" {
		refuse(w, 400, "invalid", "request_id and expected_version are required", nil)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[jobID]
	if !ok {
		refuse(w, 404, "not_found", "no such job", nil)
		return
	}
	if j.requestID == in.RequestID && j.requestHash == hashOf(body) {
		answer(w, 200, j.Job) // replay
		return
	}
	if in.ExpectedVersion != j.Version {
		refuse(w, 409, "version_conflict", fmt.Sprintf("job is at version %d, not %d", j.Version, in.ExpectedVersion), j.Job)
		return
	}
	in.Version.DAG.SpecSHA256 = hashOf([]byte(in.Version.DAG.Spec))
	versionJSON, _ := json.Marshal(in.Version)
	j.Version++
	j.Revision++
	j.versions[j.Version] = versionJSON
	j.PackageDigest = in.Version.Package.Digest
	j.DAGSpecSHA256 = hashOf([]byte(in.Version.DAG.Spec))
	j.Registration.State, j.Registration.Package = RegistrationIncomplete, nil
	j.requestID, j.requestHash = in.RequestID, hashOf(body)
	j.Updated = Stamp{By: in.Actor}
	answer(w, 200, j.Job)
}

func (f *fakeRegistry) ready(w http.ResponseWriter, jobID string, body []byte) {
	var in ReadyRequest
	if err := json.Unmarshal(body, &in); err != nil {
		refuse(w, 400, "invalid", "bad body", nil)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[jobID]
	if !ok {
		refuse(w, 404, "not_found", "no such job", nil)
		return
	}
	if in.Package.Digest != j.PackageDigest || in.Package.MachineID != j.MachineID {
		refuse(w, 409, "dag_mismatch", "package evidence does not match the registered version", j.Job)
		return
	}
	if j.Registration.State != RegistrationReady {
		if in.ExpectedRevision != j.Revision {
			refuse(w, 409, "version_conflict", fmt.Sprintf("job is at revision %d, not %d", j.Revision, in.ExpectedRevision), j.Job)
			return
		}
		evidence := in.Package
		j.Registration.State, j.Registration.Package, j.Registration.DAGVerified = RegistrationReady, &evidence, true
		j.Revision++
		// The history keeps what became ready, whatever happens to the job later.
		j.events = append(j.events, map[string]any{
			"event_id": fmt.Sprintf("evt_%s_%d", j.JobID, len(j.events)+1), "job_id": j.JobID, "revision": j.Revision,
			"kind": EventReady, "from": RegistrationIncomplete, "to": RegistrationReady,
			"evidence": []string{in.Package.Digest, j.DAGSpecSHA256}, "actor": in.Actor, "at": "2026-10-09T00:00:00Z",
		})
	}
	answer(w, 200, map[string]any{
		"job_id": j.JobID, "owner_id": j.OwnerID, "project_id": j.ProjectID, "machine_id": j.MachineID,
		"version": j.Version, "package_digest": j.PackageDigest, "dag_name": j.JobID,
		"dag_spec_sha256": j.DAGSpecSHA256, "registration": RegistrationReady, "revision": j.Revision,
	})
}

// recordArtifacts stores a run's manifest. The same manifest again is a
// no-op; a different digest for a path already recorded is refused.
// setLatest says which execution of a run the hub holds as running.
func (f *fakeRegistry) setLatest(jobID, runID string, e Execution) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latest[jobID+"/"+runID] = e
}

// recordArtifacts keeps one manifest per execution of a run. It accepts one
// only from the run's latest execution, attempt and queue marker both, takes
// the same report again, and refuses another report for an execution it
// already holds.
func (f *fakeRegistry) recordArtifacts(w http.ResponseWriter, jobAndRun string, body []byte) {
	jobID, runID, _ := strings.Cut(jobAndRun, "/runs/")
	var in ArtifactManifest
	if err := json.Unmarshal(body, &in); err != nil {
		refuse(w, 400, "invalid", "bad body", nil)
		return
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(body, &fields)
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[jobID]
	if !ok || j.versions[in.JobVersion] == nil {
		refuse(w, 404, "not_found", "no such job version", nil)
		return
	}
	if _, sent := fields["queued_at"]; in.AttemptID == "" || !sent {
		refuse(w, 400, "invalid", "attempt_id and queued_at are required", nil)
		return
	}
	key := jobID + "/" + runID
	if latest, ok := f.latest[key]; ok && latest != in.Execution {
		refuse(w, 409, "stale_binding", "execution "+in.Ref()+" is not the run's latest execution "+latest.Ref(), nil)
		return
	}
	// The time a file was recorded is not part of what was reported.
	reported := func(m ArtifactManifest) string {
		m.Artifacts = slices.Clone(m.Artifacts)
		for i := range m.Artifacts {
			m.Artifacts[i].RecordedAt = ""
		}
		data, _ := json.Marshal(m)
		return string(data)
	}
	if previous, ok := f.executions[key+"/"+in.Ref()]; ok {
		if reported(previous) != reported(in) {
			refuse(w, 409, "artifact_conflict", "execution "+in.Ref()+" already reported other deliverables", nil)
			return
		}
		answer(w, 200, previous)
		return
	}
	f.executions[key+"/"+in.Ref()] = in
	f.manifests[key] = in
	answer(w, 200, in)
}
