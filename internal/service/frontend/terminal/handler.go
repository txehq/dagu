// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package terminal

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/coder/websocket"
	"github.com/dagucloud/dagu/v2/internal/audit"
	"github.com/dagucloud/dagu/v2/internal/license"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	frontendauth "github.com/dagucloud/dagu/v2/internal/service/frontend/auth"
)

// Handler handles WebSocket connections for the terminal.
type Handler struct {
	authService    *authservice.Service
	auditService   *audit.Service
	licenseChecker license.Checker
	manager        *Manager
	shell          string
	// sessionWatch closes a terminal whose OIDC session stopped letting its
	// user in. Nil watches nothing.
	sessionWatch *frontendauth.SessionWatch
}

// NewHandler creates a new terminal handler.
func NewHandler(authSvc *authservice.Service, auditSvc *audit.Service, licenseChecker license.Checker, manager *Manager, shell string) *Handler {
	return &Handler{
		authService:    authSvc,
		auditService:   auditSvc,
		licenseChecker: licenseChecker,
		manager:        manager,
		shell:          shell,
	}
}

// SetSessionWatch makes the handler close a terminal that was opened with an
// OIDC session's hub token once that session stops letting its user in. It
// is called before the handler serves. Without it, or with nil, a terminal
// stays open until it is closed, as before.
func (h *Handler) SetSessionWatch(watch *frontendauth.SessionWatch) {
	h.sessionWatch = watch
}

// ServeHTTP handles WebSocket upgrade and terminal connection.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract token from query parameter (WebSocket doesn't support custom headers during handshake)
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	// Validate token and get user
	user, err := h.authService.GetUserFromToken(ctx, token)
	if errors.Is(err, authservice.ErrSessionCheckUnavailable) {
		frontendauth.WriteSessionCheckUnavailable(w)
		return
	}
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Check admin role
	if !user.Role.IsAdmin() {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	// The token has just been checked. It is watched from here on, before
	// anything is set up for the terminal, so that the terminal does not
	// outlive the session. A session that has stopped letting its user in
	// since the check gets no terminal.
	watchedCtx, stopWatch := h.sessionWatch.Watch(ctx, token)
	defer stopWatch()
	if watchedCtx.Err() != nil {
		frontendauth.WriteSessionWatchRefusal(watchedCtx, w)
		return
	}

	// Get client IP address
	ipAddress := frontendauth.GetClientIP(r)

	var lease *sessionLease
	if h.manager != nil {
		lease, err = h.manager.Acquire()
		if err != nil {
			status := http.StatusTooManyRequests
			message := "Terminal session limit reached. Please close another terminal and try again."
			if err == ErrManagerShuttingDown {
				status = http.StatusServiceUnavailable
				message = "Terminal is shutting down. Please try again after the server restarts."
			}
			http.Error(w, message, status)
			return
		}
		defer lease.Release()
	}

	// Upgrade to WebSocket
	// InsecureSkipVerify allows any origin since access is already protected by token auth
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	// Create and run connection
	tc := NewConnection(user, h.shell, conn, ipAddress)
	// The watch is over as soon as the terminal is, and not only when its
	// cleanup is, which can take as long as the shell does.
	tc.onSessionEnd = stopWatch
	if lease != nil {
		if err := lease.Activate(tc); err != nil {
			_ = conn.Close(websocket.StatusTryAgainLater, "terminal unavailable")
			return
		}
		// Free the session slot as soon as the event loop exits, before
		// the potentially slow cleanup (process kill, I/O drain). The
		// connection stays in the sessions map for shutdown/force-kill
		// until defer lease.Release() runs after cleanup completes.
		tc.onSessionEnd = func() {
			stopWatch()
			lease.ReleaseSlot()
		}
	}

	var managerCtx context.Context
	if h.manager != nil {
		managerCtx = h.manager.Context()
	}
	runCtx, cancelRun := mergeSessionContext(watchedCtx, managerCtx)
	defer cancelRun()
	auditSvc := h.auditService
	if h.licenseChecker != nil && !h.licenseChecker.IsFeatureEnabled(license.FeatureAudit) {
		auditSvc = nil
	}
	_ = tc.Run(runCtx, auditSvc)
}

func mergeSessionContext(requestCtx, managerCtx context.Context) (context.Context, context.CancelFunc) {
	if requestCtx == nil {
		requestCtx = context.Background()
	}
	if managerCtx == nil {
		return context.WithCancel(requestCtx)
	}

	ctx, cancel := context.WithCancel(requestCtx)
	stop := context.AfterFunc(managerCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// GetDefaultShell returns the default shell for the current system.
func GetDefaultShell() string {
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}
	return "/bin/sh"
}
