// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import "fmt"

// The Stagehand SDK's own launcher is not used, because it starts Chrome on a
// port. Its arguments are kept here so the browser the gate starts behaves
// as the browser the SDK would have started; a test compares this list with
// the SDK module's.

// sdkDefaultChromeFlags are the SDK's defaultChromeFlags (sdk-go
// chrome_launcher.go), in its order.
var sdkDefaultChromeFlags = []string{
	"--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider," +
		"CalculateNativeWinOcclusion,InterestFeedContentSuggestions," +
		"CertificateTransparencyComponentUpdater,AutofillServerCommunication," +
		"PrivacySandboxSettings4,RenderDocument",
	"--disable-component-extensions-with-background-pages",
	"--disable-background-networking",
	"--disable-component-update",
	"--disable-client-side-phishing-detection",
	"--disable-sync",
	"--metrics-recording-only",
	"--disable-default-apps",
	"--mute-audio",
	"--no-default-browser-check",
	"--no-first-run",
	"--disable-backgrounding-occluded-windows",
	"--disable-renderer-backgrounding",
	"--disable-background-timer-throttling",
	"--disable-ipc-flooding-protection",
	"--password-store=basic",
	"--use-mock-keychain",
	"--force-fieldtrials=*BackgroundTracing/default/",
	"--disable-hang-monitor",
	"--disable-prompt-on-repost",
	"--disable-domain-reliability",
	"--propagate-iph-for-testing",
	"--enable-unsafe-extension-debugging",
	"--remote-allow-origins=*",
	"--enable-features=WebMCPTesting,DevToolsWebMCPSupport",
}

const (
	// sdkDefaultWidth and sdkDefaultHeight are the SDK's window size when
	// no viewport is given.
	sdkDefaultWidth  = 1280
	sdkDefaultHeight = 800
)

// Viewport is a window size in pixels.
type Viewport struct {
	Width  int
	Height int
}

// LaunchOptions describe the browser to start.
type LaunchOptions struct {
	// UserDataDir is the profile directory. It is required: a browser the
	// gate starts never uses the user's own profile.
	UserDataDir string
	Headless    bool
	Viewport    *Viewport
	// ProxyServer is passed as --proxy-server when set.
	ProxyServer string
	// NoSandbox turns the browser sandbox off.
	NoSandbox bool
	// Extra arguments follow the defaults, before the initial page.
	Extra []string
}

// ChromeArgs builds the browser's arguments for o, the way the SDK's
// launcher builds them, without any remote-debugging flag: the gate adds the
// pipe flags when it starts the browser.
func ChromeArgs(o LaunchOptions) []string {
	args := make([]string, 0, len(sdkDefaultChromeFlags)+8+len(o.Extra))
	args = append(args, sdkDefaultChromeFlags...)
	width, height := sdkDefaultWidth, sdkDefaultHeight
	if o.Viewport != nil {
		width, height = o.Viewport.Width, o.Viewport.Height
	}
	args = append(args,
		fmt.Sprintf("--window-size=%d,%d", width, height),
		"--user-data-dir="+o.UserDataDir,
	)
	if o.Headless {
		args = append(args, "--headless")
	}
	if o.NoSandbox {
		args = append(args, "--no-sandbox")
	}
	if o.ProxyServer != "" {
		args = append(args, "--proxy-server="+o.ProxyServer)
	}
	args = append(args, o.Extra...)
	return append(args, "about:blank")
}
