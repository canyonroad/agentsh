//go:build darwin

package api

// DefaultXPCAllowList contains safe XPC services for CLI tools.
var DefaultXPCAllowList = []string{
	// Core system
	"com.apple.system.logger",
	"com.apple.system.notification_center",
	"com.apple.system.opendirectoryd",

	// CoreServices (file types, UTIs, launch services)
	"com.apple.CoreServices.coreservicesd",
	"com.apple.lsd.mapdb",
	"com.apple.lsd.modifydb",

	// Security (code signing validation)
	"com.apple.SecurityServer",
	"com.apple.securityd",

	// Preferences
	"com.apple.cfprefsd.daemon",
	"com.apple.cfprefsd.agent",

	// Fonts
	"com.apple.fonts",
	"com.apple.FontObjectsServer",

	// Distributed notifications (local only)
	"com.apple.distributed_notifications_server",
}

// DefaultXPCBlockPrefixes contains dangerous service prefixes.
var DefaultXPCBlockPrefixes = []string{
	"com.apple.accessibility.",      // Input injection, screen reading
	"com.apple.tccd.",               // TCC bypass attempts
	"com.apple.security.syspolicy.", // Security policy changes
	"com.apple.screensharing.",      // Screen sharing
	"com.apple.RemoteDesktop.",      // Remote control
}

// DefaultXPCBlockList contains specific dangerous services.
var DefaultXPCBlockList = []string{
	"com.apple.security.authhost",        // Auth dialog spoofing
	"com.apple.coreservices.appleevents", // AppleScript execution
	"com.apple.pasteboard.1",             // Clipboard exfiltration
}
