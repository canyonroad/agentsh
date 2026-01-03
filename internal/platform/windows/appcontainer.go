//go:build windows

package windows

import (
	"fmt"
	"regexp"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// appContainer wraps Windows AppContainer APIs for process isolation.
type appContainer struct {
	name        string       // Container profile name
	sid         *windows.SID // Container security identifier
	grantedACLs []string     // Paths we modified (for cleanup)
	mu          sync.Mutex
	created     bool
}

// invalidChars matches characters not allowed in AppContainer names
var invalidChars = regexp.MustCompile(`[/\\:*?"<>|]`)

var (
	modUserenv = windows.NewLazySystemDLL("userenv.dll")

	procCreateAppContainerProfile                 = modUserenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile                 = modUserenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSidFromAppContainerName = modUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// uintptrToSID converts a uintptr (from Windows API) to *windows.SID.
// This function isolates the unsafe conversion required for Windows API interop.
//
//go:nocheckptr
func uintptrToSID(ptr uintptr) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(ptr))
}

// appContainerName generates a valid AppContainer profile name from a sandbox ID.
func appContainerName(sandboxID string) string {
	// Sanitize the ID for use in registry key names
	sanitized := invalidChars.ReplaceAllString(sandboxID, "-")
	return fmt.Sprintf("agentsh-sandbox-%s", sanitized)
}

// newAppContainer creates a new appContainer wrapper.
// Does NOT create the profile yet - call create() for that.
func newAppContainer(sandboxID string) *appContainer {
	return &appContainer{
		name:        appContainerName(sandboxID),
		grantedACLs: make([]string, 0),
	}
}

// create creates the AppContainer profile in Windows.
func (c *appContainer) create() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.created {
		return nil
	}

	namePtr, err := syscall.UTF16PtrFromString(c.name)
	if err != nil {
		return fmt.Errorf("invalid container name: %w", err)
	}

	displayName := c.name
	displayNamePtr, _ := syscall.UTF16PtrFromString(displayName)
	description := "agentsh sandbox container"
	descPtr, _ := syscall.UTF16PtrFromString(description)

	var sidPtr uintptr

	// CreateAppContainerProfile(name, displayName, description, capabilities, capCount, &sid)
	r1, _, _ := procCreateAppContainerProfile.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(displayNamePtr)),
		uintptr(unsafe.Pointer(descPtr)),
		0, // capabilities array (none for now)
		0, // capability count
		uintptr(unsafe.Pointer(&sidPtr)),
	)

	if r1 != 0 {
		// HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700B7
		if r1 == 0x800700B7 {
			// Profile exists, derive the SID
			return c.deriveSIDLocked()
		}
		return fmt.Errorf("CreateAppContainerProfile failed: 0x%x", r1)
	}

	if sidPtr != 0 {
		// Convert uintptr from Windows API to *SID.
		// This is safe: sidPtr comes directly from CreateAppContainerProfile
		// and points to valid SID memory allocated by Windows.
		c.sid = uintptrToSID(sidPtr)
	}

	c.created = true
	return nil
}

// deriveSIDLocked gets the SID for an existing container profile.
// Caller must hold c.mu.
func (c *appContainer) deriveSIDLocked() error {
	namePtr, err := syscall.UTF16PtrFromString(c.name)
	if err != nil {
		return err
	}

	var sidPtr uintptr
	r1, _, _ := procDeriveAppContainerSidFromAppContainerName.Call(
		0, // reserved
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&sidPtr)),
	)

	if r1 != 0 {
		return fmt.Errorf("DeriveAppContainerSidFromAppContainerName failed: 0x%x", r1)
	}

	if sidPtr != 0 {
		// Convert uintptr from Windows API to *SID.
		// This is safe: sidPtr comes directly from DeriveAppContainerSidFromAppContainerName
		// and points to valid SID memory allocated by Windows.
		c.sid = uintptrToSID(sidPtr)
	}
	c.created = true
	return nil
}

// cleanup removes the container profile and reverts any ACL changes.
func (c *appContainer) cleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error

	// Revert ACLs we modified
	for _, path := range c.grantedACLs {
		if err := c.revokePathAccessLocked(path); err != nil {
			errs = append(errs, err)
		}
	}
	c.grantedACLs = nil

	// Free the SID allocated by Windows
	if c.sid != nil {
		windows.FreeSid(c.sid)
		c.sid = nil
	}

	// Delete profile if we created it
	if c.created {
		namePtr, _ := syscall.UTF16PtrFromString(c.name)
		r1, _, _ := procDeleteAppContainerProfile.Call(
			uintptr(unsafe.Pointer(namePtr)),
		)
		if r1 != 0 && r1 != 0x80070002 { // ignore "not found"
			errs = append(errs, fmt.Errorf("DeleteAppContainerProfile failed: 0x%x", r1))
		}
		c.created = false
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}
	return nil
}

// revokePathAccessLocked removes container SID from path ACL.
// Caller must hold c.mu.
func (c *appContainer) revokePathAccessLocked(path string) error {
	// TODO: Implement ACL removal
	return nil
}
