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
	modUserenv   = windows.NewLazySystemDLL("userenv.dll")
	modAdvapi32  = windows.NewLazySystemDLL("advapi32.dll")

	procCreateAppContainerProfile                 = modUserenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile                 = modUserenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSidFromAppContainerName = modUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")

	procSetNamedSecurityInfoW = modAdvapi32.NewProc("SetNamedSecurityInfoW")
	procGetNamedSecurityInfoW = modAdvapi32.NewProc("GetNamedSecurityInfoW")
	procSetEntriesInAclW      = modAdvapi32.NewProc("SetEntriesInAclW")
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

// AccessMode specifies the type of access to grant.
type AccessMode int

const (
	AccessRead AccessMode = iota
	AccessReadWrite
	AccessReadExecute
	AccessFull
)

// SE_OBJECT_TYPE for files
const seFileObject = 1

// Access rights
const (
	genericRead    = 0x80000000
	genericWrite   = 0x40000000
	genericExecute = 0x20000000
	genericAll     = 0x10000000
)

// ACL flags
const (
	objectInheritAce        = 0x1
	containerInheritAce     = 0x2
	daclSecurityInformation = 0x4
)

// explicitAccess is the EXPLICIT_ACCESS_W structure
type explicitAccess struct {
	grfAccessPermissions uint32
	grfAccessMode        uint32 // SET_ACCESS = 2
	grfInheritance       uint32
	trustee              trustee
}

type trustee struct {
	pMultipleTrustee         uintptr
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32 // TRUSTEE_IS_SID = 0
	TrusteeType              uint32 // TRUSTEE_IS_WELL_KNOWN_GROUP = 5
	ptstrName                uintptr
}

func buildExplicitAccess(sid *windows.SID, accessMask uint32) explicitAccess {
	return explicitAccess{
		grfAccessPermissions: accessMask,
		grfAccessMode:        2, // SET_ACCESS
		grfInheritance:       objectInheritAce | containerInheritAce,
		trustee: trustee{
			TrusteeForm: 0, // TRUSTEE_IS_SID
			ptstrName:   uintptr(unsafe.Pointer(sid)),
		},
	}
}

func setEntriesInAcl(count uint32, entries *explicitAccess, oldAcl uintptr, newAcl *uintptr) uint32 {
	r1, _, _ := procSetEntriesInAclW.Call(
		uintptr(count),
		uintptr(unsafe.Pointer(entries)),
		oldAcl,
		uintptr(unsafe.Pointer(newAcl)),
	)
	return uint32(r1)
}

// grantPathAccess adds the container SID to the path's ACL.
func (c *appContainer) grantPathAccess(path string, mode AccessMode) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sid == nil {
		return fmt.Errorf("container not created")
	}

	// Determine access mask based on mode
	var accessMask uint32
	switch mode {
	case AccessRead:
		accessMask = genericRead
	case AccessReadWrite:
		accessMask = genericRead | genericWrite
	case AccessReadExecute:
		accessMask = genericRead | genericExecute
	case AccessFull:
		accessMask = genericAll
	}

	// Get current security descriptor
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	var pSecDesc uintptr
	var pDacl uintptr

	r1, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		seFileObject,
		daclSecurityInformation,
		0, 0, // owner, group SID (not needed)
		uintptr(unsafe.Pointer(&pDacl)),
		0, // SACL
		uintptr(unsafe.Pointer(&pSecDesc)),
	)
	if r1 != 0 {
		return fmt.Errorf("GetNamedSecurityInfoW failed: %d", r1)
	}
	defer windows.LocalFree(windows.Handle(pSecDesc))

	// Build explicit access entry for container SID
	ea := buildExplicitAccess(c.sid, accessMask)

	// Create new ACL with container entry
	var pNewDacl uintptr
	r1 = uintptr(setEntriesInAcl(1, &ea, pDacl, &pNewDacl))
	if r1 != 0 {
		return fmt.Errorf("SetEntriesInAcl failed: %d", r1)
	}
	defer windows.LocalFree(windows.Handle(pNewDacl))

	// Apply new ACL
	r1, _, _ = procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		seFileObject,
		daclSecurityInformation,
		0, 0, // owner, group
		pNewDacl,
		0, // SACL
	)
	if r1 != 0 {
		return fmt.Errorf("SetNamedSecurityInfoW failed: %d", r1)
	}

	c.grantedACLs = append(c.grantedACLs, path)
	return nil
}
