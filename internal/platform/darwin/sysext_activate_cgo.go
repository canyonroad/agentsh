//go:build darwin && cgo

package darwin

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework SystemExtensions -framework Foundation

#import <Foundation/Foundation.h>
#import <SystemExtensions/SystemExtensions.h>

// Activation result codes
enum {
	ACTIVATE_OK = 0,
	ACTIVATE_NEEDS_APPROVAL = 1,
	ACTIVATE_FAILED = -1,
};

@interface SysExtActivator : NSObject <OSSystemExtensionRequestDelegate>
@property (nonatomic, assign) BOOL completed;
@property (nonatomic, assign) int result;
@property (nonatomic, copy) NSString *errorMessage;
@end

@implementation SysExtActivator

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
	NSLog(@"SysExtActivator: finished with result %ld", (long)result);
	self.result = ACTIVATE_OK;
	self.completed = YES;
	CFRunLoopStop(CFRunLoopGetMain());
}

- (void)request:(OSSystemExtensionRequest *)request
    didFailWithError:(NSError *)error {
	NSLog(@"SysExtActivator: failed: %@", error);
	self.errorMessage = [error localizedDescription];
	self.result = ACTIVATE_FAILED;
	self.completed = YES;
	CFRunLoopStop(CFRunLoopGetMain());
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
	NSLog(@"SysExtActivator: needs user approval in System Settings");
	self.result = ACTIVATE_NEEDS_APPROVAL;
	self.completed = YES;
	CFRunLoopStop(CFRunLoopGetMain());
}

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
	actionForReplacingExtension:(OSSystemExtensionProperties *)existing
	withExtension:(OSSystemExtensionProperties *)ext {
	NSLog(@"SysExtActivator: replacing %@ -> %@",
		  existing.bundleVersion, ext.bundleVersion);
	return OSSystemExtensionReplacementActionReplace;
}

@end

// activateSysExt submits an activation request and blocks until completion
// or until the system indicates user approval is needed.
// Returns: 0 = activated, 1 = needs user approval, -1 = failed.
// On failure, errOut (if non-NULL) receives a malloc'd error string the caller must free.
static int activateSysExt(const char *bundleID, char **errOut) {
	@autoreleasepool {
		SysExtActivator *activator = [[SysExtActivator alloc] init];
		NSString *identifier = [NSString stringWithUTF8String:bundleID];

		OSSystemExtensionRequest *request = [OSSystemExtensionRequest
			activationRequestForExtensionWithIdentifier:identifier
			queue:dispatch_get_main_queue()];
		request.delegate = activator;
		[[OSSystemExtensionManager sharedManager] submitRequest:request];

		// Run the main run loop until the delegate fires.
		// Timeout after 30 seconds to avoid hanging forever.
		NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:30.0];
		while (!activator.completed && [[NSDate date] compare:timeout] == NSOrderedAscending) {
			CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.5, false);
		}

		if (!activator.completed) {
			if (errOut) *errOut = strdup("activation timed out after 30 seconds");
			return ACTIVATE_FAILED;
		}

		if (activator.result == ACTIVATE_FAILED && errOut && activator.errorMessage) {
			*errOut = strdup([activator.errorMessage UTF8String]);
		}

		return activator.result;
	}
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// ActivateResult represents the outcome of a system extension activation request.
type ActivateResult int

const (
	// ActivateOK means the extension was activated successfully.
	ActivateOK ActivateResult = 0
	// ActivateNeedsApproval means the user must approve in System Settings.
	ActivateNeedsApproval ActivateResult = 1
	// ActivateFailed means the activation request failed.
	ActivateFailed ActivateResult = -1
)

const sysExtBundleID = "ai.canyonroad.agentsh.SysExt"

// activateExtension calls OSSystemExtensionManager to activate the system extension.
// This blocks until the request completes or the system indicates user approval is needed.
func activateExtension() (ActivateResult, error) {
	cBundleID := C.CString(sysExtBundleID)
	defer C.free(unsafe.Pointer(cBundleID))

	var cErr *C.char
	result := C.activateSysExt(cBundleID, &cErr)

	if cErr != nil {
		errMsg := C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
		return ActivateResult(result), fmt.Errorf("%s", errMsg)
	}

	return ActivateResult(result), nil
}
