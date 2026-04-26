package ocsf

// OCSF class UIDs used by this mapper.
const (
	ClassProcessActivity     uint32 = 1007
	ClassFileSystemActivity  uint32 = 1001
	ClassNetworkActivity     uint32 = 4001
	ClassHTTPActivity        uint32 = 4002
	ClassDNSActivity         uint32 = 4003
	ClassDetectionFinding    uint32 = 2004
	ClassApplicationActivity uint32 = 6005
)

// OCSF activity_id values per class.

const (
	ProcessActivityUnknown   uint32 = 0
	ProcessActivityLaunch    uint32 = 1
	ProcessActivityTerminate uint32 = 2
	ProcessActivityOpen      uint32 = 3
	ProcessActivityInject    uint32 = 4
)

const (
	FileActivityUnknown       uint32 = 0
	FileActivityCreate        uint32 = 1
	FileActivityRead          uint32 = 2
	FileActivityUpdate        uint32 = 3
	FileActivityDelete        uint32 = 4
	FileActivityRename        uint32 = 5
	FileActivitySetAttributes uint32 = 6
)

const (
	NetworkActivityUnknown uint32 = 0
	NetworkActivityOpen    uint32 = 1
	NetworkActivityClose   uint32 = 2
	NetworkActivityTraffic uint32 = 6
)

const (
	HTTPActivityUnknown  uint32 = 0
	HTTPActivityRequest  uint32 = 1
	HTTPActivityResponse uint32 = 2
	HTTPActivityTraffic  uint32 = 6
)

const (
	DNSActivityUnknown  uint32 = 0
	DNSActivityQuery    uint32 = 1
	DNSActivityResponse uint32 = 2
	DNSActivityTraffic  uint32 = 6
)

const (
	FindingActivityUnknown uint32 = 0
	FindingActivityCreate  uint32 = 1
	FindingActivityUpdate  uint32 = 2
	FindingActivityClose   uint32 = 3
)

// Application Activity standard + agentsh-internal extensions.
const (
	AppActivityUnknown uint32 = 0
	AppActivityOpen    uint32 = 1
	AppActivityClose   uint32 = 2
	AppActivityUpdate  uint32 = 3
	AppActivityOther   uint32 = 6

	// agentsh-internal — values >= 100 to stay clear of OCSF reservations.
	AppActivityEBPFAttached             uint32 = 100
	AppActivityFUSEMounted              uint32 = 101
	AppActivityCgroupApplied            uint32 = 102
	AppActivityLLMProxyStarted          uint32 = 103
	AppActivityNetProxyStarted          uint32 = 104
	AppActivityMCPToolCalled            uint32 = 105
	AppActivityMCPToolSeen              uint32 = 106
	AppActivityMCPToolsListChanged      uint32 = 107
	AppActivityMCPSamplingRequest       uint32 = 108
	AppActivityMCPToolResultInspected   uint32 = 109
	AppActivityIntegrityChainRotated    uint32 = 110
	AppActivityWrapInit                 uint32 = 111
	AppActivityFSEventsError            uint32 = 112
	AppActivityTransparentNetSetup      uint32 = 113
	AppActivityPolicyCreated            uint32 = 120
	AppActivityPolicyUpdated            uint32 = 121
	AppActivityPolicyDeleted            uint32 = 122
	AppActivitySessionCreated           uint32 = 130
	AppActivitySessionDestroyed         uint32 = 131
	AppActivitySessionExpired           uint32 = 132
	AppActivitySessionUpdated           uint32 = 133
	AppActivityCgroupApplyFailed        uint32 = 140
	AppActivityCgroupCleanupFailed      uint32 = 141
	AppActivityFUSEMountFailed          uint32 = 142
	AppActivityEBPFAttachFailed         uint32 = 143
	AppActivityEBPFCollectorFailed      uint32 = 144
	AppActivityEBPFEnforceDisabled      uint32 = 145
	AppActivityEBPFEnforceNonStrict     uint32 = 146
	AppActivityEBPFEnforceRefreshFailed uint32 = 147
	AppActivityEBPFUnavailable          uint32 = 148
	AppActivityLLMProxyFailed           uint32 = 149
	AppActivityNetProxyFailed           uint32 = 150
	AppActivityTransparentNetReady      uint32 = 151
	AppActivityTransparentNetFailed     uint32 = 152
	AppActivityMCPToolChanged           uint32 = 153
	AppActivityMCPCrossServerBlocked    uint32 = 154
	AppActivitySecretAccess             uint32 = 155
	AppActivityMCPNetworkConnection     uint32 = 156
)
