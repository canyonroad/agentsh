package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackageEventTypes_InEventCategory(t *testing.T) {
	packageEvents := []EventType{
		EventPackageCheckStarted,
		EventPackageCheckCompleted,
		EventPackageBlocked,
		EventPackageApproved,
		EventPackageWarning,
		EventProviderError,
	}

	for _, evt := range packageEvents {
		t.Run(string(evt), func(t *testing.T) {
			cat, ok := EventCategory[evt]
			assert.True(t, ok, "event %s missing from EventCategory", evt)
			assert.Equal(t, "package", cat, "event %s should have category 'package'", evt)
		})
	}
}

func TestPackageEventTypes_InAllEventTypes(t *testing.T) {
	packageEvents := []EventType{
		EventPackageCheckStarted,
		EventPackageCheckCompleted,
		EventPackageBlocked,
		EventPackageApproved,
		EventPackageWarning,
		EventProviderError,
	}

	allSet := make(map[EventType]bool)
	for _, evt := range AllEventTypes {
		allSet[evt] = true
	}

	for _, evt := range packageEvents {
		t.Run(string(evt), func(t *testing.T) {
			assert.True(t, allSet[evt], "event %s missing from AllEventTypes", evt)
		})
	}
}

func TestAllEventTypes_InEventCategory(t *testing.T) {
	// Verify that every event in AllEventTypes has a category.
	for _, evt := range AllEventTypes {
		t.Run(string(evt), func(t *testing.T) {
			_, ok := EventCategory[evt]
			assert.True(t, ok, "event %s in AllEventTypes but not in EventCategory", evt)
		})
	}
}

func TestEventCategory_InAllEventTypes(t *testing.T) {
	// Verify that every event in EventCategory is in AllEventTypes.
	allSet := make(map[EventType]bool)
	for _, evt := range AllEventTypes {
		allSet[evt] = true
	}

	for evt := range EventCategory {
		t.Run(string(evt), func(t *testing.T) {
			assert.True(t, allSet[evt], "event %s in EventCategory but not in AllEventTypes", evt)
		})
	}
}
