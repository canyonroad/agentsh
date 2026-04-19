package otel

import "github.com/agentsh/agentsh/internal/store/eventfilter"

// Filter is an alias for the shared eventfilter.Filter so existing callers
// continue to use otel.Filter without churn.
type Filter = eventfilter.Filter
