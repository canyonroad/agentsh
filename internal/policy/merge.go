package policy

// MergeOverlay returns a new Policy formed by overlaying `overlay` rules on
// top of `base`. Rules with matching names in overlay replace base entries
// in-place at their original index; other overlay rules are appended in
// declared order. Rules with empty Name always append.
//
// Base metadata is preserved via a shallow struct copy: every non-rule
// field on Policy (Version, Name, Description, ResourceLimits, EnvPolicy,
// Audit, EnvInject, MCPRules, ProcessContexts, ProcessIdentities,
// PackageRules, TransparentCommands, Providers, HTTPServices, the
// yaml.Node-backed extension fields, and any other future scalar fields)
// is taken from `base`; overlay metadata is ignored. Because the copy is
// shallow, slices and maps in the returned policy SHARE backing storage
// with `base`. Callers must not mutate the returned policy's non-rule
// fields in place; clone first if needed.
//
// FileRules, NetworkRules, CommandRules, UnixRules, and SignalRules are
// merged by name. DNS-redirect and connect-redirect rules are also merged
// by name. `RegistryRules` (Windows-only), HTTP services, and
// unnamed/opaque blocks remain unmerged: base wins.
//
// If either argument is nil, the other is returned unchanged. This lets
// callers handle "no user override" without a nil check at the call site.
//
// Used by cmd/agentsh-sbx-bootstrap to combine the baked coding-agent
// template with /home/agent/.agentsh/policy.yaml at sandbox startup.
func MergeOverlay(base, overlay *Policy) *Policy {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}

	out := *base
	out.FileRules = mergeFileRules(base.FileRules, overlay.FileRules)
	out.NetworkRules = mergeNetworkRules(base.NetworkRules, overlay.NetworkRules)
	out.CommandRules = mergeCommandRules(base.CommandRules, overlay.CommandRules)
	out.UnixRules = mergeUnixRules(base.UnixRules, overlay.UnixRules)
	out.SignalRules = mergeSignalRules(base.SignalRules, overlay.SignalRules)
	out.DnsRedirectRules = mergeDnsRedirectRules(base.DnsRedirectRules, overlay.DnsRedirectRules)
	out.ConnectRedirectRules = mergeConnectRedirectRules(base.ConnectRedirectRules, overlay.ConnectRedirectRules)
	return &out
}

func mergeFileRules(base, overlay []FileRule) []FileRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]FileRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeNetworkRules(base, overlay []NetworkRule) []NetworkRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]NetworkRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeCommandRules(base, overlay []CommandRule) []CommandRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]CommandRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeUnixRules(base, overlay []UnixSocketRule) []UnixSocketRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]UnixSocketRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeSignalRules(base, overlay []SignalRule) []SignalRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]SignalRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeDnsRedirectRules(base, overlay []DnsRedirectRule) []DnsRedirectRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]DnsRedirectRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeConnectRedirectRules(base, overlay []ConnectRedirectRule) []ConnectRedirectRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]ConnectRedirectRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}
