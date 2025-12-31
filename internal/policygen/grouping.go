// internal/policygen/grouping.go
package policygen

import (
	"path/filepath"
	"sort"
	"strings"
)

// PathGroup represents a group of paths collapsed into a pattern.
type PathGroup struct {
	Pattern    string
	Paths      []string
	Operations []string
	Count      int
}

// DomainGroup represents a group of domains collapsed into a pattern.
type DomainGroup struct {
	Pattern string
	Domains []string
	Ports   []int
	Count   int
}

// GroupPaths groups paths by directory and collapses to globs if above threshold.
func GroupPaths(paths []string, threshold int) []PathGroup {
	if len(paths) == 0 {
		return nil
	}

	// Group by directory
	byDir := make(map[string][]string)
	for _, p := range paths {
		dir := filepath.Dir(p)
		byDir[dir] = append(byDir[dir], p)
	}

	var groups []PathGroup

	// Check if we should collapse parent directories
	// Group directories by their parent
	byParent := make(map[string][]string)
	for dir := range byDir {
		parent := filepath.Dir(dir)
		byParent[parent] = append(byParent[parent], dir)
	}

	// If multiple subdirs under same parent exceed threshold, collapse to parent/**
	collapsedParents := make(map[string]bool)
	for parent, dirs := range byParent {
		if len(dirs) >= threshold {
			collapsedParents[parent] = true
			// Count all paths under this parent
			count := 0
			var allPaths []string
			for _, dir := range dirs {
				count += len(byDir[dir])
				allPaths = append(allPaths, byDir[dir]...)
			}
			groups = append(groups, PathGroup{
				Pattern: parent + "/**",
				Paths:   allPaths,
				Count:   count,
			})
		}
	}

	// Process remaining directories not collapsed
	for dir, dirPaths := range byDir {
		// Skip if any ancestor was collapsed
		if isUnderCollapsedParent(dir, collapsedParents) {
			// Add paths to the collapsed parent group
			for collapsedParent := range collapsedParents {
				if strings.HasPrefix(dir, collapsedParent+"/") {
					// Find the group and add paths
					for i := range groups {
						if groups[i].Pattern == collapsedParent+"/**" {
							groups[i].Paths = append(groups[i].Paths, dirPaths...)
							groups[i].Count += len(dirPaths)
							break
						}
					}
					break
				}
			}
			continue
		}

		if len(dirPaths) >= threshold {
			groups = append(groups, PathGroup{
				Pattern: dir + "/**",
				Paths:   dirPaths,
				Count:   len(dirPaths),
			})
		} else {
			// Keep individual paths
			for _, p := range dirPaths {
				groups = append(groups, PathGroup{
					Pattern: p,
					Paths:   []string{p},
					Count:   1,
				})
			}
		}
	}

	// Sort by pattern for deterministic output
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Pattern < groups[j].Pattern
	})

	return groups
}

// GroupDomains groups domains by base domain and collapses subdomains.
func GroupDomains(domains []string) []DomainGroup {
	if len(domains) == 0 {
		return nil
	}

	// Group by base domain (last two parts)
	byBase := make(map[string][]string)
	for _, d := range domains {
		base := getBaseDomain(d)
		byBase[base] = append(byBase[base], d)
	}

	var groups []DomainGroup

	for base, subdomains := range byBase {
		if len(subdomains) > 1 {
			// Multiple subdomains - collapse to wildcard
			groups = append(groups, DomainGroup{
				Pattern: "*." + base,
				Domains: subdomains,
				Count:   len(subdomains),
			})
		} else {
			// Single domain - keep as-is
			groups = append(groups, DomainGroup{
				Pattern: subdomains[0],
				Domains: subdomains,
				Count:   1,
			})
		}
	}

	// Sort for deterministic output
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Pattern < groups[j].Pattern
	})

	return groups
}

// getBaseDomain extracts the base domain (e.g., "github.com" from "api.github.com").
func getBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// isUnderCollapsedParent checks if the directory is under any collapsed parent.
func isUnderCollapsedParent(dir string, collapsedParents map[string]bool) bool {
	for parent := range collapsedParents {
		if strings.HasPrefix(dir, parent+"/") {
			return true
		}
	}
	return false
}

// GroupCIDR groups IPs into CIDRs if they cluster in the same /24.
func GroupCIDR(ips []string) []string {
	if len(ips) == 0 {
		return nil
	}

	// Group by /24 prefix
	byPrefix := make(map[string][]string)
	for _, ip := range ips {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			continue // Skip non-IPv4
		}
		prefix := strings.Join(parts[:3], ".")
		byPrefix[prefix] = append(byPrefix[prefix], ip)
	}

	var cidrs []string
	for prefix, prefixIPs := range byPrefix {
		if len(prefixIPs) >= 3 {
			// Collapse to CIDR
			cidrs = append(cidrs, prefix+".0/24")
		} else {
			// Keep individual IPs
			cidrs = append(cidrs, prefixIPs...)
		}
	}

	sort.Strings(cidrs)
	return cidrs
}
