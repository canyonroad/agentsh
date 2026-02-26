package mcpinspect

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr := make([]int, lb+1)
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev = curr
	}
	return prev[lb]
}

// NormalizedSimilarity returns a similarity score between 0.0 and 1.0.
func NormalizedSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	maxLen := max(len(a), len(b))
	if maxLen == 0 {
		return 1.0
	}
	dist := levenshtein(a, b)
	return 1.0 - float64(dist)/float64(maxLen)
}

// CheckServerNameSimilarity checks a new server ID against existing IDs.
// Returns (similarID, score) or ("", 0) if none exceed the threshold.
func CheckServerNameSimilarity(newID string, existingIDs []string, threshold float64) (match string, score float64) {
	var bestMatch string
	var bestScore float64
	for _, existing := range existingIDs {
		if existing == newID {
			return existing, 1.0
		}
		s := NormalizedSimilarity(newID, existing)
		if s > bestScore {
			bestScore = s
			bestMatch = existing
		}
	}
	if bestScore >= threshold {
		return bestMatch, bestScore
	}
	return "", 0
}
