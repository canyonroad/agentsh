package postgres

import (
	"regexp"
	"strings"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Redshift first-keyword fallback (spec §7.3, §7.7). libpg_query rejects
// Redshift-only syntax (UNLOAD, COPY ... FROM 's3://...'); when Classify is
// invoked with DialectRedshift and parsing fails, classifyWithBackend calls
// redshiftFirstKeyword to recognize a small set of statements via regex on the
// statement's leading keyword. Anything we don't recognize falls through to the
// dispatcher's "unknown" path.
var (
	unloadRE     = regexp.MustCompile(`(?is)^\s*UNLOAD\s*\(`)
	copyFromS3RE = regexp.MustCompile(`(?is)^\s*COPY\s+([^\s(]+)\s+FROM\s+'(s3://[^']+)'`)
	unloadToRE   = regexp.MustCompile(`(?is)TO\s+'(s3://[^']+)'`)
)

// redshiftFirstKeyword is invoked from classifyWithBackend on Redshift parse
// failure. Returns ok=false → fall through to unknown.
func redshiftFirstKeyword(sql string, backend effects.ParserBackend) (effects.ClassifiedStatement, bool) {
	switch {
	case unloadRE.MatchString(sql):
		s3 := ""
		if m := unloadToRE.FindStringSubmatch(sql); len(m) == 2 {
			s3 = m[1]
		}
		cs := effects.ClassifiedStatement{
			RawVerb:       "UNLOAD",
			ParserBackend: backend,
			Effects: []effects.Effect{
				{
					Group:   effects.GroupBulkExport,
					Subtype: effects.SubtypeUnloadToS3,
					Objects: []effects.ObjectRef{{Kind: effects.ObjectFilesystemPath, Path: s3}},
				},
				{
					Group:   effects.GroupUnsafeIO,
					Objects: []effects.ObjectRef{{Kind: effects.ObjectFilesystemPath, Path: s3}},
				},
				{Group: effects.GroupRead},
			},
		}
		effects.Order(cs.Effects)
		return cs, true
	case copyFromS3RE.MatchString(sql):
		m := copyFromS3RE.FindStringSubmatch(sql)
		tbl := strings.ToLower(strings.TrimSpace(m[1]))
		s3 := m[2]
		cs := effects.ClassifiedStatement{
			RawVerb:       "COPY_FROM_S3",
			ParserBackend: backend,
			Effects: []effects.Effect{
				{
					Group:   effects.GroupBulkLoad,
					Subtype: effects.SubtypeCopyFromS3,
					Objects: []effects.ObjectRef{
						{Kind: effects.ObjectTable, Name: tbl},
						{Kind: effects.ObjectFilesystemPath, Path: s3},
					},
				},
			},
		}
		return cs, true
	}
	return effects.ClassifiedStatement{}, false
}
