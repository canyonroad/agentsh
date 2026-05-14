package policy

import (
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/gobwas/glob"
)

const defaultApproveTimeout = 60 * time.Second

// compiledStatementRule is the evaluator-ready form of a StatementRule.
type compiledStatementRule struct {
	src           *StatementRule
	verb          DecisionVerb
	groups        map[effects.Group]struct{}
	subtypes      map[effects.Subtype]struct{} // empty = all subtypes match
	resolution    resolutionMatcher
	schemas       []glob.Glob // empty = all schemas match
	objects       []glob.Glob // syntactic object selectors
	relations     []glob.Glob // resolved relation canonical names
	functions     []glob.Glob // resolved function identity names
	timeout       time.Duration
	msgTemplate   *template.Template // nil = no message rendering
	serviceFilter serviceFilter
}

// compiledConnectionRule is the evaluator-ready form of a ConnectionRule.
type compiledConnectionRule struct {
	src             *ConnectionRule
	verb            DecisionVerb
	matchKind       ConnectionMatchKind
	dbUsers         map[string]struct{} // empty = no constraint
	database        string              // "" = no constraint
	applicationName glob.Glob           // nil = no constraint
	clientIdentity  glob.Glob           // nil = no constraint
	timeout         time.Duration
	msgTemplate     *template.Template
	serviceFilter   serviceFilter
}

// resolutionMatcher selects which Resolution values match.
//
//	kind=any  → matches anything (corresponds to MatchObjectResolution == "" or "*")
//	kind=eq   → matches exactly r
type resolutionMatcher struct {
	kind resMatcherKind
	r    effects.Resolution
}

type resMatcherKind uint8

const (
	resAny resMatcherKind = iota
	resEq
)

func (m resolutionMatcher) matches(r effects.Resolution) bool {
	switch m.kind {
	case resAny:
		return true
	case resEq:
		return m.r == r
	default:
		return false
	}
}

// serviceFilter encodes the (db_service, db_family, db_dialect) filter on a rule.
// Empty fields mean "any". A rule applies to a service S iff every non-empty
// filter field equals the corresponding field on S.
type serviceFilter struct {
	service ServiceID
	family  string
	dialect string
}

// matches reports whether the rule applies to the named service. svcs[id] must
// exist (rule_service_unknown is caught at validate time).
func (f serviceFilter) matches(id ServiceID, svc *DBService) bool {
	if f.service != "" && f.service != id {
		return false
	}
	if f.family != "" && (svc == nil || svc.Family != f.family) {
		return false
	}
	if f.dialect != "" && (svc == nil || svc.Dialect != f.dialect) {
		return false
	}
	return true
}

// messageContext is the data passed to a rule's message template.
//
// StatementPreview is wired by Plan 03+ when ClassifiedStatement gains a
// statement-text field. In Plan 02 it is always the empty string; templates
// that reference {{.StatementPreview}} render as an empty value.
type messageContext struct {
	Operation        string
	Subtype          string
	Schema           string
	Object           string
	Verb             string
	StatementPreview string
}

// compileStatementRule transforms a validated StatementRule into a
// compiledStatementRule. Errors carry the "glob_compile" or
// "message_template_parse" prefix for caller surfacing.
func compileStatementRule(r *StatementRule) (*compiledStatementRule, error) {
	c := &compiledStatementRule{
		src:           r,
		groups:        map[effects.Group]struct{}{},
		subtypes:      map[effects.Subtype]struct{}{},
		serviceFilter: serviceFilter{service: ServiceID(r.DBService), family: r.DBFamily, dialect: r.DBDialect},
	}
	switch r.Decision {
	case "allow":
		c.verb = VerbAllow
	case "deny":
		c.verb = VerbDeny
	case "approve":
		c.verb = VerbApprove
	case "audit":
		c.verb = VerbAudit
	default:
		return nil, fmt.Errorf("compile: rule %q has unhandled decision %q (validate should have rejected)", r.Name, r.Decision)
	}

	for _, op := range r.Operations {
		gs, ok := effects.ExpandAlias(op)
		if !ok {
			return nil, fmt.Errorf("compile: rule %q has unknown operation %q (validate should have rejected)", r.Name, op)
		}
		for _, g := range gs {
			c.groups[g] = struct{}{}
		}
	}
	for _, st := range r.Subtypes {
		s, ok := effects.ParseSubtype(st)
		if !ok {
			return nil, fmt.Errorf("compile: rule %q has unknown subtype %q", r.Name, st)
		}
		c.subtypes[s] = struct{}{}
	}

	switch r.MatchObjectResolution {
	case "", "*":
		c.resolution = resolutionMatcher{kind: resAny}
	default:
		res, ok := effects.ParseResolution(r.MatchObjectResolution)
		if !ok {
			return nil, fmt.Errorf("compile: rule %q has unknown match_object_resolution %q", r.Name, r.MatchObjectResolution)
		}
		c.resolution = resolutionMatcher{kind: resEq, r: res}
	}

	for _, pat := range r.Schemas {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: rule %q schemas %q: %w", r.Name, pat, err)
		}
		c.schemas = append(c.schemas, g)
	}
	for _, pat := range r.Objects {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: rule %q objects %q: %w", r.Name, pat, err)
		}
		c.objects = append(c.objects, g)
	}
	for _, pat := range r.Relations {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: rule %q relations %q: %w", r.Name, pat, err)
		}
		c.relations = append(c.relations, g)
	}
	for _, pat := range r.Functions {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: rule %q functions %q: %w", r.Name, pat, err)
		}
		c.functions = append(c.functions, g)
	}

	if strings.TrimSpace(r.Message) != "" {
		tmpl, err := template.New("msg").Parse(r.Message)
		if err != nil {
			return nil, fmt.Errorf("message_template_parse: rule %q: %w", r.Name, err)
		}
		c.msgTemplate = tmpl
	}

	c.timeout = r.Timeout
	if r.Decision == "approve" && c.timeout == 0 {
		c.timeout = defaultApproveTimeout
	}

	return c, nil
}

func (c *compiledStatementRule) coversAllObjects() bool { return !c.hasObjectSelectors() }

func (c *compiledStatementRule) hasObjectSelectors() bool {
	return len(c.objects) > 0 || len(c.relations) > 0 || len(c.functions) > 0
}

func (c *compiledStatementRule) matchesResolution(r effects.Resolution) bool {
	return c.resolution.matches(r)
}

// objectMatches reports whether any of the rule's `objects` globs matches
// the given ObjectRef per the kind→field table in this plan's File Structure
// section. Returns true unconditionally only when no object selector family is
// constrained.
func (c *compiledStatementRule) objectMatches(o effects.ObjectRef) bool {
	if c.coversAllObjects() {
		return true
	}
	target := objectMatchField(o)
	for _, g := range c.objects {
		if g.Match(target) {
			return true
		}
	}
	return false
}

func (c *compiledStatementRule) schemaMatchesObjectSlot(o effects.ObjectRef, resolved effects.ResolvedObjectRef, hasResolved bool) bool {
	if len(c.schemas) == 0 {
		return true
	}
	for _, g := range c.schemas {
		if o.Schema != "" && g.Match(o.Schema) {
			return true
		}
		if hasResolved && resolved.Schema != "" && g.Match(resolved.Schema) {
			return true
		}
	}
	return false
}

func (c *compiledStatementRule) schemaMatchesResolvedObject(resolved effects.ResolvedObjectRef) bool {
	if len(c.schemas) == 0 {
		return true
	}
	if resolved.Schema == "" {
		return false
	}
	for _, g := range c.schemas {
		if g.Match(resolved.Schema) {
			return true
		}
	}
	return false
}

func (c *compiledStatementRule) relationMatches(r effects.ResolvedObjectRef) bool {
	if len(c.relations) == 0 {
		return false
	}
	if r.Source != effects.ResolvedObjectSourceCatalog ||
		r.Kind != effects.ResolvedObjectRelation ||
		r.UnresolvedReason != "" {
		return false
	}
	target := r.CanonicalName()
	for _, g := range c.relations {
		if g.Match(target) {
			return true
		}
	}
	return false
}

func (c *compiledStatementRule) functionMatches(r effects.ResolvedObjectRef) bool {
	if len(c.functions) == 0 {
		return false
	}
	if r.Source != effects.ResolvedObjectSourceCatalog ||
		r.Kind != effects.ResolvedObjectFunction ||
		r.UnresolvedReason != "" {
		return false
	}
	target := resolvedFunctionIdentity(r)
	for _, g := range c.functions {
		if g.Match(target) {
			return true
		}
	}
	return false
}

func resolvedFunctionIdentity(r effects.ResolvedObjectRef) string {
	name := r.CanonicalName()
	return name + "(" + r.FunctionIdentityArgs + ")"
}

// renderMessage applies the rule's message template, or returns the raw
// Message string if no template was set.
func (c *compiledStatementRule) renderMessage(ctx messageContext) string {
	if c.msgTemplate == nil {
		return c.src.Message
	}
	var sb strings.Builder
	if err := c.msgTemplate.Execute(&sb, ctx); err != nil {
		// Templates were validated at compile time; runtime failure here means
		// a bug. Surface it visibly rather than silently swallowing.
		return fmt.Sprintf("<message render error: %v>", err)
	}
	return sb.String()
}

// objectMatchField returns the canonical glob target for an ObjectRef per the
// File Structure table in this plan.
func objectMatchField(o effects.ObjectRef) string {
	switch o.Kind {
	case effects.ObjectExternalEndpoint:
		return o.Host
	case effects.ObjectFilesystemPath:
		return o.Path
	case effects.ObjectProgram:
		return o.Argv0
	default:
		return o.Name
	}
}

// compileConnectionRule transforms a validated ConnectionRule.
func compileConnectionRule(r *ConnectionRule) (*compiledConnectionRule, error) {
	c := &compiledConnectionRule{
		src:           r,
		serviceFilter: serviceFilter{service: ServiceID(r.DBService)},
	}
	switch r.Decision {
	case "allow":
		c.verb = VerbAllow
	case "deny":
		c.verb = VerbDeny
	case "approve":
		c.verb = VerbApprove
	case "audit":
		c.verb = VerbAudit
	default:
		return nil, fmt.Errorf("compile: conn rule %q has unhandled decision %q", r.Name, r.Decision)
	}
	switch r.MatchKind {
	case "", "connect":
		c.matchKind = MatchConnect
	case "cancel":
		c.matchKind = MatchCancel
	case "replication":
		c.matchKind = MatchReplication
	default:
		return nil, fmt.Errorf("compile: conn rule %q has unhandled match_kind %q", r.Name, r.MatchKind)
	}
	if len(r.DBUser) > 0 {
		c.dbUsers = make(map[string]struct{}, len(r.DBUser))
		for _, u := range r.DBUser {
			c.dbUsers[u] = struct{}{}
		}
	}
	c.database = r.Database
	if r.ApplicationName != "" {
		g, err := glob.Compile(r.ApplicationName)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: conn rule %q application_name %q: %w", r.Name, r.ApplicationName, err)
		}
		c.applicationName = g
	}
	if r.ClientIdentity != "" {
		g, err := glob.Compile(r.ClientIdentity)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: conn rule %q client_identity %q: %w", r.Name, r.ClientIdentity, err)
		}
		c.clientIdentity = g
	}
	if strings.TrimSpace(r.Message) != "" {
		tmpl, err := template.New("msg").Parse(r.Message)
		if err != nil {
			return nil, fmt.Errorf("message_template_parse: conn rule %q: %w", r.Name, err)
		}
		c.msgTemplate = tmpl
	}
	c.timeout = r.Timeout
	if r.Decision == "approve" && c.timeout == 0 {
		c.timeout = defaultApproveTimeout
	}
	return c, nil
}

func (c *compiledConnectionRule) renderMessage(ctx messageContext) string {
	if c.msgTemplate == nil {
		return c.src.Message
	}
	var sb strings.Builder
	if err := c.msgTemplate.Execute(&sb, ctx); err != nil {
		return fmt.Sprintf("<message render error: %v>", err)
	}
	return sb.String()
}
