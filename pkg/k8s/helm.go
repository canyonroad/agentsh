package k8s

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v3"
)

// HelmValues represents the values.yaml for the Helm chart.
type HelmValues struct {
	// ReplicaCount is the number of replicas.
	ReplicaCount int `yaml:"replicaCount"`

	// Image configuration.
	Image ImageConfig `yaml:"image"`

	// Service configuration.
	Service ServiceConfig `yaml:"service"`

	// Policies configuration.
	Policies PoliciesConfig `yaml:"policies"`

	// Resources configuration.
	Resources HelmResourceConfig `yaml:"resources"`

	// Metrics configuration.
	Metrics MetricsConfig `yaml:"metrics"`

	// RBAC configuration.
	RBAC RBACConfig `yaml:"rbac"`

	// PodSecurityContext configuration.
	PodSecurityContext PodSecurityContextConfig `yaml:"podSecurityContext"`

	// SecurityContext configuration.
	SecurityContext HelmSecurityContext `yaml:"securityContext"`

	// NodeSelector for pod scheduling.
	NodeSelector map[string]string `yaml:"nodeSelector,omitempty"`

	// Tolerations for pod scheduling.
	Tolerations []Toleration `yaml:"tolerations,omitempty"`

	// Affinity for pod scheduling.
	Affinity *Affinity `yaml:"affinity,omitempty"`

	// Operator configuration.
	Operator OperatorHelmConfig `yaml:"operator"`

	// Ingress configuration.
	Ingress IngressConfig `yaml:"ingress"`
}

// ImageConfig configures container images.
type ImageConfig struct {
	Repository string `yaml:"repository"`
	Tag        string `yaml:"tag"`
	PullPolicy string `yaml:"pullPolicy"`
}

// ServiceConfig configures the Kubernetes service.
type ServiceConfig struct {
	Type        string `yaml:"type"`
	APIPort     int    `yaml:"apiPort"`
	MetricsPort int    `yaml:"metricsPort"`
}

// PoliciesConfig configures policy ConfigMaps.
type PoliciesConfig struct {
	Create bool              `yaml:"create"`
	Files  map[string]string `yaml:"files,omitempty"`
}

// HelmResourceConfig configures resource requirements.
type HelmResourceConfig struct {
	Limits   ResourceValues `yaml:"limits"`
	Requests ResourceValues `yaml:"requests"`
}

// ResourceValues specifies CPU and memory values.
type ResourceValues struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
}

// MetricsConfig configures metrics and monitoring.
type MetricsConfig struct {
	Enabled        bool                 `yaml:"enabled"`
	ServiceMonitor ServiceMonitorConfig `yaml:"serviceMonitor"`
}

// ServiceMonitorConfig configures the Prometheus ServiceMonitor.
type ServiceMonitorConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
}

// RBACConfig configures RBAC resources.
type RBACConfig struct {
	Create bool `yaml:"create"`
}

// PodSecurityContextConfig configures pod-level security.
type PodSecurityContextConfig struct {
	FSGroup int64 `yaml:"fsGroup"`
}

// HelmSecurityContext configures container-level security.
type HelmSecurityContext struct {
	Capabilities HelmCapabilities `yaml:"capabilities"`
	Privileged   bool             `yaml:"privileged"`
}

// HelmCapabilities configures Linux capabilities.
type HelmCapabilities struct {
	Add []string `yaml:"add"`
}

// Toleration represents a Kubernetes toleration.
type Toleration struct {
	Key      string `yaml:"key,omitempty"`
	Operator string `yaml:"operator,omitempty"`
	Value    string `yaml:"value,omitempty"`
	Effect   string `yaml:"effect,omitempty"`
}

// Affinity represents pod scheduling affinity.
type Affinity struct {
	NodeAffinity    *NodeAffinity    `yaml:"nodeAffinity,omitempty"`
	PodAffinity     *PodAffinity     `yaml:"podAffinity,omitempty"`
	PodAntiAffinity *PodAntiAffinity `yaml:"podAntiAffinity,omitempty"`
}

// NodeAffinity represents node affinity rules.
type NodeAffinity struct {
	RequiredDuringSchedulingIgnoredDuringExecution  *NodeSelector         `yaml:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
	PreferredDuringSchedulingIgnoredDuringExecution []PreferredScheduling `yaml:"preferredDuringSchedulingIgnoredDuringExecution,omitempty"`
}

// NodeSelector for node affinity.
type NodeSelector struct {
	NodeSelectorTerms []NodeSelectorTerm `yaml:"nodeSelectorTerms"`
}

// NodeSelectorTerm represents a node selector term.
type NodeSelectorTerm struct {
	MatchExpressions []MatchExpression `yaml:"matchExpressions,omitempty"`
}

// MatchExpression for label matching.
type MatchExpression struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values,omitempty"`
}

// PreferredScheduling represents preferred scheduling.
type PreferredScheduling struct {
	Weight     int              `yaml:"weight"`
	Preference NodeSelectorTerm `yaml:"preference"`
}

// PodAffinity represents pod affinity rules.
type PodAffinity struct{}

// PodAntiAffinity represents pod anti-affinity rules.
type PodAntiAffinity struct{}

// OperatorHelmConfig configures the operator.
type OperatorHelmConfig struct {
	Enabled bool   `yaml:"enabled"`
	Image   string `yaml:"image,omitempty"`
}

// IngressConfig configures the Ingress resource.
type IngressConfig struct {
	Enabled     bool              `yaml:"enabled"`
	ClassName   string            `yaml:"className,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
	Hosts       []IngressHost     `yaml:"hosts,omitempty"`
	TLS         []IngressTLS      `yaml:"tls,omitempty"`
}

// IngressHost configures an ingress host.
type IngressHost struct {
	Host  string        `yaml:"host"`
	Paths []IngressPath `yaml:"paths"`
}

// IngressPath configures an ingress path.
type IngressPath struct {
	Path     string `yaml:"path"`
	PathType string `yaml:"pathType"`
}

// IngressTLS configures TLS for ingress.
type IngressTLS struct {
	SecretName string   `yaml:"secretName"`
	Hosts      []string `yaml:"hosts"`
}

// DefaultHelmValues returns default Helm values.
func DefaultHelmValues() HelmValues {
	return HelmValues{
		ReplicaCount: 3,
		Image: ImageConfig{
			Repository: "agentsh/agentsh",
			Tag:        "latest",
			PullPolicy: "IfNotPresent",
		},
		Service: ServiceConfig{
			Type:        "ClusterIP",
			APIPort:     9090,
			MetricsPort: 9091,
		},
		Policies: PoliciesConfig{
			Create: true,
			Files: map[string]string{
				"env.yaml": `env_protection:
  enabled: true
  mode: allowlist
  allowlist: [PATH, HOME, USER, SHELL]`,
				"files.yaml": `file_policy:
  default_action: deny`,
			},
		},
		Resources: HelmResourceConfig{
			Limits: ResourceValues{
				CPU:    "500m",
				Memory: "512Mi",
			},
			Requests: ResourceValues{
				CPU:    "100m",
				Memory: "128Mi",
			},
		},
		Metrics: MetricsConfig{
			Enabled: true,
			ServiceMonitor: ServiceMonitorConfig{
				Enabled:  true,
				Interval: "15s",
			},
		},
		RBAC: RBACConfig{
			Create: true,
		},
		PodSecurityContext: PodSecurityContextConfig{
			FSGroup: 1000,
		},
		SecurityContext: HelmSecurityContext{
			Capabilities: HelmCapabilities{
				Add: []string{"SYS_ADMIN", "NET_ADMIN"},
			},
			Privileged: true,
		},
		Operator: OperatorHelmConfig{
			Enabled: true,
		},
		Ingress: IngressConfig{
			Enabled: false,
		},
	}
}

// HelmChart represents a Helm chart.
type HelmChart struct {
	values HelmValues
}

// NewHelmChart creates a new Helm chart.
func NewHelmChart(values HelmValues) *HelmChart {
	return &HelmChart{values: values}
}

// Values returns the chart values.
func (c *HelmChart) Values() HelmValues {
	return c.values
}

// WriteValues writes values.yaml to a writer.
func (c *HelmChart) WriteValues(w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	return encoder.Encode(c.values)
}

// WriteValuesFile writes values.yaml to a file.
func (c *HelmChart) WriteValuesFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	return c.WriteValues(f)
}

// GenerateChart generates a complete Helm chart in the specified directory.
func (c *HelmChart) GenerateChart(chartDir string) error {
	// Create directory structure
	dirs := []string{
		chartDir,
		filepath.Join(chartDir, "templates"),
		filepath.Join(chartDir, "crds"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	// Write Chart.yaml
	if err := c.writeChartYAML(chartDir); err != nil {
		return err
	}

	// Write values.yaml
	if err := c.WriteValuesFile(filepath.Join(chartDir, "values.yaml")); err != nil {
		return err
	}

	// Write templates
	if err := c.writeTemplates(chartDir); err != nil {
		return err
	}

	// Write CRDs
	if err := c.writeCRDs(chartDir); err != nil {
		return err
	}

	return nil
}

// writeChartYAML writes the Chart.yaml file.
func (c *HelmChart) writeChartYAML(chartDir string) error {
	chart := map[string]any{
		"apiVersion":  "v2",
		"name":        "agentsh",
		"description": "A Helm chart for agentsh - AI agent sandbox and policy enforcement",
		"type":        "application",
		"version":     "0.1.0",
		"appVersion":  "1.0.0",
		"keywords":    []string{"ai", "agent", "sandbox", "security", "policy"},
		"home":        "https://github.com/agentsh/agentsh",
		"sources":     []string{"https://github.com/agentsh/agentsh"},
		"maintainers": []map[string]string{
			{"name": "agentsh", "email": "maintainers@agentsh.io"},
		},
	}

	f, err := os.Create(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		return fmt.Errorf("creating Chart.yaml: %w", err)
	}
	defer f.Close()

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	return encoder.Encode(chart)
}

// writeTemplates writes the template files.
func (c *HelmChart) writeTemplates(chartDir string) error {
	templates := map[string]string{
		"deployment.yaml":     deploymentTemplate,
		"service.yaml":        serviceTemplate,
		"configmap.yaml":      configMapTemplate,
		"serviceaccount.yaml": serviceAccountTemplate,
		"rbac.yaml":           rbacTemplate,
		"servicemonitor.yaml": serviceMonitorTemplate,
		"_helpers.tpl":        helpersTemplate,
	}

	for name, content := range templates {
		path := filepath.Join(chartDir, "templates", name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}

	return nil
}

// writeCRDs writes the CRD files.
func (c *HelmChart) writeCRDs(chartDir string) error {
	path := filepath.Join(chartDir, "crds", "agentshsession-crd.yaml")
	return os.WriteFile(path, []byte(crdTemplate), 0644)
}

// RenderTemplate renders a template with the given values.
func (c *HelmChart) RenderTemplate(name, tmplContent string) (string, error) {
	tmpl, err := template.New(name).Parse(tmplContent)
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, c.values); err != nil {
		return "", fmt.Errorf("executing template: %w", err)
	}

	return buf.String(), nil
}

// Template content
const deploymentTemplate = `{{- if .Values.replicaCount }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "agentsh.fullname" . }}
  labels:
    {{- include "agentsh.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "agentsh.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "agentsh.selectorLabels" . | nindent 8 }}
    spec:
      serviceAccountName: {{ include "agentsh.serviceAccountName" . }}
      securityContext:
        {{- toYaml .Values.podSecurityContext | nindent 8 }}
      containers:
        - name: agentsh
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - name: api
              containerPort: {{ .Values.service.apiPort }}
              protocol: TCP
            - name: metrics
              containerPort: {{ .Values.service.metricsPort }}
              protocol: TCP
          securityContext:
            {{- toYaml .Values.securityContext | nindent 12 }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          volumeMounts:
            - name: policies
              mountPath: /etc/agentsh/policies
              readOnly: true
          livenessProbe:
            httpGet:
              path: /healthz
              port: api
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: api
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: policies
          configMap:
            name: {{ include "agentsh.fullname" . }}-policies
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end }}
`

const serviceTemplate = `apiVersion: v1
kind: Service
metadata:
  name: {{ include "agentsh.fullname" . }}
  labels:
    {{- include "agentsh.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.apiPort }}
      targetPort: api
      protocol: TCP
      name: api
    - port: {{ .Values.service.metricsPort }}
      targetPort: metrics
      protocol: TCP
      name: metrics
  selector:
    {{- include "agentsh.selectorLabels" . | nindent 4 }}
`

const configMapTemplate = `{{- if .Values.policies.create }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "agentsh.fullname" . }}-policies
  labels:
    {{- include "agentsh.labels" . | nindent 4 }}
data:
  {{- range $name, $content := .Values.policies.files }}
  {{ $name }}: |
    {{ $content | nindent 4 }}
  {{- end }}
{{- end }}
`

const serviceAccountTemplate = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "agentsh.serviceAccountName" . }}
  labels:
    {{- include "agentsh.labels" . | nindent 4 }}
`

const rbacTemplate = `{{- if .Values.rbac.create }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "agentsh.fullname" . }}
  labels:
    {{- include "agentsh.labels" . | nindent 4 }}
rules:
  - apiGroups: ["agentsh.io"]
    resources: ["agentshsessions"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["agentsh.io"]
    resources: ["agentshsessions/status"]
    verbs: ["get", "update", "patch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "agentsh.fullname" . }}
  labels:
    {{- include "agentsh.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "agentsh.fullname" . }}
subjects:
  - kind: ServiceAccount
    name: {{ include "agentsh.serviceAccountName" . }}
    namespace: {{ .Release.Namespace }}
{{- end }}
`

const serviceMonitorTemplate = `{{- if and .Values.metrics.enabled .Values.metrics.serviceMonitor.enabled }}
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ include "agentsh.fullname" . }}
  labels:
    {{- include "agentsh.labels" . | nindent 4 }}
spec:
  selector:
    matchLabels:
      {{- include "agentsh.selectorLabels" . | nindent 6 }}
  endpoints:
    - port: metrics
      interval: {{ .Values.metrics.serviceMonitor.interval }}
      path: /metrics
{{- end }}
`

const helpersTemplate = `{{/*
Expand the name of the chart.
*/}}
{{- define "agentsh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "agentsh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "agentsh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "agentsh.labels" -}}
helm.sh/chart: {{ include "agentsh.chart" . }}
{{ include "agentsh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "agentsh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentsh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "agentsh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "agentsh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
`

const crdTemplate = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: agentshsessions.agentsh.io
spec:
  group: agentsh.io
  names:
    kind: AgentshSession
    plural: agentshsessions
    singular: agentshsession
    shortNames:
      - as
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required:
                - agentImage
              properties:
                agentImage:
                  type: string
                  description: Container image for the AI agent
                policyRef:
                  type: string
                  description: Reference to a policy ConfigMap
                timeout:
                  type: string
                  description: Maximum session duration (e.g., "1h", "30m")
                resources:
                  type: object
                  properties:
                    limits:
                      type: object
                      additionalProperties:
                        anyOf:
                          - type: integer
                          - type: string
                    requests:
                      type: object
                      additionalProperties:
                        anyOf:
                          - type: integer
                          - type: string
                environment:
                  type: object
                  additionalProperties:
                    type: string
                serviceAccountName:
                  type: string
                agentshConfig:
                  type: object
                  properties:
                    image:
                      type: string
                    apiPort:
                      type: integer
                    metricsPort:
                      type: integer
            status:
              type: object
              properties:
                state:
                  type: string
                  enum:
                    - Pending
                    - Running
                    - Succeeded
                    - Failed
                    - TimedOut
                startTime:
                  type: string
                  format: date-time
                endTime:
                  type: string
                  format: date-time
                podName:
                  type: string
                message:
                  type: string
                stats:
                  type: object
                  properties:
                    fileOperations:
                      type: integer
                    networkRequests:
                      type: integer
                    commandsExecuted:
                      type: integer
                    policyViolations:
                      type: integer
                    durationSeconds:
                      type: integer
      subresources:
        status: {}
      additionalPrinterColumns:
        - name: State
          type: string
          jsonPath: .status.state
        - name: Pod
          type: string
          jsonPath: .status.podName
        - name: Age
          type: date
          jsonPath: .metadata.creationTimestamp
`
