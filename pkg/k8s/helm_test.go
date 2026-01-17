package k8s

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultHelmValues(t *testing.T) {
	values := DefaultHelmValues()

	if values.ReplicaCount != 3 {
		t.Errorf("ReplicaCount = %d, want 3", values.ReplicaCount)
	}

	if values.Image.Repository != "agentsh/agentsh" {
		t.Errorf("Image.Repository = %q, want agentsh/agentsh", values.Image.Repository)
	}

	if values.Image.Tag != "latest" {
		t.Errorf("Image.Tag = %q, want latest", values.Image.Tag)
	}

	if values.Service.Type != "ClusterIP" {
		t.Errorf("Service.Type = %q, want ClusterIP", values.Service.Type)
	}

	if values.Service.APIPort != 9090 {
		t.Errorf("Service.APIPort = %d, want 9090", values.Service.APIPort)
	}

	if values.Service.MetricsPort != 9091 {
		t.Errorf("Service.MetricsPort = %d, want 9091", values.Service.MetricsPort)
	}
}

func TestHelmValues_Policies(t *testing.T) {
	values := DefaultHelmValues()

	if !values.Policies.Create {
		t.Error("Policies.Create should be true")
	}

	if len(values.Policies.Files) == 0 {
		t.Error("Policies.Files should not be empty")
	}

	if _, ok := values.Policies.Files["env.yaml"]; !ok {
		t.Error("env.yaml should be in policies")
	}

	if _, ok := values.Policies.Files["files.yaml"]; !ok {
		t.Error("files.yaml should be in policies")
	}
}

func TestHelmValues_Resources(t *testing.T) {
	values := DefaultHelmValues()

	if values.Resources.Limits.CPU != "500m" {
		t.Errorf("Resources.Limits.CPU = %q, want 500m", values.Resources.Limits.CPU)
	}

	if values.Resources.Limits.Memory != "512Mi" {
		t.Errorf("Resources.Limits.Memory = %q, want 512Mi", values.Resources.Limits.Memory)
	}

	if values.Resources.Requests.CPU != "100m" {
		t.Errorf("Resources.Requests.CPU = %q, want 100m", values.Resources.Requests.CPU)
	}

	if values.Resources.Requests.Memory != "128Mi" {
		t.Errorf("Resources.Requests.Memory = %q, want 128Mi", values.Resources.Requests.Memory)
	}
}

func TestHelmValues_Metrics(t *testing.T) {
	values := DefaultHelmValues()

	if !values.Metrics.Enabled {
		t.Error("Metrics.Enabled should be true")
	}

	if !values.Metrics.ServiceMonitor.Enabled {
		t.Error("Metrics.ServiceMonitor.Enabled should be true")
	}

	if values.Metrics.ServiceMonitor.Interval != "15s" {
		t.Errorf("ServiceMonitor.Interval = %q, want 15s", values.Metrics.ServiceMonitor.Interval)
	}
}

func TestHelmValues_Security(t *testing.T) {
	values := DefaultHelmValues()

	if !values.SecurityContext.Privileged {
		t.Error("SecurityContext.Privileged should be true")
	}

	if len(values.SecurityContext.Capabilities.Add) != 2 {
		t.Errorf("Capabilities.Add count = %d, want 2", len(values.SecurityContext.Capabilities.Add))
	}

	hasAdmin := false
	hasNet := false
	for _, cap := range values.SecurityContext.Capabilities.Add {
		if cap == "SYS_ADMIN" {
			hasAdmin = true
		}
		if cap == "NET_ADMIN" {
			hasNet = true
		}
	}

	if !hasAdmin {
		t.Error("should have SYS_ADMIN capability")
	}

	if !hasNet {
		t.Error("should have NET_ADMIN capability")
	}
}

func TestHelmValues_PodSecurityContext(t *testing.T) {
	values := DefaultHelmValues()

	if values.PodSecurityContext.FSGroup != 1000 {
		t.Errorf("PodSecurityContext.FSGroup = %d, want 1000", values.PodSecurityContext.FSGroup)
	}
}

func TestHelmValues_RBAC(t *testing.T) {
	values := DefaultHelmValues()

	if !values.RBAC.Create {
		t.Error("RBAC.Create should be true")
	}
}

func TestHelmValues_Operator(t *testing.T) {
	values := DefaultHelmValues()

	if !values.Operator.Enabled {
		t.Error("Operator.Enabled should be true")
	}
}

func TestHelmValues_Ingress(t *testing.T) {
	values := DefaultHelmValues()

	if values.Ingress.Enabled {
		t.Error("Ingress.Enabled should be false by default")
	}
}

func TestNewHelmChart(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	if chart == nil {
		t.Fatal("expected non-nil chart")
	}

	if chart.Values().ReplicaCount != values.ReplicaCount {
		t.Error("chart values should match input")
	}
}

func TestHelmChart_WriteValues(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	var buf bytes.Buffer
	err := chart.WriteValues(&buf)
	if err != nil {
		t.Fatalf("WriteValues error: %v", err)
	}

	content := buf.String()

	if !strings.Contains(content, "replicaCount: 3") {
		t.Error("should contain replicaCount")
	}

	if !strings.Contains(content, "repository: agentsh/agentsh") {
		t.Error("should contain image repository")
	}
}

func TestHelmChart_WriteValuesFile(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	tmpDir, err := os.MkdirTemp("", "helm-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	valuesPath := filepath.Join(tmpDir, "values.yaml")
	err = chart.WriteValuesFile(valuesPath)
	if err != nil {
		t.Fatalf("WriteValuesFile error: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	if !strings.Contains(string(data), "replicaCount") {
		t.Error("file should contain replicaCount")
	}
}

func TestHelmChart_GenerateChart(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	tmpDir, err := os.MkdirTemp("", "helm-chart-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	chartDir := filepath.Join(tmpDir, "agentsh")
	err = chart.GenerateChart(chartDir)
	if err != nil {
		t.Fatalf("GenerateChart error: %v", err)
	}

	// Check Chart.yaml exists
	chartYaml := filepath.Join(chartDir, "Chart.yaml")
	if _, err := os.Stat(chartYaml); os.IsNotExist(err) {
		t.Error("Chart.yaml should exist")
	}

	// Check values.yaml exists
	valuesYaml := filepath.Join(chartDir, "values.yaml")
	if _, err := os.Stat(valuesYaml); os.IsNotExist(err) {
		t.Error("values.yaml should exist")
	}

	// Check templates directory exists
	templatesDir := filepath.Join(chartDir, "templates")
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		t.Error("templates directory should exist")
	}

	// Check crds directory exists
	crdsDir := filepath.Join(chartDir, "crds")
	if _, err := os.Stat(crdsDir); os.IsNotExist(err) {
		t.Error("crds directory should exist")
	}

	// Check deployment template exists
	deploymentTpl := filepath.Join(templatesDir, "deployment.yaml")
	if _, err := os.Stat(deploymentTpl); os.IsNotExist(err) {
		t.Error("deployment.yaml template should exist")
	}

	// Check service template exists
	serviceTpl := filepath.Join(templatesDir, "service.yaml")
	if _, err := os.Stat(serviceTpl); os.IsNotExist(err) {
		t.Error("service.yaml template should exist")
	}

	// Check CRD exists
	crdFile := filepath.Join(crdsDir, "agentshsession-crd.yaml")
	if _, err := os.Stat(crdFile); os.IsNotExist(err) {
		t.Error("CRD file should exist")
	}
}

func TestHelmChart_ChartYAMLContent(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	tmpDir, err := os.MkdirTemp("", "helm-chart-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	chartDir := filepath.Join(tmpDir, "agentsh")
	err = chart.GenerateChart(chartDir)
	if err != nil {
		t.Fatalf("GenerateChart error: %v", err)
	}

	// Read Chart.yaml
	data, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		t.Fatalf("reading Chart.yaml: %v", err)
	}

	var chartMeta map[string]any
	err = yaml.Unmarshal(data, &chartMeta)
	if err != nil {
		t.Fatalf("parsing Chart.yaml: %v", err)
	}

	if chartMeta["apiVersion"] != "v2" {
		t.Errorf("apiVersion = %v, want v2", chartMeta["apiVersion"])
	}

	if chartMeta["name"] != "agentsh" {
		t.Errorf("name = %v, want agentsh", chartMeta["name"])
	}

	if chartMeta["type"] != "application" {
		t.Errorf("type = %v, want application", chartMeta["type"])
	}
}

func TestHelmChart_CRDContent(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	tmpDir, err := os.MkdirTemp("", "helm-chart-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	chartDir := filepath.Join(tmpDir, "agentsh")
	err = chart.GenerateChart(chartDir)
	if err != nil {
		t.Fatalf("GenerateChart error: %v", err)
	}

	// Read CRD
	data, err := os.ReadFile(filepath.Join(chartDir, "crds", "agentshsession-crd.yaml"))
	if err != nil {
		t.Fatalf("reading CRD: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "agentshsessions.agentsh.io") {
		t.Error("CRD should contain resource name")
	}

	if !strings.Contains(content, "AgentshSession") {
		t.Error("CRD should contain kind")
	}

	if !strings.Contains(content, "agentImage") {
		t.Error("CRD should contain agentImage property")
	}
}

func TestHelmChart_Templates(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	tmpDir, err := os.MkdirTemp("", "helm-chart-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	chartDir := filepath.Join(tmpDir, "agentsh")
	err = chart.GenerateChart(chartDir)
	if err != nil {
		t.Fatalf("GenerateChart error: %v", err)
	}

	templates := []string{
		"deployment.yaml",
		"service.yaml",
		"configmap.yaml",
		"serviceaccount.yaml",
		"rbac.yaml",
		"servicemonitor.yaml",
		"_helpers.tpl",
	}

	for _, tpl := range templates {
		path := filepath.Join(chartDir, "templates", tpl)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("template %s should exist", tpl)
		}
	}
}

func TestHelmValues_YAML_Roundtrip(t *testing.T) {
	values := DefaultHelmValues()

	// Marshal
	data, err := yaml.Marshal(values)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	// Unmarshal
	var parsed HelmValues
	err = yaml.Unmarshal(data, &parsed)
	if err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	// Verify
	if parsed.ReplicaCount != values.ReplicaCount {
		t.Errorf("ReplicaCount = %d, want %d", parsed.ReplicaCount, values.ReplicaCount)
	}

	if parsed.Image.Repository != values.Image.Repository {
		t.Errorf("Image.Repository = %q, want %q", parsed.Image.Repository, values.Image.Repository)
	}
}

func TestHelmValues_CustomValues(t *testing.T) {
	values := HelmValues{
		ReplicaCount: 5,
		Image: ImageConfig{
			Repository: "custom/image",
			Tag:        "v1.0.0",
			PullPolicy: "Always",
		},
		Service: ServiceConfig{
			Type:        "LoadBalancer",
			APIPort:     18080,
			MetricsPort: 8081,
		},
		NodeSelector: map[string]string{
			"disk": "ssd",
		},
		Tolerations: []Toleration{
			{
				Key:      "node-role",
				Operator: "Equal",
				Value:    "agent",
				Effect:   "NoSchedule",
			},
		},
	}

	chart := NewHelmChart(values)

	var buf bytes.Buffer
	err := chart.WriteValues(&buf)
	if err != nil {
		t.Fatalf("WriteValues error: %v", err)
	}

	content := buf.String()

	if !strings.Contains(content, "replicaCount: 5") {
		t.Error("should contain custom replicaCount")
	}

	if !strings.Contains(content, "repository: custom/image") {
		t.Error("should contain custom repository")
	}

	if !strings.Contains(content, "type: LoadBalancer") {
		t.Error("should contain LoadBalancer service type")
	}

	if !strings.Contains(content, "disk: ssd") {
		t.Error("should contain node selector")
	}
}

func TestHelmValues_IngressConfig(t *testing.T) {
	values := DefaultHelmValues()
	values.Ingress = IngressConfig{
		Enabled:   true,
		ClassName: "nginx",
		Annotations: map[string]string{
			"cert-manager.io/cluster-issuer": "letsencrypt",
		},
		Hosts: []IngressHost{
			{
				Host: "agentsh.example.com",
				Paths: []IngressPath{
					{
						Path:     "/",
						PathType: "Prefix",
					},
				},
			},
		},
		TLS: []IngressTLS{
			{
				SecretName: "agentsh-tls",
				Hosts:      []string{"agentsh.example.com"},
			},
		},
	}

	data, err := yaml.Marshal(values.Ingress)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "enabled: true") {
		t.Error("should contain enabled: true")
	}

	if !strings.Contains(content, "className: nginx") {
		t.Error("should contain className")
	}

	if !strings.Contains(content, "agentsh.example.com") {
		t.Error("should contain host")
	}
}

func TestHelmValues_Affinity(t *testing.T) {
	values := DefaultHelmValues()
	values.Affinity = &Affinity{
		NodeAffinity: &NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &NodeSelector{
				NodeSelectorTerms: []NodeSelectorTerm{
					{
						MatchExpressions: []MatchExpression{
							{
								Key:      "kubernetes.io/arch",
								Operator: "In",
								Values:   []string{"amd64", "arm64"},
							},
						},
					},
				},
			},
		},
	}

	data, err := yaml.Marshal(values.Affinity)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "nodeAffinity") {
		t.Error("should contain nodeAffinity")
	}

	if !strings.Contains(content, "kubernetes.io/arch") {
		t.Error("should contain arch key")
	}
}

func TestTemplateConstants(t *testing.T) {
	// Verify template constants are non-empty
	if deploymentTemplate == "" {
		t.Error("deploymentTemplate should not be empty")
	}

	if serviceTemplate == "" {
		t.Error("serviceTemplate should not be empty")
	}

	if configMapTemplate == "" {
		t.Error("configMapTemplate should not be empty")
	}

	if serviceAccountTemplate == "" {
		t.Error("serviceAccountTemplate should not be empty")
	}

	if rbacTemplate == "" {
		t.Error("rbacTemplate should not be empty")
	}

	if serviceMonitorTemplate == "" {
		t.Error("serviceMonitorTemplate should not be empty")
	}

	if helpersTemplate == "" {
		t.Error("helpersTemplate should not be empty")
	}

	if crdTemplate == "" {
		t.Error("crdTemplate should not be empty")
	}
}

func TestDeploymentTemplate_Content(t *testing.T) {
	if !strings.Contains(deploymentTemplate, "apps/v1") {
		t.Error("deployment template should contain apps/v1")
	}

	if !strings.Contains(deploymentTemplate, "kind: Deployment") {
		t.Error("deployment template should contain Deployment kind")
	}

	if !strings.Contains(deploymentTemplate, "livenessProbe") {
		t.Error("deployment template should contain livenessProbe")
	}

	if !strings.Contains(deploymentTemplate, "readinessProbe") {
		t.Error("deployment template should contain readinessProbe")
	}
}

func TestServiceTemplate_Content(t *testing.T) {
	if !strings.Contains(serviceTemplate, "v1") {
		t.Error("service template should contain v1")
	}

	if !strings.Contains(serviceTemplate, "kind: Service") {
		t.Error("service template should contain Service kind")
	}

	if !strings.Contains(serviceTemplate, "apiPort") {
		t.Error("service template should reference apiPort")
	}

	if !strings.Contains(serviceTemplate, "metricsPort") {
		t.Error("service template should reference metricsPort")
	}
}

func TestRBACTemplate_Content(t *testing.T) {
	if !strings.Contains(rbacTemplate, "ClusterRole") {
		t.Error("rbac template should contain ClusterRole")
	}

	if !strings.Contains(rbacTemplate, "ClusterRoleBinding") {
		t.Error("rbac template should contain ClusterRoleBinding")
	}

	if !strings.Contains(rbacTemplate, "agentshsessions") {
		t.Error("rbac template should reference agentshsessions")
	}
}

func TestCRDTemplate_Content(t *testing.T) {
	if !strings.Contains(crdTemplate, "CustomResourceDefinition") {
		t.Error("CRD template should contain CustomResourceDefinition")
	}

	if !strings.Contains(crdTemplate, "agentsh.io") {
		t.Error("CRD template should contain group")
	}

	if !strings.Contains(crdTemplate, "Pending") {
		t.Error("CRD template should contain state enum values")
	}

	if !strings.Contains(crdTemplate, "Running") {
		t.Error("CRD template should contain Running state")
	}
}

func TestHelpersTemplate_Content(t *testing.T) {
	if !strings.Contains(helpersTemplate, "agentsh.name") {
		t.Error("helpers template should define agentsh.name")
	}

	if !strings.Contains(helpersTemplate, "agentsh.fullname") {
		t.Error("helpers template should define agentsh.fullname")
	}

	if !strings.Contains(helpersTemplate, "agentsh.labels") {
		t.Error("helpers template should define agentsh.labels")
	}

	if !strings.Contains(helpersTemplate, "agentsh.selectorLabels") {
		t.Error("helpers template should define agentsh.selectorLabels")
	}
}

func TestRenderTemplate(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	tmpl := "ReplicaCount: {{.ReplicaCount}}"
	result, err := chart.RenderTemplate("test", tmpl)
	if err != nil {
		t.Fatalf("RenderTemplate error: %v", err)
	}

	if result != "ReplicaCount: 3" {
		t.Errorf("result = %q, want 'ReplicaCount: 3'", result)
	}
}

func TestRenderTemplate_Invalid(t *testing.T) {
	values := DefaultHelmValues()
	chart := NewHelmChart(values)

	tmpl := "{{.InvalidField}"
	_, err := chart.RenderTemplate("test", tmpl)
	if err == nil {
		t.Error("should error on invalid template")
	}
}

func TestHelmChart_Values(t *testing.T) {
	values := DefaultHelmValues()
	values.ReplicaCount = 10

	chart := NewHelmChart(values)
	retrieved := chart.Values()

	if retrieved.ReplicaCount != 10 {
		t.Errorf("ReplicaCount = %d, want 10", retrieved.ReplicaCount)
	}
}
