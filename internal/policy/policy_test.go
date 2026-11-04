package policy

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

func podWith(name string, spec PodSpec) Pod {
	return Pod{Metadata: ObjectMeta{Name: name, Namespace: "default"}, Spec: spec}
}

// rulesOf 把违规列表压成规则名集合，方便断言"命中了哪几条"。
func rulesOf(vs []Violation) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vs {
		if !seen[v.Rule] {
			seen[v.Rule] = true
			out = append(out, v.Rule)
		}
	}
	return out
}

func hasRule(vs []Violation, rule string) bool {
	for _, v := range vs {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func TestPrivilegedAcrossContainerKinds(t *testing.T) {
	// 这条测试的意义：只查 spec.containers 的 webhook 是最常见的漏洞形态。
	// 把 privileged 挪进 initContainer 或 ephemeralContainer，攻击效果一样，
	// 但简陋的实现会放行。
	cases := []struct {
		name string
		spec PodSpec
	}{
		{
			name: "containers",
			spec: PodSpec{Containers: []Container{{
				Name: "c", Image: "nginx:1.27",
				SecurityContext: &SecurityContext{Privileged: boolPtr(true)},
			}}},
		},
		{
			name: "initContainers",
			spec: PodSpec{
				InitContainers: []Container{{
					Name: "i", Image: "nginx:1.27",
					SecurityContext: &SecurityContext{Privileged: boolPtr(true)},
				}},
				Containers: []Container{{Name: "c", Image: "nginx:1.27"}},
			},
		},
		{
			name: "ephemeralContainers",
			spec: PodSpec{
				EphemeralContainers: []Container{{
					Name: "e", Image: "nginx:1.27",
					SecurityContext: &SecurityContext{Privileged: boolPtr(true)},
				}},
				Containers: []Container{{Name: "c", Image: "nginx:1.27"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(podWith("p", tc.spec), Options{})
			if !hasRule(got, RulePrivileged) {
				t.Fatalf("%s 里的 privileged 没有被检出，违规: %v", tc.name, got)
			}
		})
	}
}

func TestPrivilegedFalseIsClean(t *testing.T) {
	p := podWith("p", PodSpec{Containers: []Container{{
		Name: "c", Image: "nginx:1.27",
		SecurityContext: &SecurityContext{Privileged: boolPtr(false)},
	}}})
	if got := Evaluate(p, Options{}); len(got) != 0 {
		t.Fatalf("privileged: false 不应违规，得到 %v", got)
	}
}

func TestRunAsRootPrecedence(t *testing.T) {
	// 容器级 securityContext 覆盖 Pod 级，写反了会出现两类错误：
	// 漏放（Pod 写 1000、容器写 0）和误拦（Pod 写 0、容器写 1000）。
	cases := []struct {
		name     string
		podSC    *SecurityContext
		ctrSC    *SecurityContext
		wantDeny bool
	}{
		{
			name:     "pod nonroot, container overrides to uid 0",
			podSC:    &SecurityContext{RunAsNonRoot: boolPtr(true)},
			ctrSC:    &SecurityContext{RunAsUser: int64Ptr(0)},
			wantDeny: true,
		},
		{
			name:     "pod uid 0, container overrides to 10001",
			podSC:    &SecurityContext{RunAsUser: int64Ptr(0)},
			ctrSC:    &SecurityContext{RunAsUser: int64Ptr(10001)},
			wantDeny: false,
		},
		{
			name:     "pod uid 0 only",
			podSC:    &SecurityContext{RunAsUser: int64Ptr(0)},
			wantDeny: true,
		},
		{
			name:     "runAsNonRoot false",
			ctrSC:    &SecurityContext{RunAsNonRoot: boolPtr(false)},
			wantDeny: true,
		},
		{
			name:     "nothing declared, default mode",
			wantDeny: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := podWith("p", PodSpec{
				SecurityContext: tc.podSC,
				Containers:      []Container{{Name: "c", Image: "nginx:1.27", SecurityContext: tc.ctrSC}},
			})
			got := Evaluate(p, Options{})
			if hasRule(got, RuleRunAsRoot) != tc.wantDeny {
				t.Fatalf("wantDeny=%v，实际违规: %v", tc.wantDeny, rulesOf(got))
			}
		})
	}
}

func TestStrictModeFlagsUndeclared(t *testing.T) {
	// 这是本工具最核心的取舍：默认容忍"没声明"，strict 才拦。
	// 两种模式必须都测，否则改默认识别不出来。
	p := podWith("p", PodSpec{Containers: []Container{{Name: "c", Image: "nginx:1.27"}}})

	if got := Evaluate(p, Options{}); hasRule(got, RuleRunAsRoot) {
		t.Fatalf("默认模式不应因未声明而拒绝，得到 %v", rulesOf(got))
	}
	if got := Evaluate(p, Options{Strict: true}); !hasRule(got, RuleRunAsRoot) {
		t.Fatalf("strict 模式应拒绝未声明 runAsNonRoot 的容器，得到 %v", rulesOf(got))
	}

	// 显式声明之后，strict 模式必须放行——否则说明"容忍"逻辑写死了。
	ok := podWith("p", PodSpec{Containers: []Container{{
		Name: "c", Image: "nginx:1.27",
		SecurityContext: &SecurityContext{RunAsNonRoot: boolPtr(true)},
	}}})
	if got := Evaluate(ok, Options{Strict: true}); len(got) != 0 {
		t.Fatalf("显式声明 runAsNonRoot 后 strict 模式应放行，得到 %v", got)
	}
}

func TestHostPathDetection(t *testing.T) {
	cases := []struct {
		name     string
		volume   Volume
		wantDeny bool
	}{
		{
			name:     "docker socket",
			volume:   Volume{Name: "s", HostPath: &HostPathVolumeSource{Path: "/var/run/docker.sock"}},
			wantDeny: true,
		},
		{
			name:     "whole etc",
			volume:   Volume{Name: "e", HostPath: &HostPathVolumeSource{Path: "/etc"}},
			wantDeny: true,
		},
		{
			name:     "trailing slash normalizes",
			volume:   Volume{Name: "r", HostPath: &HostPathVolumeSource{Path: "/root/"}},
			wantDeny: true,
		},
		{
			name:     "emptyDir is not hostPath",
			volume:   Volume{Name: "d"},
			wantDeny: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := podWith("p", PodSpec{
				Volumes:    []Volume{tc.volume},
				Containers: []Container{{Name: "c", Image: "nginx:1.27"}},
			})
			got := Evaluate(p, Options{})
			if hasRule(got, RuleHostPath) != tc.wantDeny {
				t.Fatalf("wantDeny=%v，实际违规: %v", tc.wantDeny, rulesOf(got))
			}
		})
	}
}

func TestSensitiveHostPathIsHighlighted(t *testing.T) {
	// 「挂了个 hostPath」和「挂了 docker.sock」严重程度差一个数量级，
	// 消息里必须区分，否则看告警的人分不出轻重。
	p := podWith("p", PodSpec{
		Volumes: []Volume{
			{Name: "a", HostPath: &HostPathVolumeSource{Path: "/var/run/docker.sock"}},
		},
		Containers: []Container{{Name: "c", Image: "nginx:1.27"}},
	})
	got := Evaluate(p, Options{})
	if len(got) != 1 {
		t.Fatalf("期望 1 条违规，得到 %v", got)
	}
	if !strings.Contains(got[0].Message, "高危") {
		t.Fatalf("docker.sock 应被标记为高危，消息是: %s", got[0].Message)
	}
}

func TestImageRegistryAllowlist(t *testing.T) {
	allowed := []string{"docker.io/library", "ghcr.io/yliucherish", "registry.k8s.io"}

	cases := []struct {
		name     string
		image    string
		wantDeny bool
	}{
		{"official short name", "nginx:1.27", false},
		{"official full name", "docker.io/library/redis:7", false},
		{"namespaced on docker hub", "bitnami/redis:7", true},
		{"own ghcr repo", "ghcr.io/yliucherish/demo-app:1.4.2", false},
		{"sibling ghcr repo", "ghcr.io/someone-else/app:1", true},
		{"prefix boundary", "ghcr.io/yliucherish-other/app:1", true},
		{"untrusted registry", "quay.io/unknown/backdoor:1.0", true},
		{"with digest", "ghcr.io/yliucherish/demo-app@sha256:abc123", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := podWith("p", PodSpec{Containers: []Container{{Name: "c", Image: tc.image}}})
			got := Evaluate(p, Options{AllowedRegistries: allowed})
			if hasRule(got, RuleImageRepo) != tc.wantDeny {
				t.Fatalf("image=%q wantDeny=%v，实际: %v", tc.image, tc.wantDeny, rulesOf(got))
			}
		})
	}
}

func TestImageAllowlistEmptyMeansNoCheck(t *testing.T) {
	// 空列表 = 不检查镜像来源。这个语义要显式测，否则以后谁改成
	// "空列表 = 全拒" 会把所有工作负载干死。
	p := podWith("p", PodSpec{Containers: []Container{{Name: "c", Image: "quay.io/x/y:1"}}})
	if got := Evaluate(p, Options{}); hasRule(got, RuleImageRepo) {
		t.Fatalf("白名单为空时不应检查镜像，得到 %v", rulesOf(got))
	}
}

func TestBareHostnameInAllowlist(t *testing.T) {
	// 回归用例。这个 bug 是被 deploy/samples/pods.json 跑出来的，不是单元测试发现的：
	// 白名单写 "registry.k8s.io" 时，早先的实现会把它当 Docker 短名补成
	// "docker.io/library/registry.k8s.io"，导致 registry.k8s.io/busybox 被判违规。
	//
	// 教训：白名单条目是**仓库前缀**，镜像引用才需要补全规则，两者不能共用同一套规范化。
	for _, host := range []string{"registry.k8s.io", "registry.k8s.io/", "GHCR.IO/Yliucherish"} {
		t.Run(host, func(t *testing.T) {
			var image string
			switch host {
			case "GHCR.IO/Yliucherish":
				image = "ghcr.io/yliucherish/app:1"
			default:
				image = "registry.k8s.io/pause:3.9"
			}
			p := podWith("p", PodSpec{Containers: []Container{{Name: "c", Image: image}}})
			got := Evaluate(p, Options{AllowedRegistries: []string{host}})
			if hasRule(got, RuleImageRepo) {
				t.Fatalf("白名单 %q 应放行 %q，得到 %v", host, image, rulesOf(got))
			}
		})
	}
}

func TestPrefixMatchBoundary(t *testing.T) {
	// ghcr.io/yliucherish 不能匹配 ghcr.io/yliucherish-other，那是两个仓库。
	if prefixMatch("ghcr.io/yliucherish-other/app", "ghcr.io/yliucherish") {
		t.Fatal("前缀匹配越过了路径边界")
	}
	if !prefixMatch("ghcr.io/yliucherish/app", "ghcr.io/yliucherish/") {
		t.Fatal("带尾部斜杠的白名单条目应能匹配")
	}
	if prefixMatch("anything", "") {
		t.Fatal("空前缀不应匹配任何东西")
	}
}

func TestNormalizeImage(t *testing.T) {
	cases := map[string]string{
		"nginx":                           "docker.io/library/nginx",
		"nginx:1.27":                      "docker.io/library/nginx",
		"library/nginx":                   "docker.io/library/nginx",
		"bitnami/redis:7":                 "docker.io/bitnami/redis",
		"ghcr.io/foo/bar:1.2":             "ghcr.io/foo/bar",
		"localhost:5000/app":              "localhost:5000/app",
		"localhost:5000/app:v1":           "localhost:5000/app",
		"ghcr.io/Foo/Bar:v1":              "ghcr.io/foo/bar",
		"ghcr.io/foo/bar@sha256:deadbeef": "ghcr.io/foo/bar",
		"registry.k8s.io/pause:3.9":       "registry.k8s.io/pause",
		"":                                "",
	}
	for in, want := range cases {
		if got := NormalizeImage(in); got != want {
			t.Errorf("NormalizeImage(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

func TestExemptions(t *testing.T) {
	priv := PodSpec{Containers: []Container{{
		Name: "c", Image: "nginx:1.27",
		SecurityContext: &SecurityContext{Privileged: boolPtr(true)},
	}}}

	t.Run("namespace", func(t *testing.T) {
		p := podWith("p", priv)
		p.Metadata.Namespace = "kube-system"
		got := Evaluate(p, Options{ExemptNamespaces: []string{"kube-system"}})
		if len(got) != 0 {
			t.Fatalf("豁免命名空间应放行，得到 %v", rulesOf(got))
		}
	})

	t.Run("annotation true", func(t *testing.T) {
		p := podWith("p", priv)
		p.Metadata.Annotations = map[string]string{"guard/exempt": "true"}
		got := Evaluate(p, Options{ExemptAnnotation: "guard/exempt"})
		if len(got) != 0 {
			t.Fatalf("豁免注解应放行，得到 %v", rulesOf(got))
		}
	})

	t.Run("annotation other value does not exempt", func(t *testing.T) {
		// 只认字面 "true"。写 "yes"/"1" 不生效是有意的：
		// 宽松比较会让 "false" 也被当成真。
		p := podWith("p", priv)
		p.Metadata.Annotations = map[string]string{"guard/exempt": "yes"}
		got := Evaluate(p, Options{ExemptAnnotation: "guard/exempt"})
		if !hasRule(got, RulePrivileged) {
			t.Fatalf("注解值不是 true 时不应豁免，得到 %v", rulesOf(got))
		}
	})

	t.Run("annotation nil map does not panic", func(t *testing.T) {
		p := podWith("p", priv)
		_ = Evaluate(p, Options{ExemptAnnotation: "guard/exempt"})
	})
}

func TestMultipleViolationsAllReported(t *testing.T) {
	// 一次拒只报一条是糟糕的体验：改完 privileged 再被 hostPath 拒，
	// 再改再被 root 拒，来回三轮。要一次说全。
	p := podWith("p", PodSpec{
		Volumes: []Volume{{Name: "s", HostPath: &HostPathVolumeSource{Path: "/var/run/docker.sock"}}},
		Containers: []Container{{
			Name: "c", Image: "quay.io/x/y:1",
			SecurityContext: &SecurityContext{Privileged: boolPtr(true), RunAsUser: int64Ptr(0)},
		}},
	})
	got := Evaluate(p, Options{AllowedRegistries: []string{"docker.io/library"}})

	for _, want := range []string{RulePrivileged, RuleHostPath, RuleRunAsRoot, RuleImageRepo} {
		if !hasRule(got, want) {
			t.Errorf("应同时报出 %s，实际只有 %v", want, rulesOf(got))
		}
	}
}

func TestEveryViolationHasRemediation(t *testing.T) {
	// 没有修法的拒绝消息只会把人赶去翻文档。这是可用性约束，不是洁癖。
	p := podWith("p", PodSpec{
		Volumes: []Volume{{Name: "s", HostPath: &HostPathVolumeSource{Path: "/etc"}}},
		Containers: []Container{{
			Name: "c", Image: "quay.io/x/y:1",
			SecurityContext: &SecurityContext{Privileged: boolPtr(true), RunAsUser: int64Ptr(0)},
		}},
	})
	for _, v := range Evaluate(p, Options{AllowedRegistries: []string{"docker.io/library"}}) {
		if v.Remediation == "" {
			t.Errorf("规则 %s 的违规没有给出修复建议", v.Rule)
		}
		if v.Field == "" {
			t.Errorf("规则 %s 的违规没有字段路径", v.Rule)
		}
	}
}
