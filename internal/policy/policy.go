// Package policy 实现 Pod 准入策略判定。
//
// 分层原则：这一层是**纯函数**——输入 Pod 结构、输出违规列表，不碰网络、不写日志、
// 不做重试。好处是每条规则的边界都能用表驱动测试钉死，而 admission 那层只管
// HTTP 与 JSON。一个 webhook 如果策略逻辑和 IO 混在一起，就没法证明"它拒的是
// 该拒的、不是碰巧拒了"。
package policy

import (
	"fmt"
	"strings"
)

// Options 是策略开关。零值可用：不严格、不查镜像来源、不豁免任何命名空间。
type Options struct {
	// Strict 为 true 时，"没声明 runAsNonRoot 也没声明 runAsUser"也算违规。
	//
	// 这是本工具最重要的一处取舍。Kubernetes 的默认行为是「以镜像里的 USER 运行」，
	// 而绝大多数镜像的 USER 是 root。严格要求显式声明才安全，但会拦掉大量
	// 没有安全意识的正常工作负载（Helm chart、教程、CI 里随手写的 Pod）。
	// 所以默认只拦「明确要求 root」的，把「没声明」留给 -strict 模式。
	Strict bool

	// AllowedRegistries 是镜像仓库白名单，前缀匹配。为空表示不检查镜像来源。
	//
	// 这条规则是 PodSecurity Admission 做不到的：PSA 只管 privileges、能力、
	// hostPath 这些运行时属性，完全不看镜像从哪来。企业里「只能拉公司仓库和
	// 官方基础镜像」是很硬的需求。
	AllowedRegistries []string

	// ExemptNamespaces 里的命名空间整体放行。
	ExemptNamespaces []string

	// ExemptAnnotation 是豁免注解的键，值恰为 "true" 时放行。
	ExemptAnnotation string
}

// Violation 是一条违规。
type Violation struct {
	Rule        string // 稳定的规则标识，可用来做统计与告警聚合
	Field       string // 违规字段路径，方便直接在 YAML 里定位
	Message     string // 给人看的一句话
	Remediation string // 怎么改
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Rule, v.Field, v.Message)
}

// 规则标识。写成常量而不是散落的字符串，是为了测试能按名字断言，
// 也让以后的告警聚合有稳定键。
const (
	RulePrivileged = "privileged-container"
	RuleHostPath   = "hostpath-mount"
	RuleRunAsRoot  = "run-as-root"
	RuleImageRepo  = "untrusted-image-registry"
)

// 视为容器逃逸入口的高危宿主机路径。命中时在消息里额外提示，
// 因为「挂了个 hostPath」和「挂了 docker.sock」的严重程度差一个数量级。
var sensitiveHostPaths = []string{
	"/var/run/docker.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
	"/var/lib/kubelet",
	"/etc/kubernetes",
	"/root",
}

// Evaluate 判定一个 Pod，返回全部违规。空切片表示放行。
//
// 注意它检查三类容器：containers、initContainers、ephemeralContainers。
// 只查 containers 是这类 webhook 最常见的漏洞——攻击者把 privileged 写在
// initContainer 里就绕过去了，而 initContainer 同样跑在节点上。
func Evaluate(pod Pod, opt Options) []Violation {
	if opt.isExempt(pod) {
		return nil
	}

	var out []Violation

	groups := []struct {
		field string
		list  []Container
	}{
		{"containers", pod.Spec.Containers},
		{"initContainers", pod.Spec.InitContainers},
		{"ephemeralContainers", pod.Spec.EphemeralContainers},
	}

	for _, g := range groups {
		for i, c := range g.list {
			path := fmt.Sprintf("spec.%s[%d]", g.field, i)
			name := c.Name
			if name == "" {
				name = path
			}

			// 1) 特权容器：直接等于拿到节点 root。
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				out = append(out, Violation{
					Rule:        RulePrivileged,
					Field:       path + ".securityContext.privileged",
					Message:     fmt.Sprintf("容器 %q 声明了 privileged: true，等同宿主 root", name),
					Remediation: "去掉 privileged，改为按需 add 单个 capability（如 NET_BIND_SERVICE）",
				})
			}

			// 2) 以 root 身份运行。
			if v := checkRunAsRoot(pod, c, path, name, opt.Strict); v != nil {
				out = append(out, *v)
			}

			// 3) 镜像来源。
			if v := checkImage(c, path, name, opt.AllowedRegistries); v != nil {
				out = append(out, *v)
			}
		}
	}

	// 4) hostPath 挂载。放在卷层面查，因为一个卷可能被多个容器挂。
	for i, vol := range pod.Spec.Volumes {
		if vol.HostPath == nil {
			continue
		}
		path := fmt.Sprintf("spec.volumes[%d].hostPath", i)
		msg := fmt.Sprintf("卷 %q 挂载了宿主机路径 %q", vol.Name, vol.HostPath.Path)
		if hit := matchSensitivePath(vol.HostPath.Path); hit != "" {
			msg += fmt.Sprintf("（高危：%s，容器逃逸经典入口）", hit)
		}
		out = append(out, Violation{
			Rule:        RuleHostPath,
			Field:       path,
			Message:     msg,
			Remediation: "改用 emptyDir / configMap / secret / PVC；确需宿主机文件时用只读的 hostPath 并限定到具体文件",
		})
	}

	return out
}

// checkRunAsRoot 处理 runAsUser / runAsNonRoot 的容器级覆盖 Pod 级语义。
//
// 优先级：container.securityContext 覆盖 pod.securityContext。写错这个优先级
// 会让「Pod 级声明 runAsNonRoot: true、容器级写 runAsUser: 0」这种组合漏过去。
func checkRunAsRoot(pod Pod, c Container, path, name string, strict bool) *Violation {
	uid, uidSet := effectiveRunAsUser(pod, c)
	nonRoot, nonRootSet := effectiveRunAsNonRoot(pod, c)

	if uidSet && uid == 0 {
		return &Violation{
			Rule:        RuleRunAsRoot,
			Field:       path + ".securityContext.runAsUser",
			Message:     fmt.Sprintf("容器 %q 以 UID 0 运行", name),
			Remediation: "设 runAsNonRoot: true 并指定非 0 的 runAsUser（如 10001）",
		}
	}
	if nonRootSet && !nonRoot {
		return &Violation{
			Rule:        RuleRunAsRoot,
			Field:       path + ".securityContext.runAsNonRoot",
			Message:     fmt.Sprintf("容器 %q 显式声明 runAsNonRoot: false", name),
			Remediation: "改为 runAsNonRoot: true",
		}
	}
	if strict && !uidSet && !nonRootSet {
		return &Violation{
			Rule:        RuleRunAsRoot,
			Field:       path + ".securityContext",
			Message:     fmt.Sprintf("容器 %q 未声明 runAsNonRoot，将继承镜像 USER（多数镜像为 root）", name),
			Remediation: "显式声明 runAsNonRoot: true —— strict 模式下不接受「默认」",
		}
	}
	return nil
}

func effectiveRunAsUser(pod Pod, c Container) (int64, bool) {
	if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
		return *c.SecurityContext.RunAsUser, true
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil {
		return *pod.Spec.SecurityContext.RunAsUser, true
	}
	return 0, false
}

func effectiveRunAsNonRoot(pod Pod, c Container) (bool, bool) {
	if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		return *c.SecurityContext.RunAsNonRoot, true
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return *pod.Spec.SecurityContext.RunAsNonRoot, true
	}
	return false, false
}

func checkImage(c Container, path, name string, allowed []string) *Violation {
	if len(allowed) == 0 {
		return nil
	}
	if c.Image == "" {
		return &Violation{
			Rule:        RuleImageRepo,
			Field:       path + ".image",
			Message:     fmt.Sprintf("容器 %q 没有指定镜像", name),
			Remediation: "指定完整镜像引用",
		}
	}
	got := NormalizeImage(c.Image)
	for _, a := range allowed {
		// 这里只能做「前缀规范化」，不能套 NormalizeImage。
		//
		// 踩过的坑：白名单写 "registry.k8s.io" 时，NormalizeImage 会把它当成
		// Docker 短名，补成 "docker.io/library/registry.k8s.io"，于是
		// registry.k8s.io/busybox 反而被判为不在白名单里。
		// 原因很简单——白名单条目是**仓库前缀**，不是镜像引用，两者的规范化规则不同。
		if prefixMatch(got, normalizePrefix(a)) {
			return nil
		}
	}
	return &Violation{
		Rule:        RuleImageRepo,
		Field:       path + ".image",
		Message:     fmt.Sprintf("容器 %q 的镜像 %q（规范化为 %q）不在允许的仓库列表内", name, c.Image, got),
		Remediation: "改用白名单仓库的镜像：" + strings.Join(allowed, ", "),
	}
}

// NormalizeImage 把**镜像引用**规范成「仓库/路径」形式，去掉 tag 与 digest。
//
// Docker 的短名规则是真实存在的坑，不做这一步白名单就永远对不上：
//
//	nginx                  → docker.io/library/nginx
//	bitnami/redis          → docker.io/bitnami/redis
//	ghcr.io/foo/bar:1.2    → ghcr.io/foo/bar
//	localhost:5000/app     → localhost:5000/app   （冒号是端口不是 tag）
//
// 注意：**不要用它处理白名单条目**。白名单写的是仓库前缀（可能是裸主机名
// 如 registry.k8s.io），套上这套规则会被当成 Docker 短名补全。用 normalizePrefix。
func NormalizeImage(ref string) string {
	// 去 digest
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	// 去 tag：只有出现在最后一个 '/' 之后的冒号才是 tag
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	ref = strings.ToLower(ref)
	if ref == "" {
		return ""
	}

	first := ref
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		first = ref[:i]
	} else {
		// 单段名 = 官方镜像
		return "docker.io/library/" + ref
	}
	// 第一段带 '.' 或 ':'，或就是 localhost，说明显式写了仓库地址
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return ref
	}
	return "docker.io/" + ref
}

// normalizePrefix 只做白名单条目该做的规范化：小写、去掉首尾斜杠。
// 不补 docker.io、不解析 tag —— 前缀不是镜像引用。
func normalizePrefix(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "/"))
}

// prefixMatch 按路径边界做前缀匹配。
// 不能让白名单 "ghcr.io/foo" 匹配到 "ghcr.io/foobar"——那是两个不同的仓库。
func prefixMatch(s, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return false
	}
	return s == prefix || strings.HasPrefix(s, prefix+"/")
}

func matchSensitivePath(p string) string {
	clean := strings.TrimSuffix(p, "/")
	for _, s := range sensitiveHostPaths {
		if clean == s || strings.HasPrefix(clean, s+"/") {
			return s
		}
	}
	return ""
}

func (o Options) isExempt(pod Pod) bool {
	for _, ns := range o.ExemptNamespaces {
		if ns != "" && pod.Metadata.Namespace == ns {
			return true
		}
	}
	if o.ExemptAnnotation != "" {
		if v, ok := pod.Metadata.Annotations[o.ExemptAnnotation]; ok && v == "true" {
			return true
		}
	}
	return false
}
