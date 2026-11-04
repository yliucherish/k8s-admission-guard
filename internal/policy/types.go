// 本文件只放 Pod 的最小结构定义。
//
// 为什么不用 k8s.io/api：完整的 API 类型会把 30+ 个包拉进来（编译后的模块缓存
// 上百 MB），而我们真正读的字段只有十来个。更重要的是——**零依赖意味着任何人
// 拿到仓库就能 go build，不需要联网拉模块**。这在演示、审计、离线环境里都是
// 实打实的好处。
//
// 代价是字段要手写，且必须和 apiserver 发过来的 JSON 对齐。所有字段都按
// Kubernetes 的 JSON tag 命名，未知字段被 encoding/json 静默忽略（这也是我们想要的：
// 上游加字段不应该让 webhook 崩掉）。
package policy

// ObjectMeta 只取策略用得到的部分。
type ObjectMeta struct {
	Name        string            `json:"name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SecurityContext 合并了 Pod 级与容器级的字段。
//
// 全部用指针是必要的：nil 表示「未声明」，而 false/0 表示「明确声明为 false/0」。
// 用值类型会把这两种情况糊在一起，strict 模式就无从判断。
type SecurityContext struct {
	Privileged   *bool  `json:"privileged,omitempty"`
	RunAsUser    *int64 `json:"runAsUser,omitempty"`
	RunAsNonRoot *bool  `json:"runAsNonRoot,omitempty"`
	RunAsGroup   *int64 `json:"runAsGroup,omitempty"`
}

// Container 覆盖 containers / initContainers / ephemeralContainers 三者共有的字段。
type Container struct {
	Name            string           `json:"name,omitempty"`
	Image           string           `json:"image,omitempty"`
	SecurityContext *SecurityContext `json:"securityContext,omitempty"`
	VolumeMounts    []VolumeMount    `json:"volumeMounts,omitempty"`
}

// VolumeMount 目前只用于将来把违规定位到具体挂载点，判定仍以卷为准。
type VolumeMount struct {
	Name      string `json:"name,omitempty"`
	MountPath string `json:"mountPath,omitempty"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// Volume 只关心 hostPath，其余卷类型对判定无影响。
type Volume struct {
	Name     string                `json:"name,omitempty"`
	HostPath *HostPathVolumeSource `json:"hostPath,omitempty"`
}

// HostPathVolumeSource 的 Type 字段（""/"Directory"/"Socket" 等）暂不参与判定，
// 留作以后区分「只读文件挂载」与「整目录挂载」。
type HostPathVolumeSource struct {
	Path string  `json:"path"`
	Type *string `json:"type,omitempty"`
}

// PodSpec 只取与容器逃逸/提权相关的字段。
type PodSpec struct {
	Containers          []Container      `json:"containers,omitempty"`
	InitContainers      []Container      `json:"initContainers,omitempty"`
	EphemeralContainers []Container      `json:"ephemeralContainers,omitempty"`
	Volumes             []Volume         `json:"volumes,omitempty"`
	SecurityContext     *SecurityContext `json:"securityContext,omitempty"`

	// 下面三个对「逃逸」的严重程度有影响，但本工具的规则集不直接拦它们
	// （PodSecurity baseline 已经拦了 hostNetwork/hostPID/hostIPC）。
	// 留着是为了将来做统计与告警分级。
	HostNetwork bool `json:"hostNetwork,omitempty"`
	HostPID     bool `json:"hostPID,omitempty"`
	HostIPC     bool `json:"hostIPC,omitempty"`
}

// Pod 是最小 Pod 定义。
type Pod struct {
	APIVersion string     `json:"apiVersion,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       PodSpec    `json:"spec"`
}
