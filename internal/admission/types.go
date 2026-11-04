// Package admission 实现 Validating Admission Webhook 的 HTTP 层。
//
// AdmissionReview 的官方类型在 k8s.io/api/admission/v1 里，同样出于零依赖的
// 考虑（见 internal/policy/types.go 的说明）这里只声明实际用到的字段。
// 这些字段名与版本由 apiserver 决定，写错的表现是「webhook 收到请求但解析出
// 空 uid」——所以 handler 对 uid 缺失会直接返回 400，而不是硬着头皮放行。
package admission

import "encoding/json"

// GroupVersionKind 与 GroupVersionResource 是 admission 请求里的类型标识。
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// GroupVersionResource 用于标明请求的资源复数名。
type GroupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// Request 是 apiserver 发过来的待审对象。
type Request struct {
	UID             string                `json:"uid"`
	Kind            GroupVersionKind      `json:"kind"`
	Resource        GroupVersionResource  `json:"resource"`
	SubResource     string                `json:"subResource,omitempty"`
	RequestKind     *GroupVersionKind     `json:"requestKind,omitempty"`
	RequestResource *GroupVersionResource `json:"requestResource,omitempty"`
	Operation       string                `json:"operation"`
	Namespace       string                `json:"namespace,omitempty"`
	Name            string                `json:"name,omitempty"`
	Object          json.RawMessage       `json:"object,omitempty"`
	OldObject       json.RawMessage       `json:"oldObject,omitempty"`
	DryRun          *bool                 `json:"dryRun,omitempty"`
	UserInfo        *UserInfo             `json:"userInfo,omitempty"`
}

// UserInfo 记录是谁发起的请求，用来在审计日志里区分「人」和「控制器」。
type UserInfo struct {
	Username string   `json:"username,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Status 是拒绝原因的载体。Code 用 403 是约定俗成的做法（Forbidden），
// kubectl 会把它渲染成 "Error from server (Forbidden): ..."。
type Status struct {
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Code    int32  `json:"code,omitempty"`
}

// Response 是我们要回给 apiserver 的结论。
type Response struct {
	UID              string            `json:"uid"`
	Allowed          bool              `json:"allowed"`
	Status           *Status           `json:"status,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	PatchType        *string           `json:"patchType,omitempty"`
	Patch            []byte            `json:"patch,omitempty"`
	AuditAnnotations map[string]string `json:"auditAnnotations,omitempty"`
}

// Review 是请求与响应共用的信封。
type Review struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Request    *Request  `json:"request,omitempty"`
	Response   *Response `json:"response,omitempty"`
}
