package admission

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/yliucherish/k8s-admission-guard/internal/policy"
)

// maxBodyBytes 是请求体上限。apiserver 自己会把对象限制在几 MB 内，
// 这里设一个上限是为了不因为畸形请求把内存吃满——webhook 是同步调用的，
// 它被一个大 body 拖住，等于整个集群的 Pod 创建被拖住。
const maxBodyBytes = 8 << 20

// Config 组装 handler。
type Config struct {
	// Policy 是策略参数。
	Policy policy.Options
	// Logger 为空时丢弃日志（测试用）。
	Logger *slog.Logger
	// Observe 为 true 时只记录、不拒绝（observation-only 模式）。
	//
	// 上线新规则的正确姿势是先 observe 一段时间，看它会拦掉哪些现存工作负载，
	// 再切成强制。直接上强制模式，最常见的结局是某天把监控组件自己拦死，
	// 然后整个集群起不来——因为 webhook 是 fail-closed 的。
	Observe bool
}

// Handler 是 /validate 的实现。
type Handler struct {
	cfg Config
	log *slog.Logger
}

// NewHandler 构造 handler。
func NewHandler(cfg Config) *Handler {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Handler{cfg: cfg, log: log}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}

	var review Review
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "cannot decode AdmissionReview: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.Request == nil || review.Request.UID == "" {
		// 没有 uid 就无法把响应对回请求。apiserver 会把这种现象报成
		// "webhook response was invalid"，排查起来很痛苦，所以在这里直接说清楚。
		http.Error(w, "AdmissionReview.request.uid is required", http.StatusBadRequest)
		return
	}

	resp := h.decide(review.Request)
	out := Review{
		APIVersion: review.APIVersion,
		Kind:       "AdmissionReview",
		Response:   resp,
	}
	if out.APIVersion == "" {
		out.APIVersion = "admission.k8s.io/v1"
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		h.log.Error("encode response failed", "err", err)
	}
}

// decide 是真正的判定入口：从 request 里解出 Pod，跑策略，组装响应。
func (h *Handler) decide(req *Request) *Response {
	// 只审 Pod。webhook 配置可能被扩大到其他资源，那时一律放行，
	// 而不是拿别的对象去解 Pod 结构（解出来是空 Pod，会误判为合规）。
	if req.Kind.Kind != "" && req.Kind.Kind != "Pod" {
		return allow(req.UID)
	}
	// DELETE 没有 object 可审，且删除本身不带来新的逃逸面。
	if strings.EqualFold(req.Operation, "DELETE") {
		return allow(req.UID)
	}
	if len(req.Object) == 0 {
		return allow(req.UID)
	}

	var pod policy.Pod
	if err := json.Unmarshal(req.Object, &pod); err != nil {
		// 解析失败不能放行——那等于"畸形对象自动通过"，是最糟的失败模式。
		return &Response{
			UID:     req.UID,
			Allowed: false,
			Status: &Status{
				Status:  "Failure",
				Message: "cannot decode Pod object: " + err.Error(),
				Reason:  "BadRequest",
				Code:    http.StatusBadRequest,
			},
		}
	}

	// namespace 以 request 字段为准：object 里可能是空的（很多人写清单时省略）。
	if pod.Metadata.Namespace == "" {
		pod.Metadata.Namespace = req.Namespace
	}

	violations := policy.Evaluate(pod, h.cfg.Policy)

	user := ""
	if req.UserInfo != nil {
		user = req.UserInfo.Username
	}

	if len(violations) == 0 {
		h.log.Info("allow",
			"pod", pod.Metadata.Namespace+"/"+podName(pod, req),
			"op", req.Operation, "user", user)
		return allow(req.UID)
	}

	rules := make([]string, 0, len(violations))
	for _, v := range violations {
		rules = append(rules, v.Rule)
	}

	h.log.Warn("deny",
		"pod", pod.Metadata.Namespace+"/"+podName(pod, req),
		"op", req.Operation, "user", user,
		"rules", strings.Join(rules, ","),
		"count", len(violations))

	if h.cfg.Observe {
		// 观察模式：结论仍是 allow，但把违规作为 warning 回传。
		// kubectl 会把这些 warning 打出来，于是"如果开启强制会拦谁"变得可见，
		// 而且不会真的挡住任何工作负载。
		return &Response{
			UID:      req.UID,
			Allowed:  true,
			Warnings: []string{"observe-only, would deny: " + describe(violations)},
		}
	}

	return &Response{
		UID:     req.UID,
		Allowed: false,
		Status: &Status{
			Status: "Failure",
			Message: fmt.Sprintf("denied by k8s-admission-guard (%d violation(s)):\n%s",
				len(violations), describe(violations)),
			Reason: "Forbidden",
			Code:   http.StatusForbidden,
		},
	}
}

func allow(uid string) *Response {
	return &Response{UID: uid, Allowed: true}
}

func podName(pod policy.Pod, req *Request) string {
	if pod.Metadata.Name != "" {
		return pod.Metadata.Name
	}
	if req.Name != "" {
		return req.Name
	}
	return "<unnamed>"
}

// describe 把违规渲染成多行文本。
// 带上 Remedy 是有意的：被拒的人应该一眼知道怎么改，否则他只会来问"为什么不让建"。
func describe(vs []policy.Violation) string {
	var b strings.Builder
	for i, v := range vs {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  - [%s] %s: %s\n    fix: %s", v.Rule, v.Field, v.Message, v.Remediation)
	}
	return b.String()
}
