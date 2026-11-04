package admission

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yliucherish/k8s-admission-guard/internal/policy"
)

func boolPtr(b bool) *bool { return &b }

// post 走一次完整的 HTTP 往返：请求体进、响应体出。
// 不直接调 decide() 是因为要验证的正是编码这一层——uid 有没有回填、
// apiVersion 有没有对齐、status.code 是不是 403，这些只有走完 HTTP 才看得到。
func post(t *testing.T, h *Handler, body string, ct string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func reviewJSON(t *testing.T, kind, operation, uid string, obj any, namespace string) string {
	t.Helper()
	req := map[string]any{
		"uid":       uid,
		"kind":      map[string]string{"group": "", "version": "v1", "kind": kind},
		"operation": operation,
	}
	if namespace != "" {
		req["namespace"] = namespace
	}
	if obj != nil {
		req["object"] = obj
	}
	b, err := json.Marshal(map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request":    req,
	})
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	return string(b)
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) Review {
	t.Helper()
	var out Review
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是合法 JSON: %v\n%s", err, rec.Body.String())
	}
	return out
}

func privilegedPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "evil", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":            "shell",
					"image":           "nginx:1.27",
					"securityContext": map[string]any{"privileged": true},
				},
			},
		},
	}
}

func TestRejectsNonPost(t *testing.T) {
	h := NewHandler(Config{})
	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应返回 405，得到 %d", rec.Code)
	}
}

func TestRejectsWrongContentType(t *testing.T) {
	h := NewHandler(Config{})
	rec := post(t, h, "{}", "text/plain")
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("非 JSON Content-Type 应返回 415，得到 %d", rec.Code)
	}
}

func TestRejectsBrokenJSON(t *testing.T) {
	h := NewHandler(Config{})
	rec := post(t, h, "{not json", "application/json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应返回 400，得到 %d", rec.Code)
	}
}

func TestRejectsMissingUID(t *testing.T) {
	// 没有 uid 就没法把响应对回请求，apiserver 会报
	// "webhook response was invalid" —— 排查时极难定位，所以这里必须显式 400。
	h := NewHandler(Config{})
	body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"operation":"CREATE"}}`
	rec := post(t, h, body, "application/json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 uid 应返回 400，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "uid") {
		t.Fatalf("400 的说明里应点明 uid，得到: %s", rec.Body.String())
	}
}

func TestAllowsNonPodResources(t *testing.T) {
	// webhook 配置一旦被扩大范围，不能拿 Deployment 去解 Pod 结构——
	// 解出来是空 Pod，会被判成"合规"，属于静默放行。
	h := NewHandler(Config{})
	body := reviewJSON(t, "Deployment", "CREATE", "u1", map[string]any{
		"spec": map[string]any{"template": map[string]any{}},
	}, "default")
	rec := post(t, h, body, "application/json")
	out := decode(t, rec)
	if out.Response == nil || !out.Response.Allowed {
		t.Fatalf("非 Pod 资源应放行，得到 %+v", out.Response)
	}
}

func TestAllowsDelete(t *testing.T) {
	h := NewHandler(Config{})
	body := reviewJSON(t, "Pod", "DELETE", "u2", privilegedPod(), "default")
	rec := post(t, h, body, "application/json")
	out := decode(t, rec)
	if !out.Response.Allowed {
		t.Fatalf("DELETE 应放行，得到 %s", out.Response.Status.Message)
	}
}

func TestDeniesPrivilegedWith403(t *testing.T) {
	h := NewHandler(Config{})
	body := reviewJSON(t, "Pod", "CREATE", "u3", privilegedPod(), "default")
	rec := post(t, h, body, "application/json")

	if rec.Code != http.StatusOK {
		// admission 拒绝时的 HTTP 状态码仍是 200，结论在 response.allowed 里。
		// 这里搞错的人不少，所以显式断言。
		t.Fatalf("admission 响应本身应是 200，得到 %d", rec.Code)
	}

	out := decode(t, rec)
	if out.Response == nil {
		t.Fatal("响应缺少 response")
	}
	if out.Response.Allowed {
		t.Fatal("privileged Pod 应被拒绝")
	}
	if out.Response.UID != "u3" {
		t.Fatalf("uid 必须原样回填，得到 %q", out.Response.UID)
	}
	if out.Response.Status == nil {
		t.Fatal("拒绝时必须带 status 说明原因")
	}
	if out.Response.Status.Code != http.StatusForbidden {
		t.Fatalf("status.code 应为 403，得到 %d", out.Response.Status.Code)
	}
	if !strings.Contains(out.Response.Status.Message, policy.RulePrivileged) {
		t.Fatalf("消息里应包含规则名 %s，得到: %s", policy.RulePrivileged, out.Response.Status.Message)
	}
	if !strings.Contains(out.Response.Status.Message, "fix:") {
		t.Fatalf("消息里应包含修复建议，得到: %s", out.Response.Status.Message)
	}
}

func TestMalformedPodIsDeniedNotAllowed(t *testing.T) {
	// 最糟的失败模式是"解析不了就放行"。这里把 spec 塞成数字，强制解析失败。
	h := NewHandler(Config{})
	body := reviewJSON(t, "Pod", "CREATE", "u4", map[string]any{
		"metadata": map[string]any{"name": "broken"},
		"spec":     12345,
	}, "default")
	rec := post(t, h, body, "application/json")

	out := decode(t, rec)
	if out.Response.Allowed {
		t.Fatal("无法解析的对象必须拒绝——解析失败就放行等于给畸形对象开后门")
	}
	if out.Response.Status.Code != http.StatusBadRequest {
		t.Fatalf("应返回 400 类语义，得到 %d", out.Response.Status.Code)
	}
}

func TestAllowsCleanPod(t *testing.T) {
	h := NewHandler(Config{})
	body := reviewJSON(t, "Pod", "CREATE", "u5", map[string]any{
		"metadata": map[string]any{"name": "good", "namespace": "default"},
		"spec": map[string]any{
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 10001},
			"containers": []any{map[string]any{
				"name": "app", "image": "nginx:1.27",
				"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 10001},
			}},
		},
	}, "default")

	out := decode(t, post(t, h, body, "application/json"))
	if !out.Response.Allowed {
		t.Fatalf("合规 Pod 应放行，得到: %s", out.Response.Status.Message)
	}
}

func TestObserveModeAllowsButWarns(t *testing.T) {
	// 观察模式是上线新规则的必经阶段：结论放行，但把"本该拒"的信息
	// 通过 warning 暴露出来，这样能先看清会拦到谁。
	h := NewHandler(Config{Observe: true})
	body := reviewJSON(t, "Pod", "CREATE", "u6", privilegedPod(), "default")
	out := decode(t, post(t, h, body, "application/json"))

	if !out.Response.Allowed {
		t.Fatal("观察模式下应放行")
	}
	if len(out.Response.Warnings) == 0 {
		t.Fatal("观察模式下必须给出 warning，否则等于什么都没做")
	}
	if !strings.Contains(strings.Join(out.Response.Warnings, " "), policy.RulePrivileged) {
		t.Fatalf("warning 应点明会命中哪条规则，得到: %v", out.Response.Warnings)
	}
}

func TestNamespaceFallsBackToRequest(t *testing.T) {
	// 很多人写清单时不写 metadata.namespace，靠 kubectl -n 或上下文决定。
	// 若只看 object 里的 namespace，豁免就会失效——该豁免的没豁免。
	pod := privilegedPod()
	// 显式去掉 metadata.namespace，才能真的走到回退分支。
	pod["metadata"] = map[string]any{"name": "evil"}

	h := NewHandler(Config{Policy: policy.Options{ExemptNamespaces: []string{"kube-system"}}})
	body := reviewJSON(t, "Pod", "CREATE", "u7", pod, "kube-system")
	out := decode(t, post(t, h, body, "application/json"))

	if !out.Response.Allowed {
		t.Fatalf("object 未写 namespace 时应回退到 request.namespace 并命中豁免，得到: %s",
			out.Response.Status.Message)
	}
}

func TestResponseEchoesAPIVersion(t *testing.T) {
	// 响应的 apiVersion 必须与请求一致，否则 apiserver 直接丢弃。
	h := NewHandler(Config{})
	body := reviewJSON(t, "Pod", "CREATE", "u8", privilegedPod(), "default")
	out := decode(t, post(t, h, body, "application/json"))
	if out.APIVersion != "admission.k8s.io/v1" {
		t.Fatalf("apiVersion 应回填为 admission.k8s.io/v1，得到 %q", out.APIVersion)
	}
	if out.Kind != "AdmissionReview" {
		t.Fatalf("kind 应为 AdmissionReview，得到 %q", out.Kind)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	// webhook 是同步调用，一个大 body 会占住 apiserver 的 worker。
	// 这里只验证不会因此 panic 或挂死，具体状态码允许 400。
	h := NewHandler(Config{})
	huge := strings.Repeat("a", maxBodyBytes+1024)
	body := fmt.Sprintf(`{"apiVersion":"admission.k8s.io/v1","request":{"uid":"u9","object":"%s"}}`, huge)
	rec := post(t, h, body, "application/json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超大/畸形 body 应返回 400，得到 %d", rec.Code)
	}
}
