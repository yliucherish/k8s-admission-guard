// cmd/checkpod 是无集群也能跑的准入判定器。
//
// 它把样例清单包装成真实的 AdmissionReview 请求，灌进**与线上完全相同**的
// handler（internal/admission），再把结论和预期比对。也就是说它验证的不是
// 「策略函数算得对」，而是「整条 JSON 解码 → 策略 → 响应编码」链路。
//
// 用法：
//
//	go run ./cmd/checkpod -samples deploy/samples/pods.json
//	go run ./cmd/checkpod -samples deploy/samples/pods.json -strict
//
// 退出码 0 表示全部符合预期，1 表示有不符合。
//
// 它**不能**代替集群验证：证书、Service、ValidatingWebhookConfiguration 的
// CA bundle、failurePolicy 这些只有真集群才验得到。两者是互补关系，
// 别用这个脚本冒充"我在 K8s 上跑通了"。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/yliucherish/k8s-admission-guard/internal/admission"
	"github.com/yliucherish/k8s-admission-guard/internal/policy"
)

// sample 是样例文件里的一项。
type sample struct {
	Name string `json:"name"`
	// Expect 取 "deny" 或 "allow"。
	Expect string `json:"expect"`
	// WantRules 是期望命中的规则标识（仅 Expect=deny 时有意义）。
	WantRules []string `json:"wantRules,omitempty"`
	// Operation 留空默认 CREATE。
	Operation string          `json:"operation,omitempty"`
	Pod       json.RawMessage `json:"pod"`

	// ExpectStrict / WantRulesStrict 是 -strict 模式下的另一套预期。
	//
	// 为什么需要两套：同一条清单在不同模式下结论本就不同——「没声明 runAsNonRoot」
	// 在默认模式放行、在 strict 模式拒绝，这正是本工具最核心的取舍。
	// 用一个静态预期去套两种模式，只会让人把其中一个模式跑成"失败"，
	// 然后误以为代码有问题。
	ExpectStrict    string   `json:"expectStrict,omitempty"`
	WantRulesStrict []string `json:"wantRulesStrict,omitempty"`
}

func main() {
	var (
		samplesPath = flag.String("samples", "deploy/samples/pods.json", "样例清单路径")
		strict      = flag.Bool("strict", false, "strict 模式")
		registries  = flag.String("allowed-registries", "docker.io/library,ghcr.io/yliucherish,registry.k8s.io", "镜像仓库白名单")
		exemptNS    = flag.String("exempt-namespaces", "kube-system", "豁免命名空间")
		observe     = flag.Bool("observe", false, "观察模式（此时所有样例都应为 allow）")
	)
	flag.Parse()

	raw, err := os.ReadFile(*samplesPath)
	if err != nil {
		fatal("读取样例失败: %v", err)
	}
	var cases []sample
	if err := json.Unmarshal(raw, &cases); err != nil {
		fatal("解析样例失败: %v", err)
	}
	if len(cases) == 0 {
		fatal("样例文件为空")
	}

	h := admission.NewHandler(admission.Config{
		Observe: *observe,
		Policy: policy.Options{
			Strict:            *strict,
			AllowedRegistries: splitCSV(*registries),
			ExemptNamespaces:  splitCSV(*exemptNS),
			ExemptAnnotation:  "admission-guard.example.com/exempt",
		},
	})

	// 这一层统计只为了排版清楚，不参与断言。
	var pass, fail int
	fmt.Printf("%-28s %-8s %-8s %s\n", "样例", "预期", "实际", "命中规则")
	fmt.Println(strings.Repeat("-", 92))

	for _, c := range cases {
		op := c.Operation
		if op == "" {
			op = "CREATE"
		}

		got, rules, msg := run(h, c.Pod, op)

		expect, wantRules := c.Expect, c.WantRules
		if *strict && c.ExpectStrict != "" {
			expect, wantRules = c.ExpectStrict, c.WantRulesStrict
		}
		expect = strings.ToLower(expect)

		ok := expect == got
		if ok && got == "deny" {
			for _, want := range wantRules {
				if !contains(rules, want) {
					ok = false
					msg = "缺少预期规则 " + want + "；" + msg
				}
			}
		}
		// 打印是用来看的，断言是拿来判的：只看 ok，不看颜色。
		mark := "✓"
		if !ok {
			mark = "✗"
			fail++
		} else {
			pass++
		}
		fmt.Printf("%s %-26s %-8s %-8s %s\n", mark, c.Name, expect, got, strings.Join(rules, ","))
		if !ok {
			fmt.Printf("    └─ %s\n", indent(msg))
		}
	}

	fmt.Println(strings.Repeat("-", 92))
	fmt.Printf("通过 %d / %d\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}

// run 走真实的 handler 链路。用 httptest 是因为答案要由 HTTP 层的
// 编解码决定，而不是我们在这里再算一遍策略——那样等于自己证明自己。
func run(h *admission.Handler, pod json.RawMessage, operation string) (verdict string, rules []string, message string) {
	review := map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]any{
			"uid":       "probe-0001",
			"kind":      map[string]string{"group": "", "version": "v1", "kind": "Pod"},
			"operation": operation,
			"object":    pod,
			"userInfo":  map[string]any{"username": "checkpod"},
		},
	}
	body, err := json.Marshal(review)
	if err != nil {
		return "error", nil, err.Error()
	}

	req := httptest.NewRequest("POST", "/validate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		return "error", nil, fmt.Sprintf("HTTP %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	var out admission.Review
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		return "error", nil, err.Error()
	}
	if out.Response == nil {
		return "error", nil, "响应缺少 response 字段"
	}
	if out.Response.Allowed {
		if len(out.Response.Warnings) > 0 {
			return "allow", nil, strings.Join(out.Response.Warnings, " ")
		}
		return "allow", nil, ""
	}

	msg := ""
	if out.Response.Status != nil {
		msg = out.Response.Status.Message
	}
	return "deny", parseRules(msg), msg
}

// parseRules 从消息里回捞规则标识。
// 这不是优雅的做法，但它让输出能直接回答"被哪条规则拦的"，
// 比只打印一大段 message 有用得多。
func parseRules(msg string) []string {
	var out []string
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- [") {
			continue
		}
		end := strings.Index(line, "]")
		if end < 0 {
			continue
		}
		r := line[3:end]
		if !contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func indent(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n       ")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
