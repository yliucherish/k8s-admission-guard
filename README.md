# k8s-admission-guard

[![CI](https://github.com/yliucherish/k8s-admission-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yliucherish/k8s-admission-guard/actions/workflows/ci.yml)

一个最小可用的 Kubernetes **Validating Admission Webhook**：在 Pod 被创建之前，
按策略拒绝高危配置。

**零第三方依赖**——只用 Go 标准库，`GOPROXY=off` 也能 `go build`。
没有 `k8s.io/api`，没有 controller-runtime，没有 cert-manager。

```bash
go test ./...                                   # 27 个用例（含子用例 54）
go run ./cmd/checkpod -samples deploy/samples/pods.json   # 12 条样例判定
```

---

## 1. 先说清楚：这跟 PodSecurity Admission 重了什么

**大部分是重的。** Kubernetes 1.25 起 PodSecurity Admission（PSA）进入 GA，
`restricted` 档位已经会拦 privileged、要求 `runAsNonRoot`、限制 hostPath 类型。
如果这个项目宣称"我实现了容器逃逸防护"，内行第一句就会问"你为什么不用 PSA"。

所以它的定位不是"补 PSA 的空白"，而是两件事：

1. **走通 admission webhook 这条扩展路径**。PSA 是内置的、不可编程的；
   而企业真实的准入需求大多超出 PSA 的表达能力，落地方式就是自己写 webhook。
   这个仓库是一个可以直接读、直接改的最小骨架。
2. **做 PSA 表达不了的那一类规则**。本项目第四条规则（镜像仓库白名单）就是：
   PSA 完全不看镜像从哪来，而"只许拉公司仓库和官方基础镜像"是企业里非常硬的需求。

诚实结论：**这个项目的价值在于"我知道 PSA 已经覆盖了 80%，我补的是剩下 20%，
并且我清楚边界在哪"**，而不是"我发明了新防护"。

---

## 2. 拦什么

| 规则 | 判据 | 为什么 | PSA 有吗 |
|---|---|---|---|
| `privileged-container` | 任一容器 `securityContext.privileged: true` | 等于拿到宿主 root | ✅ restricted 已拦 |
| `hostpath-mount` | `volumes[].hostPath` 存在 | 可读写宿主文件系统；`/var/run/docker.sock` 是经典逃逸入口 | ✅ baseline 限类型 |
| `run-as-root` | 生效的 `runAsUser == 0` 或 `runAsNonRoot: false` | root 容器 + 内核漏洞 = 逃逸 | ✅ restricted 已拦 |
| `untrusted-image-registry` | 镜像不在仓库白名单内 | 供应链：谁能推镜像谁就能执行代码 | ❌ **PSA 不做** |

四条规则都做了三件容易被忽略的事：

**① 三类容器全查。** `containers`、`initContainers`、`ephemeralContainers` 都走一遍。
只查 `containers` 是这类 webhook 最常见的漏洞——攻击者把 `privileged: true`
写进 `initContainer`，逃逸效果一模一样，而简陋的实现会放行。
`ephemeralContainers` 更隐蔽：`kubectl debug` 就是用它在运行中的 Pod 里插容器。

**② 处理 `runAsUser` 的层级覆盖。** 容器级 `securityContext` 覆盖 Pod 级。
写反了会同时产生两类错误：漏放（Pod 写 1000、容器写 0）和误拦（Pod 写 0、容器写 1000）。

**③ 一次报全，并给修法。** 一次只报一条，用户改完 privileged 又被 hostPath 拒，
再改再被 root 拒，来回三轮。拒绝消息里每条违规都带 `fix:`。

---

## 3. 三个设计取舍（面试真正会问的地方）

### 取舍一：`failurePolicy: Fail` 还是 `Ignore`

webhook 是在 `CREATE pods` 的同步路径上被调用的。选 `Fail`，则 webhook 不可用时
**整个集群建不了 Pod**；选 `Ignore`，则 webhook 不可用时门是敞开的。

本项目选 `Fail`（默认安全），代价和缓解手段都写在 `deploy/webhook.yaml` 里：

- `namespaceSelector` 只匹配带 `guard=enforce` 标签的命名空间 → 系统组件不受影响
- 代码层再加 `-exempt-namespaces=kube-system,k8s-guard` → 配置写错时还有兜底
- `replicas: 2` + `PodDisruptionBudget minAvailable: 1` → 滚动更新不会把门关死

**这是"检测能力变成单点故障"的典型例子**：一个为了安全而加的组件，
如果没考虑自己的可用性，最后造成的故障比它防的风险更大。

### 取舍二：`-strict` 模式与"未声明"的边界

Kubernetes 的默认行为是"以镜像里的 `USER` 运行"，而多数镜像的 `USER` 是 root。
所以「没写 `runAsNonRoot`」实际上约等于「以 root 跑」。

但严格要求显式声明，会拦掉大量正常负载（Helm chart、教程、CI 里随手写的 Pod）。
直接这么上，第一天就会有人来投诉。

所以：

- **默认模式**只拦「明确要求 root」的（`runAsUser: 0` / `runAsNonRoot: false`）
- **`-strict` 模式**才把「未声明」也算违规

两种模式的预期都写在 `deploy/samples/pods.json` 里（`expect` / `expectStrict` 两个字段），
`go run ./cmd/checkpod -strict` 会验证翻转是否正确。

### 取舍三：先 observe，再 enforce

`-observe` 模式下结论仍是 `allow`，但把"本该拒"的信息通过 `warnings` 回传，
`kubectl` 会把它打出来。

上线新规则的正确顺序是：先 observe 几天，看清会拦到哪些现存工作负载，
再切强制。跳过这一步的常见结局是某天把监控组件自己拦死——而 webhook 是
`fail-closed` 的，那时候集群已经起不来了。

---

## 4. 怎么验证

### 路径一：单元测试（不需要集群，不需要 Docker）

```bash
go test ./... -v
```

27 个顶层用例（含子用例 54），覆盖：三类容器的 privileged、`runAsUser` 层级覆盖、
strict 模式翻转、hostPath 与高危路径提示、镜像短名规范化（`nginx` →
`docker.io/library/nginx`）、白名单前缀边界（`ghcr.io/foo` 不能匹配
`ghcr.io/foobar`）、豁免注解只认字面 `"true"`。

admission 那一层单独测 HTTP 语义：GET → 405、非 JSON → 415、
缺 `uid` → 400（没有 uid 就无法把响应对回请求，apiserver 只会报
`webhook response was invalid`，极难排查）、**Pod 对象解析失败必须拒绝而不是放行**。

### 路径二：无集群判定器（不需要集群，走真实 handler）

```bash
go run ./cmd/checkpod -samples deploy/samples/pods.json
go run ./cmd/checkpod -samples deploy/samples/pods.json -strict
```

它把样例包装成真实的 `AdmissionReview`，灌进**与线上完全相同**的 handler
（`internal/admission`），再比对预期。验证的是"JSON 解码 → 策略 → 响应编码"整条链路，
不是"策略函数算得对"。

```
样例                            预期     实际     命中规则
✓ privileged-container          deny     deny     privileged-container
✓ privileged-in-initContainer   deny     deny     privileged-container
✓ hostpath-docker-sock          deny     deny     hostpath-mount
...
通过 12 / 12
```

**它不能代替集群验证**：证书、Service、CA bundle、`failurePolicy` 的实际生效
只有真集群才验得到。两者是互补关系，别用这个脚本冒充"我在 K8s 上跑通了"。

### 路径三：真集群（kind，已在 K8s v1.37.0 上实测通过）

```bash
export PATH="$PATH:$(go env GOPATH)/bin"   # kind 装在这里
go install sigs.k8s.io/kind@latest
./deploy/install.sh                        # 从起集群到验证一把过
```

`install.sh` 里每一步都写清了"不这么写就会卡住"的原因，主要两个坑：

1. **必须用经典构建器**：`DOCKER_BUILDKIT=0 docker build`。buildx 会去
   `auth.docker.io` 换 token，在网络受限环境里报
   `failed to fetch oauth token: Bad Gateway`，而 `docker pull` 明明是通的——
   现象极易误判成"镜像仓库不通"。
2. **`kind load` 只载自己构建的镜像**。载 `registry.k8s.io/pause:3.9` 这类
   manifest list 镜像会报 `content digest ... not found`，那是 kind 的
   platform 解析摩擦，不是镜像坏了。
3. **重跑脚本时不能只 `rollout status`**。它返回时 `EndpointSlice` 里可能还留着
   正在终止的旧 Pod IP，kube-proxy 仍会把请求发过去，而那些 Pod 内存里是旧证书
   （Go 的 `ListenAndServeTLS` 只在启动时读一次证书），于是 apiserver 等到
   `timeoutSeconds` 超时，报 `context deadline exceeded`。看着像 TLS 配错，
   实际是路由没收敛。脚本因此要等 `endpoints 集合 == ready Pod IP 集合` 才继续。

手动版（`install.sh` 逐步展开）：

```bash
kind create cluster --name guard
./deploy/gen-cert.sh
kubectl apply -f deploy/namespace.yaml
kubectl -n k8s-guard create secret tls k8s-guard-tls \
  --cert=deploy/tls.crt --key=deploy/tls.key
DOCKER_BUILDKIT=0 docker build -t ghcr.io/yliucherish/k8s-admission-guard:0.1.0 .
kind load docker-image ghcr.io/yliucherish/k8s-admission-guard:0.1.0 --name guard
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/service.yaml
CA_BUNDLE=$(base64 -w0 deploy/ca.crt)
sed "s|\${CA_BUNDLE}|$CA_BUNDLE|" deploy/webhook.yaml | kubectl apply -f -
kubectl label namespace default guard=enforce
```

#### 实测记录（2026-11-05，kind v0.33.0 / K8s v1.37.0 / containerd 2.3.4）

**特权容器 → 被拒**（真实 apiserver 返回 403，带规则名与修法）：

```
$ kubectl apply -f bad1.yaml
Error from server (Forbidden): error when creating "bad1.yaml": admission webhook
"pods.k8s-guard.example.com" denied the request: denied by k8s-admission-guard (1 violation(s)):
  - [privileged-container] spec.containers[0].securityContext.privileged: 容器 "shell" 声明了 privileged: true，等同宿主 root
    fix: 去掉 privileged，改为按需 add 单个 capability（如 NET_BIND_SERVICE）
```

**四类违规全部拦住**：

| 用例 | 结果 |
|---|---|
| `privileged: true` | Forbidden，`privileged-container` |
| `hostPath: /var/run/docker.sock` | Forbidden，`hostpath-mount` |
| `runAsUser: 0` | Forbidden，`run-as-root` |
| `image: quay.io/unknown/backdoor:1.0` | Forbidden，`untrusted-image-registry` |

**`initContainer` 绕过 → 被拒，字段路径精确**（这是只查 `containers` 的实现会漏的那一类）：

```
Error from server (Forbidden): ... denied by k8s-admission-guard (1 violation(s)):
  - [privileged-container] spec.initContainers[0].securityContext.privileged:
    容器 "setup" 声明了 privileged: true，等同宿主 root
```

**合规 Pod → 放行且正常运行**（反向控制，证明门没焊死）：

```
$ kubectl apply -f good.yaml
pod/legit-app created
$ kubectl get pod legit-app
NAME        READY   STATUS    RESTARTS   AGE
legit-app   1/1     Running   0          8s
```

**镜像体积**：9.09 MB（scratch 基底 + 静态链接二进制，无 shell、无包管理器）。

---

## 5. 已知局限（写在这里，不藏着）

1. **自签证书会过期。** `gen-cert.sh` 生成的是 365 天自签证书，不会自动轮转。
   过期那天 webhook 挂掉、`failurePolicy: Fail`、集群建不了 Pod。
   生产必须换成 cert-manager CA injector 之类的自动轮转方案。
2. **`base64 -w0` 是 GNU 参数**，macOS 上要用 `base64` 不带 `-w0`（或用
   `openssl base64 -A`）。脚本里没做跨平台分支。
3. **只覆盖 Pod 创建。** 不处理 Deployment/StatefulSet 的 `spec.template`——
   那些最终会创建 Pod，所以仍会被拦，但报错会指向 ReplicaSet 而不是原始 Deployment，
   用户体验上要差一层。
4. **没有处理 `allowPrivilegeEscalation`** 和 capability 白名单。
   它们是 `restricted` 档位的一部分，本项目没做——因为目标是最小证明，不是完整复刻 PSA。
5. **规则是硬编码的**，没有做成 CRD 可配置。真实产品会做成
   `ClusterPolicy` 之类的 CRD，本项目刻意不做（会增加一个 controller 的量）。
6. **只在 kind 单节点上验证过**（K8s v1.37.0 / containerd 2.3.4），
   没有在托管集群（EKS/ACK）、多节点、IPv6 环境验证过。
   `namespaceSelector` 这类配置在多租户集群里的边界条件，单节点测不出来。
7. **`kind load docker-image` 对 manifest list 镜像不可靠**
   （`registry.k8s.io/pause:3.9` 报 `content digest ... not found`）；
   安装脚本因此只载本地构建的镜像。

---

## 6. 面试可以怎么讲

> 我写了一个 K8s 准入 webhook 来拦高危 Pod。写之前我先确认了 PSA 已经覆盖
> privileged、runAsNonRoot、hostPath 这几条，所以我没把它包装成"新防护"——
> 它的价值是走通 webhook 这条扩展路径，外加一条 PSA 做不到的镜像仓库白名单。
>
> 实现上有三个坑我特意处理了：一是 `initContainers` 和 `ephemeralContainers`
> 也要查，只查 `containers` 的话 `kubectl debug` 插进去的特权容器就漏了；
> 二是 `runAsUser` 容器级覆盖 Pod 级，写反会同时漏放和误拦；
> 三是 webhook 本身是同步调用 + `failurePolicy: Fail`，它挂了集群就建不了 Pod，
> 所以我给它配了 PDB、双副本、系统命名空间豁免，并且先跑 observe 模式再切强制。

---

## 7. 目录

```
k8s-admission-guard/
├── cmd/webhook/            # HTTPS 服务端
├── cmd/checkpod/           # 无集群判定器
├── internal/policy/        # 策略引擎（纯函数，无 IO）
├── internal/admission/     # AdmissionReview 编解码 + HTTP 层
├── deploy/
│   ├── install.sh          # 一键装进 kind 并验证
│   ├── gen-cert.sh         # 自签 CA + 服务端证书（含 SAN）
│   ├── namespace.yaml
│   ├── deployment.yaml     # guard 自己按自己的规则加固
│   ├── service.yaml
│   ├── webhook.yaml        # ValidatingWebhookConfiguration（含 ${CA_BUNDLE} 占位）
│   └── samples/pods.json   # 12 条判定样例，含 strict 模式的另一套预期
└── Dockerfile              # 两阶段，最终 scratch，9 MB
```
