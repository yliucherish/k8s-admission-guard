#!/usr/bin/env bash
# 一键把 k8s-admission-guard 装进一个 kind 集群并跑通验证。
#
# 前置：docker 守护进程在跑、kind 与 kubectl 在 PATH 里。
#
# 为什么单独写这个脚本而不是把命令放在 README 里等人复制：
# 下面每一步都有一个不写就会卡住的细节（见各处注释），
# 照抄 README 的人一定会在第 4 步和第 5 步踩到。
set -euo pipefail

CLUSTER="${CLUSTER:-guard}"
IMAGE="ghcr.io/yliucherish/k8s-admission-guard:0.1.0"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

step "0) 检查前置"
command -v docker >/dev/null || { echo "缺少 docker"; exit 1; }
command -v kind   >/dev/null || { echo "缺少 kind：go install sigs.k8s.io/kind@latest"; exit 1; }
command -v kubectl >/dev/null || { echo "缺少 kubectl"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker 守护进程没起"; exit 1; }

step "1) 起集群（已存在则复用）"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "集群 $CLUSTER 已存在，跳过创建"
else
  kind create cluster --name "$CLUSTER" --wait 180s
fi

step "2) 生成证书"
bash "$HERE/gen-cert.sh"

step "3) 命名空间 + TLS secret"
kubectl apply -f "$HERE/namespace.yaml"
kubectl -n k8s-guard create secret tls k8s-guard-tls \
  --cert="$HERE/tls.crt" --key="$HERE/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -

step "4) 构建镜像"
# 必须用经典构建器。BuildKit/buildx 会去 auth.docker.io 换 token，
# 在网络受限的环境里报 "failed to fetch oauth token: Bad Gateway"，
# 而 docker pull 本身是通的 —— 现象很容易误判成镜像仓库不通。
DOCKER_BUILDKIT=0 docker build -t "$IMAGE" "$ROOT"

step "5) 载入 kind"
# 只载我们自己构建的镜像。kind 对 registry.k8s.io/pause 这类
# manifest list 镜像常报 "content digest ... not found"，
# 那是 kind 与 platform 解析的已知摩擦，不是镜像坏了。
kind load docker-image "$IMAGE" --name "$CLUSTER"

step "6) 部署工作负载"
kubectl apply -f "$HERE/deployment.yaml"
kubectl apply -f "$HERE/service.yaml"
kubectl -n k8s-guard rollout status deployment/k8s-guard --timeout=150s

step "7) 注册 webhook（替换 caBundle）"
# base64 用的是 -w0（GNU），macOS 上退回 openssl。
CA_BUNDLE=$(base64 -w0 "$HERE/ca.crt" 2>/dev/null || openssl base64 -A -in "$HERE/ca.crt")
# 用 '|' 当 sed 分隔符：base64 字母表只有 A-Za-z0-9+/=，
# 不含 '|'、'&'、'\'，所以不会被分隔符或替换语义吃掉。
sed "s|\${CA_BUNDLE}|$CA_BUNDLE|" "$HERE/webhook.yaml" | kubectl apply -f -

step "8) 重启工作负载，让它加载新证书"
# 必须重启，不能只更新 secret。
# Go 的 ListenAndServeTLS 在启动时把证书读进内存，之后不再看文件；
# secret 被替换后，挂载卷里的文件会变，但进程里的证书还是旧的。
# 于是 apiserver 用新 caBundle 去验旧证书 → x509 错误 → 所有 Pod 创建失败。
# 这是"证书轮转忘了重启"的经典故障，重跑本脚本时一定会遇到。
kubectl -n k8s-guard rollout restart deployment/k8s-guard
kubectl -n k8s-guard rollout status deployment/k8s-guard --timeout=150s

step "9) 等 endpoints 与 ready Pod 集合一致"
# 光等 rollout status 不够。它返回时 EndpointSlice 里可能还留着正在终止的旧 Pod IP，
# kube-proxy 仍会把请求发过去，而那些 Pod 内存里是旧证书 → apiserver 等到
# timeoutSeconds 超时，报 "context deadline exceeded" / "failed to call webhook"。
# 这个坑第一次跑脚本一定会踩到：现象看着像 TLS 配错了，其实是路由还没收敛。
# 所以判据要取"endpoints 集合 == ready pod IP 集合"，不是睡固定秒数。
for _ in $(seq 1 30); do
  ready=$(kubectl -n k8s-guard get pods -l app.kubernetes.io/name=k8s-guard \
            -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}' 2>/dev/null | sort | tr '\n' ' ')
  eps=$(kubectl -n k8s-guard get endpointslices -l kubernetes.io/service-name=k8s-guard \
          -o jsonpath='{range .items[*]}{range .endpoints[*]}{.addresses[0]}{"\n"}{end}{end}' 2>/dev/null | sort | tr '\n' ' ')
  if [ -n "$eps" ] && [ "$ready" = "$eps" ]; then
    echo "已收敛: $eps"
    break
  fi
  sleep 1
done

step "10) 给 default 命名空间打上 guard=enforce"
kubectl label namespace default guard=enforce --overwrite >/dev/null
echo "default 已标记 guard=enforce"

step "11) 验证：应被拒"
cat <<'EOF' | kubectl apply -f - || true
apiVersion: v1
kind: Pod
metadata:
  name: should-be-denied
spec:
  containers:
    - name: shell
      image: nginx:1.27
      securityContext:
        privileged: true
EOF

echo
echo "如果上面出现 Error from server (Forbidden) 且点明 privileged-container，说明整条链路是通的。"
echo "清理：kind delete cluster --name $CLUSTER"
