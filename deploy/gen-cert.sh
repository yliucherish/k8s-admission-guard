#!/usr/bin/env bash
# 给 webhook 生成自签证书，并输出可直接填进 ValidatingWebhookConfiguration 的 caBundle。
#
# 为什么不用 cert-manager：这是最小证明，不想引入第二个组件。
# 但如果要在生产用，正确做法是 cert-manager 的 CA injector 或
# service.beta.openshift.io/serving-cert-secret-name 之类的自动轮转方案——
# 自签证书会过期，过期那天 webhook 挂了、failurePolicy=Fail、整个集群建不了 Pod。
# 这个坑必须在文档里写出来，而不是等它某天凌晨炸。
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE="k8s-guard"
NAMESPACE="k8s-guard"
DAYS="${DAYS:-365}"

echo "[*] 输出目录: $OUT_DIR"
command -v openssl >/dev/null || { echo "需要 openssl"; exit 1; }

# 1) CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/ca.key" -out "$OUT_DIR/ca.crt" \
  -days "$DAYS" -subj "/CN=k8s-guard-ca" >/dev/null 2>&1

# 2) 服务端私钥 + CSR
#    SAN 必须写全：apiserver 用 <service>.<namespace>.svc 这个域名访问，
#    只写 CN 而不写 SAN 时，Go 的 TLS 校验会直接失败，
#    报错是 "x509: certificate relies on legacy Common Name field"，很难猜。
openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/tls.key" -out "$OUT_DIR/tls.csr" \
  -subj "/CN=${SERVICE}.${NAMESPACE}.svc" >/dev/null 2>&1

cat >"$OUT_DIR/san.cnf" <<EOF
subjectAltName = DNS:${SERVICE}, DNS:${SERVICE}.${NAMESPACE}, DNS:${SERVICE}.${NAMESPACE}.svc, DNS:${SERVICE}.${NAMESPACE}.svc.cluster.local
extendedKeyUsage = serverAuth
EOF

# 3) 用 CA 签发服务端证书
openssl x509 -req -in "$OUT_DIR/tls.csr" \
  -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$OUT_DIR/tls.crt" -days "$DAYS" \
  -extfile "$OUT_DIR/san.cnf" >/dev/null 2>&1

rm -f "$OUT_DIR/tls.csr" "$OUT_DIR/san.cnf"

echo "[+] 已生成: ca.crt  tls.crt  tls.key"
echo
echo "下一步："
echo "  kubectl -n $NAMESPACE create secret tls k8s-guard-tls \\"
echo "    --cert=$OUT_DIR/tls.crt --key=$OUT_DIR/tls.key"
echo
echo "  CA_BUNDLE=\$(base64 -w0 $OUT_DIR/ca.crt)"
echo "  sed \"s|\\\${CA_BUNDLE}|\$CA_BUNDLE|\" deploy/webhook.yaml | kubectl apply -f -"
echo
echo "验证 SAN（应能看到 ${SERVICE}.${NAMESPACE}.svc）："
echo "  openssl x509 -in $OUT_DIR/tls.crt -noout -text | grep -A1 'Subject Alternative Name'"
