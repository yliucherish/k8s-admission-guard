# 两阶段构建，最终镜像用 scratch —— 没有 shell、没有包管理器、没有 libc。
# 一个准入控制器如果自己跑在带 shell 的镜像里，被拿下之后攻击者就有现成的跳板。
#
# 注意：因为 go.mod 声明的是 go 1.22，这里用 1.24 的构建镜像即可；
# 项目本身零第三方依赖，所以构建阶段不需要 `go mod download` 联网。
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/webhook ./cmd/webhook

FROM scratch
COPY --from=build /out/webhook /webhook
# 10001 与 deployment.yaml 里的 runAsUser 保持一致。
# scratch 镜像没有 /etc/passwd，所以只能写数字 UID。
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/webhook"]
