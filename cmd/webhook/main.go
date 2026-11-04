// cmd/webhook 是 Validating Admission Webhook 的服务端。
//
// 用法：
//
//	go run ./cmd/webhook -addr :8443 -cert deploy/tls.crt -key deploy/tls.key \
//	    -allowed-registries docker.io/library,ghcr.io/yliucherish
//
// 不带 -cert/-key 时以明文 HTTP 启动，只用于本地联调（apiserver 要求 HTTPS，
// 真实部署必须给证书）。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yliucherish/k8s-admission-guard/internal/admission"
	"github.com/yliucherish/k8s-admission-guard/internal/policy"
)

func main() {
	var (
		addr       = flag.String("addr", ":8443", "监听地址")
		certFile   = flag.String("cert", "", "TLS 证书路径（PEM）；留空则明文 HTTP")
		keyFile    = flag.String("key", "", "TLS 私钥路径（PEM）")
		strict     = flag.Bool("strict", false, "要求显式声明 runAsNonRoot，未声明即视为违规")
		observe    = flag.Bool("observe", false, "观察模式：只记录与返回 warning，不拒绝")
		exemptNS   = flag.String("exempt-namespaces", "kube-system", "整体豁免的命名空间，逗号分隔")
		registries = flag.String("allowed-registries", "", "镜像仓库白名单前缀，逗号分隔；留空表示不检查")
		exemptAnn  = flag.String("exempt-annotation", "admission-guard.example.com/exempt", "豁免注解键，值为 true 时放行")
		logLevel   = flag.String("log-level", "info", "日志级别：debug/info/warn/error")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	cfg := admission.Config{
		Observe: *observe,
		Logger:  log,
		Policy: policy.Options{
			Strict:            *strict,
			AllowedRegistries: splitCSV(*registries),
			ExemptNamespaces:  splitCSV(*exemptNS),
			ExemptAnnotation:  *exemptAnn,
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/validate", admission.NewHandler(cfg))
	// 存活与就绪分开：就绪探针不通过时 apiserver 仍会调用 webhook，
	// 但 kubelet 不会再把流量发进来。这里的 webhook 没有外部依赖，
	// 所以两者都只是"进程还活着"。
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// 读超时必须有：admission 调用是同步的，一个慢请求会占住 apiserver 的 worker。
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening",
			"addr", *addr,
			"tls", *certFile != "",
			"strict", *strict,
			"observe", *observe,
			"allowedRegistries", cfg.Policy.AllowedRegistries,
			"exemptNamespaces", cfg.Policy.ExemptNamespaces)

		if *certFile != "" && *keyFile != "" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errCh <- srv.ListenAndServeTLS(*certFile, *keyFile)
			return
		}
		log.Warn("running without TLS — apiserver 不会接受明文 webhook，仅用于本地联调")
		errCh <- srv.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "err", err)
			os.Exit(1)
		}
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
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

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
