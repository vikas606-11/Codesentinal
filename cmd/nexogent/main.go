// Command CodeSentinal. runs the SecOps agent API server.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/sriramg-aivar/CodeSentinal./internal/api"
	"github.com/sriramg-aivar/CodeSentinal./internal/demo"
	"github.com/sriramg-aivar/CodeSentinal./internal/kube"
	"github.com/sriramg-aivar/CodeSentinal./internal/session"
	"github.com/sriramg-aivar/CodeSentinal./internal/store"
)

const version = "2.0.0"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	region := env("AWS_REGION", env("AWS_DEFAULT_REGION", "us-east-1"))
	addr := env("LISTEN_ADDR", ":8080")
	demoMode := env("DEMO_MODE", "") == "true"
	reviewsTable := env("REVIEWS_TABLE", "")
	adminPassword := env("SUPERADMIN_PASSWORD", "")
	scanInterval := env("SCAN_INTERVAL", "")
	sessionSecret := env("SESSION_SECRET", "")
	local := env("KUBERNETES_SERVICE_HOST", "") == ""

	ctx := context.Background()

	var awsCfg aws.Config
	if !demoMode {
		c, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			log.Fatalf("load AWS config: %v", err)
		}
		awsCfg = c
	}

	// Store.
	var st store.Store
	if demoMode {
		st = store.NewMemory()
		seedDemo(ctx, st)
		log.Printf("DEMO MODE: synthetic data, no AWS calls")
	} else if reviewsTable != "" {
		st = store.NewDynamo(dynamodb.NewFromConfig(awsCfg), reviewsTable)
		log.Printf("persistence: DynamoDB table %q", reviewsTable)
	} else {
		st = store.NewMemory()
		log.Printf("persistence: in-memory (set REVIEWS_TABLE for DynamoDB)")
	}

	// Sessions.
	authEnabled := adminPassword != "" && !demoMode
	if sessionSecret == "" {
		sessionSecret = session.RandomSecret()
		if authEnabled {
			log.Printf("WARNING: SESSION_SECRET not set; generated an ephemeral one (sessions won't survive restart / multi-replica)")
		}
	}
	ttl := 8 * time.Hour
	if v := env("SESSION_TTL", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ttl = d
		}
	}

	var runner kube.JobRunner
	if !demoMode {
		runner = kube.New()
	}

	srv := api.New(api.Config{
		AWS: awsCfg, Region: region,
		BedrockModel:   env("BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0"),
		ProwlerResults: env("PROWLER_RESULTS_DIR", "/data/prowler"),
		ScoutResults:   env("SCOUTSUITE_RESULTS_DIR", ""),
		CSPResults:     env("CLOUDSPLAINING_RESULTS_DIR", ""),
		Store:          st,
		Sessions:       session.New(sessionSecret, ttl),
		Throttle:       session.NewThrottle(),
		Password:       adminPassword,
		AuthEnabled:    authEnabled,
		TrustProxy:     env("TRUST_PROXY", "") == "true",
		PublicURL:      env("PUBLIC_URL", ""),
		Kube:           runner,
		ProwlerCronJob: env("PROWLER_CRONJOB_NAME", "CodeSentinal.-prowler"),
		Demo:           demoMode,
		Local:          local,
		Version:        version,
	})

	if !authEnabled && !demoMode {
		log.Printf("WARNING: SUPERADMIN_PASSWORD not set — auth gate is OPEN (dev only)")
	}

	if scanInterval != "" && !demoMode {
		if d, err := time.ParseDuration(scanInterval); err == nil && d > 0 {
			log.Printf("scheduler: running a review every %s", d)
			go runScheduler(ctx, srv, d)
		}
	}

	log.Printf("CodeSentinal. v%s listening on %s (region %s)", version, addr, region)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

func runScheduler(ctx context.Context, srv *api.Server, d time.Duration) {
	time.Sleep(20 * time.Second)
	for {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		if _, err := srv.RunReview(rctx, "", ""); err != nil {
			log.Printf("scheduled review failed: %v", err)
		}
		cancel()
		time.Sleep(d)
	}
}

// seedDemo loads synthetic data into the store for DEMO_MODE.
func seedDemo(ctx context.Context, st store.Store) {
	_ = st.Put(ctx, demo.Review())
	kv := st.KV()
	for _, h := range demo.History() {
		_ = kv.PutItem(ctx, "history", h.At.UTC().Format(time.RFC3339Nano), h)
	}
	for _, r := range demo.Risks() {
		_ = kv.PutItem(ctx, "risk", r.Fingerprint, r)
	}
}
