package contract_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	openapi "github.com/quocdev03/user-access-management/docs/openapi"
	"github.com/quocdev03/user-access-management/internal/blob"
	"github.com/quocdev03/user-access-management/internal/config"
	"github.com/quocdev03/user-access-management/internal/httpapi"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type publicOperation struct {
	semanticID   string
	method       string
	path         string
	authRequired bool
	successCode  string
}

var publicOperations = []publicOperation{
	{"AUTH-REGISTER", http.MethodPost, "/auth/register", false, "201"},
	{"AUTH-EMAIL-VERIFY", http.MethodPost, "/auth/email/verify", false, "200"},
	{"AUTH-EMAIL-RESEND", http.MethodPost, "/auth/email/resend", false, "200"},
	{"AUTH-LOGIN", http.MethodPost, "/auth/login", false, "200"},
	{"AUTH-TOKEN-REFRESH", http.MethodPost, "/auth/token/refresh", false, "200"},
	{"AUTH-LOGOUT", http.MethodPost, "/auth/logout", true, "200"},
	{"AUTH-LOGOUT-ALL", http.MethodPost, "/auth/logout-all", true, "200"},
	{"AUTH-PASSWORD-FORGOT", http.MethodPost, "/auth/password/forgot", false, "200"},
	{"AUTH-PASSWORD-RESET", http.MethodPost, "/auth/password/reset", false, "200"},
	{"AUTH-PASSWORD-CHANGE", http.MethodPost, "/auth/password/change", true, "200"},
	{"AUTH-PASSWORD-FORCE-CHANGE", http.MethodPost, "/auth/password/force-change", false, "200"},
	{"MFA-LOGIN-VERIFY", http.MethodPost, "/auth/mfa/login/verify", false, "200"},
	{"MFA-SETUP", http.MethodPost, "/auth/mfa/setup", true, "200"},
	{"MFA-CONFIRM", http.MethodPost, "/auth/mfa/confirm", true, "200"},
	{"MFA-DISABLE", http.MethodPost, "/auth/mfa/disable", true, "200"},
	{"MFA-STATUS", http.MethodGet, "/auth/mfa/status", true, "200"},
	{"MFA-RECOVERY-REGENERATE", http.MethodPost, "/auth/mfa/recovery/regenerate", true, "200"},
	{"ACCOUNT-PROFILE-GET", http.MethodGet, "/users/me", true, "200"},
	{"ACCOUNT-PROFILE-UPDATE", http.MethodPatch, "/users/me", true, "200"},
	{"ACCOUNT-EMAIL-CHANGE-REQUEST", http.MethodPost, "/users/me/email/change-request", true, "200"},
	{"ACCOUNT-EMAIL-CHANGE-VERIFY", http.MethodPost, "/users/me/email/verify", true, "200"},
	{"ACCOUNT-EMAIL-CHANGE-RESEND", http.MethodPost, "/users/me/email/resend", true, "200"},
	{"ACCOUNT-AVATAR-UPLOAD", http.MethodPost, "/users/me/avatar", true, "200"},
	{"ACCOUNT-AVATAR-DELETE", http.MethodDelete, "/users/me/avatar", true, "200"},
	{"SESSION-LIST", http.MethodGet, "/users/me/sessions", true, "200"},
	{"SESSION-REVOKE", http.MethodDelete, "/users/me/sessions/{id}", true, "200"},
	{"CLIENT-PROFILE-LIST", http.MethodGet, "/users/me/devices", true, "200"},
	{"ACCESS-USER-LIST", http.MethodGet, "/admin/users", true, "200"},
	{"ACCESS-USER-GET", http.MethodGet, "/admin/users/{id}", true, "200"},
	{"ACCESS-USER-UPDATE", http.MethodPut, "/admin/users/{id}", true, "200"},
	{"ACCESS-USER-STATUS-CHANGE", http.MethodPatch, "/admin/users/{id}/status", true, "200"},
	{"ACCESS-USER-PASSWORD-RESET", http.MethodPost, "/admin/users/{id}/password/reset", true, "200"},
	{"ACCESS-USER-NOTIFY", http.MethodPost, "/admin/users/{id}/notify", true, "200"},
	{"ACCESS-ROLE-LIST", http.MethodGet, "/admin/roles", true, "200"},
	{"ACCESS-ROLE-CREATE", http.MethodPost, "/admin/roles", true, "200"},
	{"ACCESS-ROLE-UPDATE", http.MethodPut, "/admin/roles/{id}", true, "200"},
	{"ACCESS-ROLE-DELETE", http.MethodDelete, "/admin/roles/{id}", true, "200"},
	{"ACCESS-ROLE-PERMISSIONS-REPLACE", http.MethodPut, "/admin/roles/{id}/permissions", true, "200"},
	{"ACCESS-ROLE-ASSIGN", http.MethodPost, "/admin/users/{id}/roles", true, "200"},
	{"ACCESS-ROLE-REMOVE", http.MethodDelete, "/admin/users/{id}/roles/{roleId}", true, "200"},
	{"AUDIT-EXPORT", http.MethodGet, "/admin/audit-logs/export", true, "200"},
}

type swaggerDocument struct {
	BasePath string                                 `json:"basePath"`
	Paths    map[string]map[string]swaggerOperation `json:"paths"`
	Security map[string]json.RawMessage             `json:"securityDefinitions"`
}

type swaggerOperation struct {
	Produces  []string                `json:"produces"`
	Responses map[string]swaggerReply `json:"responses"`
	Security  []map[string][]string   `json:"security"`
}

type swaggerReply struct {
	Schema json.RawMessage `json:"schema"`
}

func TestPublicAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	redisClient := newContractRedis(t)
	assertContractRedis(t, redisClient)
	blobStore, err := blob.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("create contract blob store: %v", err)
	}
	engine := httpapi.Setup(
		nil,
		redisClient,
		zap.NewNop(),
		contractConfig(),
		blobStore,
	)
	spec := readSwagger(t)

	if spec.BasePath != "/api/v1" {
		t.Fatalf("OpenAPI base path = %q, want /api/v1", spec.BasePath)
	}
	if _, ok := spec.Security["BearerAuth"]; !ok {
		t.Fatal("OpenAPI BearerAuth security definition is missing")
	}

	actualRoutes := make(map[string]struct{})
	for _, route := range engine.Routes() {
		if !strings.HasPrefix(route.Path, "/api/v1/") {
			continue
		}
		key := route.Method + " " + normalizeGinPath(strings.TrimPrefix(route.Path, "/api/v1"))
		actualRoutes[key] = struct{}{}
	}

	registered := make(map[string]string, len(publicOperations))
	for _, operation := range publicOperations {
		operation := operation
		t.Run(operation.semanticID, func(t *testing.T) {
			key := operation.method + " " + operation.path
			if previous, exists := registered[key]; exists {
				t.Fatalf("contract duplicates %s from %s", key, previous)
			}
			registered[key] = operation.semanticID

			if _, ok := actualRoutes[key]; !ok {
				t.Fatalf("runtime route %s is missing", key)
			}

			swaggerPath, ok := spec.Paths[operation.path]
			if !ok {
				t.Fatalf("OpenAPI path %s is missing", operation.path)
			}
			documented, ok := swaggerPath[strings.ToLower(operation.method)]
			if !ok {
				t.Fatalf("OpenAPI operation %s is missing", key)
			}

			if hasBearerSecurity(documented) != operation.authRequired {
				t.Fatalf(
					"BearerAuth for %s = %t, want %t",
					key,
					hasBearerSecurity(documented),
					operation.authRequired,
				)
			}
			if reply, ok := documented.Responses[operation.successCode]; !ok || len(reply.Schema) == 0 {
				t.Fatalf("OpenAPI success response %s for %s has no schema", operation.successCode, key)
			}

			errorCode := "400"
			if operation.authRequired {
				errorCode = "401"
			}
			if reply, ok := documented.Responses[errorCode]; !ok || len(reply.Schema) == 0 {
				t.Fatalf("OpenAPI error response %s for %s has no schema", errorCode, key)
			}

			assertRuntimeBoundary(t, engine, operation)
		})
	}

	for key := range actualRoutes {
		if _, ok := registered[key]; !ok {
			t.Errorf(
				"runtime operation %s has no semantic contract; add it to publicOperations and docs/use-cases",
				key,
			)
		}
	}
	for path, methods := range spec.Paths {
		for method := range methods {
			key := strings.ToUpper(method) + " " + path
			if _, ok := registered[key]; !ok {
				t.Errorf(
					"OpenAPI operation %s has no semantic contract; add it to publicOperations and docs/use-cases",
					key,
				)
			}
		}
	}
}

func assertContractRedis(t *testing.T, client *redis.Client) {
	t.Helper()

	ctx := context.Background()
	if _, err := client.Exists(ctx, "contract:missing").Result(); err != nil {
		t.Fatalf("contract Redis EXISTS: %v", err)
	}
	pipe := client.TxPipeline()
	pipe.Incr(ctx, "contract:counter")
	pipe.Expire(ctx, "contract:counter", time.Minute)
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatalf("contract Redis transaction: %v", err)
	}
}

func assertRuntimeBoundary(t *testing.T, engine http.Handler, operation publicOperation) {
	t.Helper()

	request := httptest.NewRequest(
		operation.method,
		"/api/v1"+concretePath(operation.path),
		strings.NewReader("{}"),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	wantStatus := http.StatusBadRequest
	if operation.authRequired {
		wantStatus = http.StatusUnauthorized
	}
	if recorder.Code != wantStatus {
		t.Fatalf(
			"runtime status for unauthenticated %s %s = %d, want %d; body=%s",
			operation.method,
			operation.path,
			recorder.Code,
			wantStatus,
			recorder.Body.String(),
		)
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response envelope: %v; body=%s", err, recorder.Body.String())
	}
	if string(envelope["success"]) != "false" || len(envelope["error"]) == 0 {
		t.Fatalf("invalid error envelope for %s %s: %s", operation.method, operation.path, recorder.Body.String())
	}
}

func readSwagger(t *testing.T) swaggerDocument {
	t.Helper()

	var spec swaggerDocument
	if err := json.Unmarshal([]byte(openapi.SwaggerInfo.ReadDoc()), &spec); err != nil {
		t.Fatalf("decode generated OpenAPI: %v", err)
	}
	return spec
}

func hasBearerSecurity(operation swaggerOperation) bool {
	for _, requirement := range operation.Security {
		if _, ok := requirement["BearerAuth"]; ok {
			return true
		}
	}
	return false
}

var ginParameter = regexp.MustCompile(`:([^/]+)`)
var swaggerParameter = regexp.MustCompile(`\{[^/]+\}`)

func normalizeGinPath(path string) string {
	return ginParameter.ReplaceAllString(path, `{$1}`)
}

func concretePath(path string) string {
	return swaggerParameter.ReplaceAllString(path, "1")
}

func contractConfig() *config.Config {
	return &config.Config{
		App: config.AppConfig{
			Env:         "production",
			FrontendURL: "https://contract.invalid",
		},
		Blob: config.BlobConfig{
			Provider: "s3",
		},
		JWT: config.JWTConfig{
			Secret: "contract-test-secret",
		},
		Security: config.SecurityConfig{
			RateLimitRequests:    1000,
			RateLimitWindow:      time.Minute,
			RateLimitBanDuration: 15 * time.Minute,
		},
		MFA: config.MFAConfig{
			Issuer:           "Contract Test",
			ActiveKeyVersion: "v1",
			EncryptionKeys: map[string][]byte{
				"v1": []byte("contract-test-mfa-key-32-bytes00"),
			},
			ChallengeTTL:      5 * time.Minute,
			MaxAttempts:       5,
			RecoveryCodeCount: 10,
		},
	}
}

func newContractRedis(t *testing.T) *redis.Client {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Protocol:        2,
		DisableIdentity: true,
		PoolSize:        1,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go serveRedisConnection(serverConn)
			return clientConn, nil
		},
	})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close contract Redis client: %v", err)
		}
	})
	return client
}

func serveRedisConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	inTransaction := false
	queuedCommands := 0

	for {
		command, err := readRedisCommand(reader)
		if err != nil {
			return
		}

		switch strings.ToUpper(command[0]) {
		case "HELLO":
			_, err = writer.WriteString("*2\r\n$5\r\nproto\r\n:2\r\n")
		case "PING":
			_, err = writer.WriteString("+PONG\r\n")
		case "EVALSHA", "EVAL":
			_, err = writer.WriteString("*2\r\n:0\r\n:0\r\n")
		case "EXISTS":
			_, err = writer.WriteString(":0\r\n")
		case "MULTI":
			inTransaction = true
			queuedCommands = 0
			_, err = writer.WriteString("+OK\r\n")
		case "EXEC":
			_, err = writer.WriteString("*" + strconv.Itoa(queuedCommands) + "\r\n")
			for i := 0; i < queuedCommands; i++ {
				_, err = writer.WriteString(":1\r\n")
				if err != nil {
					break
				}
			}
			inTransaction = false
		default:
			if inTransaction {
				queuedCommands++
				_, err = writer.WriteString("+QUEUED\r\n")
			} else {
				_, err = writer.WriteString("+OK\r\n")
			}
		}
		if err != nil || writer.Flush() != nil {
			return
		}
	}
}

func readRedisCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 4 || line[0] != '*' {
		return nil, fmt.Errorf("invalid RESP array %q", line)
	}

	count, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, fmt.Errorf("parse RESP array length: %w", err)
	}

	command := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lengthLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(lengthLine) < 4 || lengthLine[0] != '$' {
			return nil, fmt.Errorf("invalid RESP bulk length %q", lengthLine)
		}
		length, err := strconv.Atoi(strings.TrimSpace(lengthLine[1:]))
		if err != nil {
			return nil, fmt.Errorf("parse RESP bulk length: %w", err)
		}

		value := make([]byte, length+2)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		command = append(command, string(value[:length]))
	}
	if len(command) == 0 {
		return nil, fmt.Errorf("empty RESP command")
	}
	return command, nil
}
