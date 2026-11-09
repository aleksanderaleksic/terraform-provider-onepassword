package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeRunner answers op commands with canned output. The key is the command
// line without the account flag, joined by spaces.
type fakeRunner struct {
	outputs map[string]string
	errors  map[string]error
	calls   []string
	// files are written into the working directory when the command runs.
	files map[string]map[string]string
}

func (f *fakeRunner) Run(_ context.Context, dir string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	f.calls = append(f.calls, command)
	for name, content := range f.files[command] {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return nil, err
		}
	}
	if err, ok := f.errors[command]; ok {
		return nil, err
	}
	return []byte(f.outputs[command]), nil
}

func TestCreateConnectServer(t *testing.T) {
	runner := &fakeRunner{
		outputs: map[string]string{
			"connect server create ailab --vaults v1,v2": "Set up a Connect server.\nUUID: SERVER1\nCredentials file: /tmp/x/1password-credentials.json\n",
			"connect server get SERVER1 --format json":   `{"id":"SERVER1","name":"ailab","state":"ACTIVE"}`,
		},
		files: map[string]map[string]string{
			"connect server create ailab --vaults v1,v2": {CredentialsFileName: `{"verifier":{}}`},
		},
	}

	server, credentials, err := NewClient(runner).CreateConnectServer(context.Background(), "ailab", []string{"v1", "v2"})
	if err != nil {
		t.Fatal(err)
	}
	if server.ID != "SERVER1" || server.Name != "ailab" {
		t.Errorf("server = %+v", server)
	}
	if string(credentials) != `{"verifier":{}}` {
		t.Errorf("credentials = %q", credentials)
	}
}

func TestCreateConnectServerRemovesCredentialsFile(t *testing.T) {
	var dir string
	runner := &dirRecorder{fakeRunner: fakeRunner{
		outputs: map[string]string{
			"connect server create ailab":              "UUID: SERVER1\n",
			"connect server get SERVER1 --format json": `{"id":"SERVER1","name":"ailab"}`,
		},
		files: map[string]map[string]string{"connect server create ailab": {CredentialsFileName: "{}"}},
	}, dir: &dir}

	if _, _, err := NewClient(runner).CreateConnectServer(context.Background(), "ailab", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the directory with the credentials file still exists: %v", err)
	}
}

// dirRecorder remembers the working directory op was run in.
type dirRecorder struct {
	fakeRunner
	dir *string
}

func (d *dirRecorder) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	if dir != "" {
		*d.dir = dir
	}
	return d.fakeRunner.Run(ctx, dir, args...)
}

func TestCreateConnectServerWithoutCredentialsFile(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{"connect server create ailab": "UUID: SERVER1\n"}}
	_, _, err := NewClient(runner).CreateConnectServer(context.Background(), "ailab", nil)
	if err == nil || !strings.Contains(err.Error(), "SERVER1") {
		t.Errorf("expected an error naming the created server, got %v", err)
	}
}

func TestCreatedServerID(t *testing.T) {
	tests := map[string]string{
		"Set up a Connect server.\nUUID: ABC123\nCredentials file: x\n": "ABC123",
		`{"id":"ABC123","name":"ailab"}`:                                "ABC123",
		"something else":                                                "",
	}
	for output, expected := range tests {
		if actual := createdServerID([]byte(output)); actual != expected {
			t.Errorf("createdServerID(%q) = %q, expected %q", output, actual, expected)
		}
	}
}

func TestGetConnectServerNotFound(t *testing.T) {
	runner := &fakeRunner{errors: map[string]error{
		"connect server get GONE --format json": opError(
			[]string{"connect", "server", "get", "GONE"},
			`[ERROR] 2026/11/03 22:09:17 There are 0 servers that match "GONE". Try again and specify the servers's UUID instead.`,
			errors.New("exit status 1"),
		),
	}}
	_, err := NewClient(runner).GetConnectServer(context.Background(), "GONE")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestOpErrorHidesArgumentsAndDatePrefix(t *testing.T) {
	err := opError(
		[]string{"connect", "server", "create", "secret-name", "--vaults", "v1"},
		"[ERROR] 2026/11/03 22:08:12 (403) Forbidden: You aren't authorized to access this resource.\n",
		errors.New("exit status 1"),
	)
	if err.Error() != "op connect server create: (403) Forbidden: You aren't authorized to access this resource." {
		t.Errorf("error = %q", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a 403 is not a missing object")
	}
}

func TestVaultAccessCommands(t *testing.T) {
	runner := &fakeRunner{}
	client := NewClient(runner)
	ctx := context.Background()
	_ = client.GrantConnectServerVault(ctx, "S", "V1")
	_ = client.RevokeConnectServerVault(ctx, "S", "V2")
	_ = client.RenameConnectServer(ctx, "S", "new")
	_ = client.DeleteConnectServer(ctx, "S")

	expected := []string{
		"connect vault grant --server S --vault V1",
		"connect vault revoke --server S --vault V2",
		"connect server edit S --name new",
		"connect server delete S",
	}
	if !reflect.DeepEqual(runner.calls, expected) {
		t.Errorf("calls = %q", runner.calls)
	}
}

func TestWithoutEnv(t *testing.T) {
	env := withoutEnv([]string{"PATH=/bin", "OP_SERVICE_ACCOUNT_TOKEN=x", "OP_CONNECT_TOKEN=y", "OP_ACCOUNT=a"},
		"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN")
	if !reflect.DeepEqual(env, []string{"PATH=/bin", "OP_ACCOUNT=a"}) {
		t.Errorf("env = %q", env)
	}
}

func TestCreateConnectToken(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"connect token create operator --server S --vault V1 --vault V2,r --expires-in 90d": "eyJ-token\n",
		"connect token list --server S --format json": `[
			{"id":"OLD","name":"operator","state":"REVOKED"},
			{"id":"T1","name":"operator","state":"ACTIVE"},
			{"id":"T2","name":"other","state":"ACTIVE"}
		]`,
	}}

	token, value, err := NewClient(runner).CreateConnectToken(context.Background(), "S", "operator",
		[]ConnectTokenVault{{VaultID: "V1"}, {VaultID: "V2", Permission: "r"}}, "90d")
	if err != nil {
		t.Fatal(err)
	}
	if value != "eyJ-token" {
		t.Errorf("token value = %q", value)
	}
	if token.ID != "T1" {
		t.Errorf("token = %+v, expected the active T1, not the revoked OLD", token)
	}
}

func TestTokenCommands(t *testing.T) {
	runner := &fakeRunner{}
	client := NewClient(runner)
	_ = client.RenameConnectToken(context.Background(), "S", "T1", "new")
	_ = client.DeleteConnectToken(context.Background(), "S", "T1")
	expected := []string{
		"connect token edit T1 --server S --name new",
		"connect token delete T1 --server S",
	}
	if !reflect.DeepEqual(runner.calls, expected) {
		t.Errorf("calls = %q", runner.calls)
	}
}
