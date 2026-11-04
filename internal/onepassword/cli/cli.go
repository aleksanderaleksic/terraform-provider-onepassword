// Package cli runs the 1Password CLI (op) for operations the 1Password SDK
// does not offer, such as managing Connect servers. It only works with a user
// account signed in through the 1Password desktop app: service accounts and
// Connect credentials can't manage Connect servers.
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when op reports that the requested object does not exist.
var ErrNotFound = errors.New("not found")

// Runner runs op in dir and returns its standard output.
type Runner interface {
	Run(ctx context.Context, dir string, args ...string) ([]byte, error)
}

// ExecRunner runs the op binary as the given account.
type ExecRunner struct {
	Binary  string
	Account string
}

// NewExecRunner finds op on PATH.
func NewExecRunner(account string) (*ExecRunner, error) {
	binary, err := exec.LookPath("op")
	if err != nil {
		return nil, fmt.Errorf("the 1Password CLI (op) was not found on PATH: %w", err)
	}
	return &ExecRunner{Binary: binary, Account: account}, nil
}

func (r *ExecRunner) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.Binary, append(args, "--account", r.Account)...)
	cmd.Dir = dir
	// Sign in as the account's user, never as a service account or through
	// Connect credentials that happen to be in the environment.
	cmd.Env = withoutEnv(os.Environ(), "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Standard output is left out of the error: it can hold credentials.
		return nil, opError(args, stderr.String(), err)
	}
	return stdout.Bytes(), nil
}

func withoutEnv(env []string, names ...string) []string {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		drop := false
		for _, n := range names {
			if name == n {
				drop = true
				break
			}
		}
		if !drop {
			result = append(result, entry)
		}
	}
	return result
}

// opError turns op's standard error into an error, and into ErrNotFound when
// op says the object does not exist.
func opError(args []string, stderr string, err error) error {
	message := strings.TrimSpace(stderr)
	// op prefixes its messages with "[ERROR] <date> <time> ".
	if strings.HasPrefix(message, "[ERROR]") {
		if fields := strings.SplitN(message, " ", 4); len(fields) == 4 {
			message = fields[3]
		}
	}
	if message == "" {
		message = err.Error()
	}

	command := "op " + strings.Join(commandWords(args), " ")
	if isNotFound(message) {
		return fmt.Errorf("%s: %s: %w", command, message, ErrNotFound)
	}
	return fmt.Errorf("%s: %s", command, message)
}

// commandWords are the leading words of args before the first flag or
// argument that names an object, so errors don't echo names or values.
func commandWords(args []string) []string {
	var words []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || len(words) == 3 {
			break
		}
		words = append(words, arg)
	}
	return words
}

func isNotFound(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "there are 0 ") ||
		strings.Contains(lower, "isn't a") ||
		strings.Contains(lower, "not found")
}
