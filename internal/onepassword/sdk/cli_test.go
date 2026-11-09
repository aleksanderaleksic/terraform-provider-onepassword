package sdk

import (
	"strings"
	"testing"
)

func TestCLIRequiresDesktopAppAuthentication(t *testing.T) {
	client := &Client{config: SDKConfig{ServiceAccountToken: "ops_test"}}
	if _, err := client.CLI(); err == nil || !strings.Contains(err.Error(), "desktop app authentication") {
		t.Errorf("expected a desktop app authentication error, got %v", err)
	}
}
