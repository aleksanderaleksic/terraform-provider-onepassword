package sdk

import (
	"context"
	"errors"
	"testing"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
)

func TestCollectGroups(t *testing.T) {
	access := map[string][]string{
		"vault-a": {"owners", "developers"},
		"vault-b": {"owners", "admins"},
	}
	var reads []string
	groupIDsOf := func(_ context.Context, vaultID string) ([]string, error) {
		if vaultID == "hidden" {
			return nil, errors.New("not allowed to read access")
		}
		return access[vaultID], nil
	}
	getGroup := func(_ context.Context, groupID string) (*model.Group, error) {
		reads = append(reads, groupID)
		return &model.Group{ID: groupID}, nil
	}

	groups, err := collectGroups(context.Background(), []string{"vault-a", "hidden", "vault-b"}, groupIDsOf, getGroup)
	if err != nil {
		t.Fatal(err)
	}
	// Each group is read once, even when it has access to several vaults, and
	// a vault whose access can't be read is skipped.
	if len(groups) != 3 || len(reads) != 3 {
		t.Errorf("groups %+v from reads %v, expected owners, developers and admins once each", groups, reads)
	}
}

func TestCollectGroupsFailsWhenGroupCannotBeRead(t *testing.T) {
	groupIDsOf := func(_ context.Context, _ string) ([]string, error) {
		return []string{"broken"}, nil
	}
	getGroup := func(_ context.Context, _ string) (*model.Group, error) {
		return nil, errors.New("boom")
	}
	if _, err := collectGroups(context.Background(), []string{"vault"}, groupIDsOf, getGroup); err == nil {
		t.Error("expected the group read error")
	}
}

func TestGroupCacheScansOnce(t *testing.T) {
	scans := 0
	load := func(_ context.Context) ([]model.Group, error) {
		scans++
		return []model.Group{
			{ID: "devs", Name: "Developers"},
			{ID: "admins", Name: "Administrators"},
		}, nil
	}

	var cache groupCache
	for _, name := range []string{"Developers", "Administrators", "Nobody"} {
		found, err := cache.byName(context.Background(), name, load)
		if err != nil {
			t.Fatal(err)
		}
		if name == "Nobody" && len(found) != 0 || name != "Nobody" && (len(found) != 1 || found[0].Name != name) {
			t.Errorf("byName(%q) = %+v", name, found)
		}
	}
	if scans != 1 {
		t.Errorf("scanned %d times, expected once", scans)
	}
}

func TestGroupCacheRetriesAfterFailedScan(t *testing.T) {
	scans := 0
	load := func(_ context.Context) ([]model.Group, error) {
		scans++
		if scans == 1 {
			return nil, errors.New("temporary")
		}
		return []model.Group{{ID: "devs", Name: "Developers"}}, nil
	}

	var cache groupCache
	if _, err := cache.byName(context.Background(), "Developers", load); err == nil {
		t.Fatal("expected the first scan to fail")
	}
	found, err := cache.byName(context.Background(), "Developers", load)
	if err != nil || len(found) != 1 {
		t.Errorf("second lookup = %+v, %v, expected Developers", found, err)
	}
}
