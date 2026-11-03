package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccGroupDataSourceRejectsConnect(t *testing.T) {
	for name, config := range map[string]string{
		"by uuid": `uuid = "erqj6ta7mfo3al4budn2thylri"`,
		"by name": `name = "Developers"`,
	} {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      testAccProviderConfig("http://127.0.0.1:1") + "\ndata \"onepassword_group\" \"test\" {\n  " + config + "\n}\n",
					ExpectError: regexp.MustCompile(`not available\s+with\s+1Password\s+Connect`),
				}},
			})
		})
	}
}
