data "onepassword_group" "developers" {
  name = "Developers"
}

resource "onepassword_vault" "example" {
  name        = "Terraform managed vault"
  description = "Managed by Terraform"

  group_permissions {
    group_id = data.onepassword_group.developers.uuid
    permissions = [
      "read_items",
      "reveal_item_password",
      "create_items",
      "update_items",
    ]
  }

  group_permissions {
    group_id    = "3gjoowf6ofrcjldq5z7v6h3cde"
    permissions = ["read_items"]
  }

  # Destroying a vault deletes every item in it.
  lifecycle {
    prevent_destroy = true
  }
}
