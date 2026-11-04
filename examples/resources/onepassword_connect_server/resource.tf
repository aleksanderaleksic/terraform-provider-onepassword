data "onepassword_vault" "admin" {
  name = "Infrastructure admin"
}

resource "onepassword_vault" "cluster" {
  name = "production-cluster"

  lifecycle {
    prevent_destroy = true
  }
}

# One Connect server per cluster, with access to that cluster's vault. Its
# credentials go to an item in a vault only administrators can open.
resource "onepassword_connect_server" "cluster" {
  name              = "production-cluster"
  vaults            = [onepassword_vault.cluster.uuid]
  credentials_vault = data.onepassword_vault.admin.uuid
  credentials_title = "production-cluster Connect credentials"
}

# Read the credentials file where 1Password Connect is installed, without
# storing it in state.
ephemeral "onepassword_item" "connect_credentials" {
  vault = data.onepassword_vault.admin.uuid
  uuid  = onepassword_connect_server.cluster.credentials_item_id
}

locals {
  connect_credentials = ephemeral.onepassword_item.connect_credentials.section_map["Connect server"].field_map["credentials"].value
}
