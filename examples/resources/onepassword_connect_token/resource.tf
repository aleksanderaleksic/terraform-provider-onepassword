resource "onepassword_connect_token" "operator" {
  server_id = onepassword_connect_server.cluster.id
  name      = "operator"

  vaults = [
    { id = onepassword_vault.cluster.uuid, access = "read" },
  ]
  expires_in = "90d"

  token_vault = data.onepassword_vault.admin.uuid
  token_title = "production-cluster Connect operator token"
}

ephemeral "onepassword_item" "operator_token" {
  vault = data.onepassword_vault.admin.uuid
  uuid  = onepassword_connect_token.operator.token_item_id
}

locals {
  operator_token = ephemeral.onepassword_item.operator_token.section_map["Connect token"].field_map["token"].value
}
