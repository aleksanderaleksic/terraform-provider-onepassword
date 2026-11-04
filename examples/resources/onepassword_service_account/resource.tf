data "onepassword_vault" "admin" {
  name = "Infrastructure admin"
}

data "onepassword_vault" "deploy" {
  name = "Deploy secrets"
}

resource "onepassword_service_account" "ci" {
  name       = "ci"
  expires_in = "90d"

  vaults = [
    { id = data.onepassword_vault.deploy.uuid, permissions = ["read_items"] },
  ]

  token_vault = data.onepassword_vault.admin.uuid
  token_title = "ci service account token"

  # Destroying only deletes the token item; the service account itself has to
  # be deleted in the 1Password web interface.
  lifecycle {
    prevent_destroy = true
  }
}
