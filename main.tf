terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

locals {
  config = yamldecode(file("${path.module}/rules.yaml"))
}

# 每個 zone 一個 http_request_firewall_custom 階段的 entry point ruleset（kind = "zone"）。
# 規則內容來自 rules.yaml；ASN block 那條由 update_abuseipdb_asns.py 就地更新。
#
# v5 重點：rules 是 list attribute（不是 v4 的 dynamic block）；action_parameters / logging
# 是 object（= {...}）而非 block。skip 規則才帶 action_parameters，其餘設 null。
resource "cloudflare_ruleset" "waf_ruleset" {
  for_each    = var.zone_ids
  zone_id     = each.value
  name        = "Terraform Managed WAF Rules"
  description = "WAF rules auto-updated from AbuseIPDB"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    for idx, rule in local.config.rules : {
      ref         = format("rule_%02d", idx)
      description = rule.name
      expression  = rule.expression
      action      = rule.action
      enabled     = true

      # 只有 skip 規則需要 action_parameters：
      #   products             → 跳過的受管產品（waf / bic / rateLimit ...）
      #   skip_current_ruleset → true 時跳過本 ruleset 其餘 custom rules（ruleset = "current"）
      action_parameters = rule.action == "skip" ? {
        products = lookup(rule, "products", null)
        ruleset  = lookup(rule, "skip_current_ruleset", false) ? "current" : null
      } : null

      logging = rule.action == "skip" ? {
        enabled = lookup(rule, "logging_enabled", true)
      } : null
    }
  ]
}
