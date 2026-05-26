# Cloudflare WAF Auto-Update (Terraform + AbuseIPDB)

English | [繁體中文](./README_zh-TW.md) | [简体中文](./README_zh-CN.md)

GitHub Actions keeps a set of Cloudflare WAF custom rules in sync for your zones.
It pulls bad ASNs from AbuseIPDB daily to refresh the blocklist, while allowing
normal traffic like search engines and uptime monitors. Manage multiple zones
from a single `rules.yaml`.

## How it works

GitHub Actions (daily at 03:00 UTC + on push to main + manual dispatch) runs:

1. `update_abuseipdb_asns.py` — refreshes the ASN list in `rules.yaml`, and discovers each zone's existing ruleset id into `import_targets.txt`
2. `terraform import` — pulls the existing ruleset into state
3. `terraform apply` — **in-place update**, no destroy/recreate, so there's no window where the zone is left unprotected

> The earlier version did "DELETE the whole ruleset, then recreate". That left a brief unprotected gap on every run and wiped any manual edits. Import → apply is much cleaner.

## Usage

**1. Fork this repo.**

**2. Set two GitHub Secrets** (Settings → Secrets and variables → Actions):

| Name | What it's for |
|---|---|
| `CLOUDFLARE_API_TOKEN` | API Token with **Zone : WAF : Edit**. A token can only manage zones in the account it belongs to — don't add zones from another account. Leave Client IP filtering empty, or it'll block the runner. |
| `ABUSEIPDB_API_KEY` | Optional. Without it the script falls back to a built-in static ASN list; everything else still works. |

**3. Edit `terraform.tfvars`** with your own zones (domain = zone id; find the zone id at the bottom-right of the domain's Overview page in the CF dashboard):

```hcl
zone_ids = {
  "yourdomain.com" = "your_zone_id"
}
```

**4. Push it.** Actions runs automatically. You can also dispatch it manually from the Actions tab.

## Editing rules

Everything lives in `rules.yaml`; top-to-bottom is the priority order. Five rules by default:

1. **Allow Trusted Infrastructure** — allow your own IPs (server / CI / monitoring). **Replace the example IPs with your own first** — otherwise the day your own traffic gets caught by the rules below, you lock yourself out.
2. **Block Known Bad ASNs** — bad-ASN blocklist (this rule's expression is rewritten by the script on every run, so editing it by hand is pointless).
3. **Allow Essential Legitimate Services** — allow Googlebot, UptimeRobot, etc.
4. **Block Malicious Traffic & Exploit Probes** — block scanner UAs + exploit paths.
5. **Challenge High Threat Score Traffic** — managed challenge for high threat scores.

A `skip` rule can take `skip_current_ruleset: true` (skip all remaining custom rules) and `products` (which managed products to skip).

> Heads-up: **don't use a "challenge all overseas traffic" country rule**. If your site is a SPA + API, a managed challenge breaks the frontend's XHR / preflight and locks out overseas users entirely. Use something like `threat_score` instead.

## Review the plan locally first (recommended)

Don't let CI blindly apply to a live site — eyeball the diff once:

```bash
export TF_VAR_cloudflare_api_token="your_token"   # in your terminal only, don't paste it anywhere
python update_abuseipdb_asns.py
terraform init
while IFS=$'\t' read -r a id; do terraform import "$a" "$id"; done < import_targets.txt
terraform plan    # confirm it's in-place, no destroy/recreate
```

If the plan is clean, `terraform apply` or merge.

## Troubleshooting

- **apply 403 `code 10000`**: usually not a bad token — it's a zone in `tfvars` that **isn't in this token's account**. Remove that zone.
- **Is the token alive?** `curl -s https://api.cloudflare.com/client/v4/user/tokens/verify -H "Authorization: Bearer $TF_VAR_cloudflare_api_token"`
- **Legit service getting blocked**: add its UA to rule 3, `Allow Essential Legitimate Services`.
