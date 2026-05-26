# Cloudflare WAF 自動更新（Terraform + AbuseIPDB）

用 GitHub Actions 自動幫你的 Cloudflare zone 維護一組 WAF custom rules。
每天從 AbuseIPDB 抓壞 ASN 更新黑名單，順便放行搜尋引擎 / 監控這類正常服務。
多個 zone 可以一起管，規則寫在一個 `rules.yaml` 裡。

## 它怎麼跑

GitHub Actions（每天 03:00 UTC + push main + 手動）會做這幾步：

1. `update_abuseipdb_asns.py` → 更新 `rules.yaml` 的 ASN 清單，順便查出每個 zone 現有的 ruleset id 寫進 `import_targets.txt`
2. `terraform import` → 把現有 ruleset 拉進 state
3. `terraform apply` → **in-place 更新**，不會砍掉重建，所以沒有「中間一段沒防護」的空窗

> 早期版本是「先 DELETE 整個 ruleset 再重建」，每天都有短暫空窗、還會把手動改的規則洗掉。現在改成 import → apply，乾淨很多。

## 怎麼用

**1. Fork 這個 repo。**

**2. 設兩個 GitHub Secret**（Settings → Secrets and variables → Actions）：

| Name | 要幹嘛 |
|---|---|
| `CLOUDFLARE_API_TOKEN` | **Zone : WAF : Edit** 權限的 API Token。一把 token 只能管它所屬帳號的 zone，別放別帳號的進來。Client IP filtering 留空，不然會擋到 runner。 |
| `ABUSEIPDB_API_KEY` | 選用。沒設就用內建的靜態 ASN 清單，功能照常。 |

**3. 改 `terraform.tfvars`**，填你自己的 zone（域名 = zone id，dashboard 該網域 Overview 右下角找得到）：

```hcl
zone_ids = {
  "yourdomain.com" = "你的zone_id"
}
```

**4. push 上去**，Actions 會自己跑。也可以去 Actions 頁手動 dispatch。

## 改規則

全部在 `rules.yaml`，由上到下就是優先順序。預設五條：

1. **Allow Trusted Infrastructure** — 放行你自己的 IP（server / CI / 監控）。**先把這條的範例 IP 換成你自己的**，不然哪天自家流量被下面的規則掃到就把自己鎖在外面了。
2. **Block Known Bad ASNs** — 壞 ASN 黑名單（這條的 expression 每次跑會被腳本自動重寫，手改沒用）。
3. **Allow Essential Legitimate Services** — 放行 Googlebot、UptimeRobot 這類。
4. **Block Malicious Traffic & Exploit Probes** — 擋掃描工具 UA + 漏洞路徑。
5. **Challenge High Threat Score Traffic** — 高威脅分數丟 managed challenge。

`skip` 規則可以加 `skip_current_ruleset: true`（跳過後面所有 custom rules）跟 `products`（跳過哪些受管產品）。

> 小提醒：**別用「挑戰所有海外流量」那種國家規則**。如果你的站是 SPA + API，managed challenge 會卡死前端的 XHR / preflight，海外用戶直接進不來。用 `threat_score` 之類比較安全。

## 本機先看 plan（建議）

別讓 CI 盲 apply 到正式站，先本機看一次 diff：

```bash
export TF_VAR_cloudflare_api_token="你的token"   # 只在你終端機，別貼出去
python update_abuseipdb_asns.py
terraform init
while IFS=$'\t' read -r a id; do terraform import "$a" "$id"; done < import_targets.txt
terraform plan    # 確認是 in-place、沒有 destroy/recreate
```

plan 乾淨再 `terraform apply` 或 merge。

## 卡關時

- apply 403 `code 10000`：多半不是 token 壞，是 tfvars 裡有 zone **不在這把 token 的帳號**底下 → 拿掉那個 zone。
- token 到底活不活：`curl -s https://api.cloudflare.com/client/v4/user/tokens/verify -H "Authorization: Bearer $TF_VAR_cloudflare_api_token"`
- 正常服務被擋：把它的 UA 加進第三條 `Allow Essential Legitimate Services`。
