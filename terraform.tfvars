# cloudflare_api_token 走環境變數 TF_VAR_cloudflare_api_token（從 GitHub Secrets 進來）
# 不要把 token 寫在這個檔案裡。

# 填你自己的 zone（域名 = zone id）。zone id 在 CF dashboard 該網域 Overview 右下角。
# 一把 token 只能管它所屬「帳號」底下的 zone——別把別帳號的 zone 放進來，否則那條 apply 會 403。
zone_ids = {
  "example.com" = "0000000000000000000000000000aaaa"
  "example.org" = "0000000000000000000000000000bbbb"
}
