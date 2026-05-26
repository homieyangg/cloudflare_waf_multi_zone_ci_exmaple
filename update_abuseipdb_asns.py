import requests
import yaml
import os

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CLOUDFLARE_API_TOKEN = os.getenv("TF_VAR_cloudflare_api_token")
OUTPUT_FILE = "rules.yaml"
MAX_ASNS = 50

# Zone IDs - 動態從 terraform.tfvars 讀取以確保一致性
def load_zone_ids_from_tfvars():
    """從 terraform.tfvars 文件讀取 zone_ids"""
    try:
        zone_ids = {}
        with open('terraform.tfvars', 'r') as f:
            content = f.read()

        # 簡單解析 terraform.tfvars 中的 zone_ids
        import re

        # 先剝掉註解（# 之後到行尾），否則被註解掉的 zone 仍會被下面的 regex 撈到，
        # 與 terraform 實際納管的 zone 不一致（terraform 會正確忽略註解）。
        content = re.sub(r'#.*', '', content)

        # 匹配 zone_ids 區塊
        zone_block_pattern = r'zone_ids\s*=\s*\{([^}]+)\}'
        zone_block_match = re.search(zone_block_pattern, content, re.DOTALL)

        if zone_block_match:
            zone_block_content = zone_block_match.group(1)
            # 匹配每個 zone 條目
            zone_pattern = r'"([^"]+)"\s*=\s*"([^"]+)"'
            matches = re.findall(zone_pattern, zone_block_content)

            for domain, zone_id in matches:
                zone_ids[domain] = zone_id

        if zone_ids:
            print(f"📋 Loaded {len(zone_ids)} zones from terraform.tfvars:")
            for domain, zone_id in zone_ids.items():
                print(f"   {domain}: {zone_id}")
        else:
            print("⚠️ No zone_ids found in terraform.tfvars")

        return zone_ids
    except FileNotFoundError:
        print("❌ terraform.tfvars file not found")
        print("Please ensure terraform.tfvars exists with zone_ids configuration")
        return {}
    except Exception as e:
        print(f"❌ Error reading terraform.tfvars: {e}")
        print("Please check terraform.tfvars format")
        return {}

# 動態載入 Zone IDs
ZONE_IDS = load_zone_ids_from_tfvars()

def get_known_bad_asns():
    """
    返回一個精選的已知惡意 ASN 列表
    這些 ASN 是根據安全研究、威脅情報和公開資料確定的
    """
    return [
        # 俄羅斯相關的高風險 ASN
        197695,  # "Domain names registrar REG.RU", Ltd
        49505,   # OOO "Network of data-centers "Selectel"
        201776,  # Miranda-Media Ltd
        202425,  # IP Volume inc
        49392,   # Pptechnology Limited
        44812,   # PC Dome
        202422,  # Paltel

        # 歐洲高風險託管商
        49981,   # WorldStream B.V. (荷蘭)
        60068,   # Datacamp Limited (英國)
        44901,   # Belcloud Ltd (比利時)
        51167,   # Contabo GmbH (德國)
        200000,  # Hosting concepts B.V. d/b/a Openprovider (荷蘭)

        # 其他已知問題 ASN
        208091,  # Hydra Communications Ltd
        202448,  # MVPS LTD
        63949,   # Linode (部分濫用)
        16276,   # OVH SAS (部分濫用)
        24940,   # Hetzner Online GmbH (部分濫用)

        # 中國大陸可疑 ASN (根據需要調整)
        45090,   # Shenzhen Tencent Computer Systems Company Limited
        37963,   # Hangzhou Alibaba Advertising Co.,Ltd.

        # 美國可疑 ASN
        20473,   # AS-CHOOPA (Vultr)
        14061,   # DigitalOcean, LLC

        # 其他國家可疑 ASN
        9009,    # M247 Ltd (羅馬尼亞/英國)
        35913,   # DediPath (美國)

        # 新增的高風險 ASN
        31034,   # Aruba S.p.A. (義大利)
        8100,    # QuadraNet Enterprises LLC (美國)
        46844,   # ST-BGP (新加坡)

        # VPN/代理服務商 ASN
        40676,   # Psychz Networks (美國)
        53667,   # FranTech Solutions (美國)

        # 最近發現的問題 ASN
        209605,  # UAB Host Baltic (立陶宛)
        212238,  # Datacamp Limited (英國)

        # 加密貨幣挖礦相關
        29802,   # HVC-AS (荷蘭)

        # 殭屍網絡相關
        48693,   # University of Dubuque (美國，經常被濫用)
    ]

def fetch_abuseipdb_asns():
    """
    獲取惡意 ASN 列表
    優先嘗試 AbuseIPDB API，失敗時回退到靜態列表
    """
    if not ABUSEIPDB_API_KEY:
        print("No AbuseIPDB API key provided, using static ASN list")
        return get_known_bad_asns()[:MAX_ASNS]

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    try:
        print("🔍 Attempting to fetch data from AbuseIPDB API...")

        # 嘗試獲取黑名單數據
        response = requests.get("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100", headers=headers)

        if response.status_code == 200:
            print("✅ AbuseIPDB API call successful!")
            data = response.json()

            if "data" in data and len(data["data"]) > 0:
                print(f"📊 Received {len(data['data'])} entries from AbuseIPDB")

                # 分析 AbuseIPDB 數據中的國家分布
                print("🔍 Analyzing AbuseIPDB threat intelligence...")
                country_stats = {}

                for entry in data["data"]:
                    country = entry.get("countryCode", "Unknown")
                    country_stats[country] = country_stats.get(country, 0) + 1

                print("🌍 Top countries in AbuseIPDB blacklist:")
                sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:10]
                for country, count in sorted_countries:
                    print(f"   {country}: {count} IPs")

                # 基於威脅情報動態調整 ASN 列表
                print("🔄 Combining AbuseIPDB intelligence with curated ASN list...")
                static_asns = get_known_bad_asns()

                # 根據當前威脅情報添加額外的高風險 ASN（只添加已知的惡意/可疑 ASN）
                additional_asns = []

                # 如果美國在威脅列表前列，添加更多美國的可疑託管商 ASN
                if "US" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        35913,   # DediPath (已在靜態列表中)
                        40676,   # Psychz Networks (已在靜態列表中)
                        53667,   # FranTech Solutions (已在靜態列表中)
                        19531,   # Psychz Networks
                        46562,   # Total Server Solutions L.L.C.
                        62904,   # Eonix Corporation
                        26496,   # AS-26496-GO-DADDY-COM-LLC
                    ])

                # 如果中國在威脅列表前列，添加更多中國的可疑 ASN（避免主要 ISP）
                if "CN" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        45090,   # Shenzhen Tencent (已在靜態列表中)
                        37963,   # Hangzhou Alibaba (已在靜態列表中)
                        55990,   # Hwclouds-as-ap Huawei International
                        132203,  # Tencent Building, Kejizhongyi Avenue
                        38365,   # Beijing Baidu Netcom Science and Technology Co., Ltd.
                    ])

                # 如果荷蘭在威脅列表前列，添加更多荷蘭的可疑託管商 ASN
                if "NL" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        49981,   # WorldStream B.V. (已在靜態列表中)
                        212238,  # Datacamp Limited (已在靜態列表中)
                        60781,   # LeaseWeb Netherlands B.V.
                        16265,   # LeaseWeb Netherlands B.V.
                        60404,   # Liteserver Holding B.V.
                        206264,  # Amarutu Technology Ltd
                    ])

                # 如果德國在威脅列表前列，添加更多德國的可疑託管商 ASN
                if "DE" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        24940,   # Hetzner Online GmbH (已在靜態列表中)
                        51167,   # Contabo GmbH (已在靜態列表中)
                        197540,  # netcup GmbH
                        61317,   # Digital Energy Technologies Chile SpA
                        48314,   # Michael Sebastian Schinzel trading as IP-Projects GmbH & Co. KG
                    ])

                # 如果俄羅斯相關威脅增加，添加更多俄羅斯 ASN
                if "RU" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        197695,  # REG.RU (已在靜態列表中)
                        49505,   # Selectel (已在靜態列表中)
                        201776,  # Miranda-Media Ltd (已在靜態列表中)
                        25513,   # Moscow Local Telephone Network (OAO MGTS)
                        31133,   # PJSC MegaFon
                        42610,   # Rostelecom networks
                    ])

                # 合併所有 ASN 並去重
                all_asns = list(set(static_asns + additional_asns))

                print(f"📊 Static ASN list: {len(static_asns)} ASNs")
                print(f"📊 Threat-based additional ASNs: {len(set(additional_asns))} ASNs")
                print(f"📊 Combined unique ASNs: {len(all_asns)} ASNs")

                # 如果俄羅斯、中國等高風險國家在前列，優先使用相關 ASN
                high_risk_countries = ["RU", "CN", "KP", "IR"]
                if any(country in [c[0] for c in sorted_countries[:5]] for country in high_risk_countries):
                    print("⚠️  High-risk countries detected in current threats, prioritizing related ASNs")

                # 使用前 MAX_ASNS 個 ASN
                selected_asns = all_asns[:MAX_ASNS]
                print(f"✅ Using {len(selected_asns)} ASNs based on AbuseIPDB intelligence + static list")

                if additional_asns:
                    new_asns = [asn for asn in additional_asns if asn not in static_asns]
                    if new_asns:
                        print(f"🆕 New threat-based ASNs added: {sorted(list(set(new_asns)))}")

                return selected_asns
            else:
                print("⚠️  AbuseIPDB returned empty data, falling back to static list")
                return get_known_bad_asns()[:MAX_ASNS]

        elif response.status_code == 429:
            print("⚠️  AbuseIPDB API rate limit exceeded (429)")
            print("🔄 Falling back to static ASN list to maintain protection")
            return get_known_bad_asns()[:MAX_ASNS]

        elif response.status_code == 401:
            print("❌ AbuseIPDB API authentication failed (401)")
            print("🔄 Falling back to static ASN list")
            return get_known_bad_asns()[:MAX_ASNS]

        else:
            print(f"⚠️  AbuseIPDB API error: {response.status_code}")
            print(f"Response: {response.text[:200]}...")
            print("🔄 Falling back to static ASN list")
            return get_known_bad_asns()[:MAX_ASNS]

    except requests.exceptions.RequestException as e:
        print(f"🌐 Network error connecting to AbuseIPDB: {e}")
        print("🔄 Falling back to static ASN list")
        return get_known_bad_asns()[:MAX_ASNS]

    except Exception as e:
        print(f"❌ Unexpected error with AbuseIPDB API: {e}")
        print("🔄 Falling back to static ASN list")
        return get_known_bad_asns()[:MAX_ASNS]

def update_rules_yaml(asns):
    """就地更新 ASN block 規則的 expression，保留規則順序與其他規則不動。

    重要：不可像舊版那樣「移除後 insert(0)」——那會把 ASN 規則插到最前面，
    壓過最高優先的「Allow EZLO Self Infrastructure」skip 規則，導致自家流量
    在 skip 生效前就被 ASN 規則攔下（會把自家/白名單流量也擋掉）。
    """
    if not asns:
        print("⚠️  No ASN data available, leaving existing ASN rule untouched")
        return

    with open(OUTPUT_FILE, 'r') as f:
        data = yaml.safe_load(f)

    new_expression = f"(ip.geoip.asnum in {{{' '.join(map(str, asns))}}})"

    asn_rule_found = False
    for rule in data["rules"]:
        if "ASN" in rule.get("name", ""):
            rule["expression"] = new_expression
            asn_rule_found = True
            print(f"✏️  Updated ASN rule expression in place with {len(asns)} ASNs")
            break

    # 找不到既有 ASN 規則才新增（放在第一個 block 規則的位置：跳過開頭的 skip 規則）
    if not asn_rule_found:
        insert_at = next(
            (i for i, r in enumerate(data["rules"]) if r.get("action") != "skip"),
            len(data["rules"]),
        )
        data["rules"].insert(insert_at, {
            "name": "Block Known Bad ASNs (AbuseIPDB)",
            "action": "block",
            "expression": new_expression,
        })
        print(f"➕ Inserted new ASN rule at index {insert_at} with {len(asns)} ASNs")

    with open(OUTPUT_FILE, 'w') as f:
        yaml.dump(data, f, sort_keys=False, allow_unicode=True)

def get_zone_rulesets(zone_id):
    """獲取指定 zone 的所有 ruleset"""
    if not CLOUDFLARE_API_TOKEN:
        print("Warning: CLOUDFLARE_API_TOKEN not found, skipping ruleset cleanup")
        return []

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # 會在 HTTP 錯誤時拋出異常
        return response.json().get("result", [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching rulesets for zone {zone_id}: {e}")
        return []

IMPORT_TARGETS_FILE = "import_targets.txt"

def emit_import_targets():
    """探查每個 zone 現有的 http_request_firewall_custom (kind=zone) ruleset id，
    寫出 terraform import 目標到 IMPORT_TARGETS_FILE，供 workflow 在 apply 前把現有
    ruleset import 進當次 state，達成 in-place update（零無防護空窗）。

    取代舊版 cleanup_existing_rulesets() 的「先 DELETE 再重建」——後者每次跑都有
    短暫無 custom WAF 的空窗、且會抹掉任何手動規則。改成 import 後純 in-place 更新。

    每行格式：  <terraform_address>\t<import_id>
    例：       cloudflare_ruleset.waf_ruleset["example.com"]\tzones/<zone_id>/<ruleset_id>

    某 zone 若還沒有 entry point ruleset（全新 zone），就不寫該行 → terraform 會自行 create。
    """
    # 每次重寫，避免殘留上次的目標
    open(IMPORT_TARGETS_FILE, "w").close()

    if not CLOUDFLARE_API_TOKEN:
        print("⚠️ No Cloudflare API token — skipping import-target discovery")
        print("   terraform 會嘗試 create；若 zone 已有 ruleset 會衝突。請設定 TF_VAR_cloudflare_api_token")
        return

    if not ZONE_IDS:
        print("❌ No zone IDs loaded from terraform.tfvars — nothing to discover")
        return

    print("\n🔍 Discovering existing entry-point rulesets for in-place import...")
    lines = []
    for zone_name, zone_id in ZONE_IDS.items():
        print(f"\n📍 Zone: {zone_name} ({zone_id})")
        rulesets = get_zone_rulesets(zone_id)
        entry_points = [
            rs for rs in rulesets
            if rs.get("phase") == "http_request_firewall_custom" and rs.get("kind") == "zone"
        ]
        if not entry_points:
            print("  ➕ No existing entry-point ruleset — terraform will create it")
            continue

        ruleset_id = entry_points[0]["id"]
        address = f'cloudflare_ruleset.waf_ruleset["{zone_name}"]'
        import_id = f"zones/{zone_id}/{ruleset_id}"
        lines.append(f"{address}\t{import_id}")
        print(f"  📌 Import target: {address}  ->  {import_id}")

    with open(IMPORT_TARGETS_FILE, "w") as f:
        f.write("\n".join(lines))
        if lines:
            f.write("\n")
    print(f"\n📝 Wrote {len(lines)} import target(s) to {IMPORT_TARGETS_FILE}")

def verify_api_tokens():
    """驗證 API Token 是否有效"""
    # 驗證 Cloudflare API Token
    if not CLOUDFLARE_API_TOKEN:
        print("⚠️ Warning: CLOUDFLARE_API_TOKEN not set")
        print("Ruleset cleanup and deployment will be skipped")
    else:
        print("✅ CLOUDFLARE_API_TOKEN is set")

        # 簡單測試 Cloudflare API Token
        for zone_name, zone_id in ZONE_IDS.items():
            headers = {
                "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
                "Content-Type": "application/json"
            }

            url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    print(f"  ✅ Successfully verified access to zone: {zone_name}")
                else:
                    print(f"  ❌ Failed to access zone {zone_name}: HTTP {response.status_code}")
                    print(f"     Response: {response.text[:200]}...")
            except Exception as e:
                print(f"  ❌ Error testing Cloudflare API for zone {zone_name}: {e}")

    # 驗證 AbuseIPDB API Key
    if not ABUSEIPDB_API_KEY:
        print("⚠️ Warning: ABUSEIPDB_API_KEY not set")
        print("Will use static ASN list instead")
    else:
        print("✅ ABUSEIPDB_API_KEY is set")

if __name__ == "__main__":
    print("🚀 Starting WAF ruleset update process...")

    # 驗證 API Token
    verify_api_tokens()

    # 探查現有 ruleset，寫出 terraform import 目標（取代舊的 delete-then-recreate）
    emit_import_targets()

    print("\n📊 Fetching AbuseIPDB ASN blacklist...")
    asns = fetch_abuseipdb_asns()
    print(f"✅ Fetched {len(asns)} unique ASNs.")

    # 更新 rules.yaml
    update_rules_yaml(asns)
    print(f"📝 Updated {OUTPUT_FILE} successfully.")

    print("\n✨ Process completed successfully!")
