# Azure Front Door WAF Architecture & Defense-in-Depth Specification

**Author:** Member 4 — Azure Solutions Architect & Cloud Security Engineer  
**Azure Service:** Azure Front Door Premium + Web Application Firewall (WAF)  
**Security Standard:** OWASP Core Rule Set (CRS 3.2) / Microsoft Threat Intelligence  

---

## 1. Overview & Edge Security Architecture

Azure Front Door (AFD) Premium acts as the **global perimeter gateway** and layer-7 ingress controller for SecureShare. By positioning the Web Application Firewall at Microsoft's global edge network (over 180 points of presence), malicious requests, volumetric DDoS attacks, and OWASP exploits are intercepted and dropped before they ever reach the backend Azure App Service origin.

```mermaid
flowchart LR
    User["Public Internet Traffic"] --> AFD["Azure Front Door (Edge PoP)"]
    
    subgraph "AFD WAF Engine"
        AFD --> GeoCheck["1. Geo-Filtering (Country Code Policy)"]
        GeoCheck --> RateLimit["2. Rate Limiting (Per-Client IP)"]
        RateLimit --> CustomRules["3. Custom IP & Header Filtering"]
        CustomRules --> ManagedRules["4. OWASP DRS 2.1 / Bot Manager"]
    end

    ManagedRules -->|Clean Inspected Traffic (Private Link)| Backend["Azure App Service (FastAPI)"]
    GeoCheck -.->|Blocked| Block403["403 Forbidden Edge Drop"]
    RateLimit -.->|Exceeded| Block429["429 Too Many Requests"]
    ManagedRules -.->|Exploit Match| BlockWAF["403 WAF Blocked"]
```

---

## 2. WAF Policy Architecture

SecureShare specifies a multi-layered WAF policy combining **Managed Rules** and **Custom Rules**:

### 2.1 Managed Rule Sets (OWASP CRS)
1. **DefaultRuleSet 2.1 (DRS 2.1 / OWASP CRS 3.2):**
   - **SQL Injection (SQLi):** Intercepts classic, boolean, and union-based injection strings in query parameters, headers, and form bodies.
   - **Cross-Site Scripting (XSS):** Blocks reflected, stored, and DOM-based `<script>` injections.
   - **Remote Code Execution (RCE):** Blocks OS command injections and reverse shell payloads.
   - **Local File Inclusion (LFI / Path Traversal):** Blocks `../` directory traversal attempts.
2. **Microsoft_BotManagerRuleSet 1.0:**
   - Detects malicious crawlers, credential-stuffing botnets, and automated scrapers based on Microsoft Threat Intelligence telemetry.

---

### 2.2 Custom Security Rules

#### A. Geo-Blocking Policy (`CustomRule-GeoBlock`)
- **Action:** `Block`
- **Condition:** Match Variable `RemoteAddr`. Operator `GeoMatch`.
- **Allowed Regions:** Configured to restrict administrative and API traffic to authorized operating territories (e.g. US, IN, EU) while blocking high-risk embargoed jurisdictions.

#### B. Per-Client IP Rate Limiting (`CustomRule-RateLimit`)
- **Action:** `Block` (Returns HTTP 429)
- **Threshold:** `100 requests per 1 minute` per client IP across general routes; `10 requests per minute` on `/api/v1/auth/*`.
- **Duration:** 1-minute sliding window.

#### C. Enterprise Security Header Enforcement (`CustomRule-HeaderValidation`)
- **Action:** `Block`
- **Rule:** Rejects requests with missing or spoofed `Host` headers or payload sizes exceeding 25MB before file upload processing begins.

---

## 3. Deployment & Provisioning Steps (Azure CLI)

Because the test subscription has service restrictions, the deployment steps are provided for execution when transitioning to enterprise subscriptions:

```bash
# 1. Create Azure Front Door Profile (Premium Tier required for Managed WAF & Private Link)
az afd profile create \
  --profile-name "afd-secureshare-prod" \
  --resource-group "rg-secureshare-prod" \
  --sku "Premium_AzureFrontDoor"

# 2. Create WAF Policy in Prevention Mode
az network front-door waf-policy create \
  --name "wafsecureshareprod" \
  --resource-group "rg-secureshare-prod" \
  --sku "Premium_AzureFrontDoor" \
  --mode "Prevention"

# 3. Enable OWASP Default Rule Set (DRS 2.1)
az network front-door waf-policy managed-rules add \
  --policy-name "wafsecureshareprod" \
  --resource-group "rg-secureshare-prod" \
  --type "DefaultRuleSet" \
  --version "2.1"

# 4. Enable Microsoft Bot Manager Rule Set
az network front-door waf-policy managed-rules add \
  --policy-name "wafsecureshareprod" \
  --resource-group "rg-secureshare-prod" \
  --type "Microsoft_BotManagerRuleSet" \
  --version "1.0"

# 5. Add Custom Rate Limiting Rule
az network front-door waf-policy custom-rule create \
  --policy-name "wafsecureshareprod" \
  --resource-group "rg-secureshare-prod" \
  --name "RateLimitPerIP" \
  --priority 10 \
  --rule-type "RateLimitRule" \
  --action "Block" \
  --rate-limit-duration-in-minutes 1 \
  --rate-limit-threshold 100

# 6. Associate WAF Policy with Front Door Endpoint
az afd endpoint create \
  --endpoint-name "secureshare-gateway" \
  --profile-name "afd-secureshare-prod" \
  --resource-group "rg-secureshare-prod"
```

---

## 4. Origin Security & Private Link Integration

To ensure the backend App Service cannot be reached directly via its default `*.azurewebsites.net` URL (bypassing the WAF):
- **Access Restrictions:** The App Service is configured with IP access restrictions allowing only traffic from the Azure Front Door IP range (`AzureFrontDoor.Backend` service tag) or via Azure Private Link.
- **Header Verification:** App Service verifies the `X-Azure-FDID` (Front Door ID) header on every incoming request.
