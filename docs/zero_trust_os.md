ini hasilnya .. (cd "$(git rev-parse --show-toplevel)" && git apply --3way <<'EOF' 
diff --git a/docs/zero_trust_os.md b/docs/zero_trust_os.md
new file mode 100644
index 0000000000000000000000000000000000000000..2d35809fbfe8bb45112b62bd3547f149c8f77f77
--- /dev/null
+++ b/docs/zero_trust_os.md
@@ -0,0 +1,397 @@
+# Zero-Trust Digital Infrastructure Compliance Operating System (Zer0light Mandiri)
+
+## Assumptions
+- Supabase project is already provisioned and reachable from the runtime environment.
+- Portal gateway (`zerolight.site`) can run a small Python API service with environment variables for Supabase credentials.
+- Production sites are primarily static and can be toggled via a status flag in the portal/gateway service plus web server routing rules.
+- All automation and bot activity is explicitly disclosed, rate-limited, and logged.
+
+## Step 1 — Minimal, lawful system design
+
+### High-level architecture (minimal, auditable)
+**Static frontends**
+- `zerolight.site` (portal UI + transparency pages)
+  - Static HTML/JS for public transparency dashboards, policy summaries, and legal pages.
+  - The portal **also** exposes backend API endpoints (see below) for zero-trust gating.
+- `semestaorbit.com` + `spiralstadion1a.web.id` to `spiralstadion7a.web.id`
+  - Static or static-first frontends (HTML/CSS/JS + server-side redirects) that can be published/unpublished.
+
+**Backend services**
+- **Portal gateway API** (`zerolight.site`)
+  - A small Python service (FastAPI suggested) that:
+    - Enforces zero-trust decisions for outbound redirects.
+    - Exposes read-only APIs for bots to query allowed domains and content.
+    - Exposes admin-only recalc endpoint to update domain status based on policies & metrics.
+
+**Data layer**
+- Supabase (PostgreSQL) is the authoritative datastore:
+  - Domain registry, policies, events (append-only), decisions, metrics.
+  - Auditability: append-only event and decision logs with timestamps and actor IDs.
+
+**Background jobs / workers**
+- **Policy evaluator job (cron)**
+  - Reads metrics + events, writes decisions, updates `domains.status`.
+- **Metrics aggregator job**
+  - Aggregates daily counters from raw events into `metrics_daily`.
+- **Bot queue/ratelimit job**
+  - Ensures posting schedule per channel respects limits and policy.
+
+### Compliance considerations
+- **Consent logging**: store consent for newsletters or downloadable assets in `events` (type `consent_recorded`).
+- **Affiliate disclosure**: store event `affiliate_disclosure_shown` with channel + content ID + timestamp.
+- **Rate-limits**: store `policy_type=rate_limit` in `policies`, log enforcement outcomes in `events`.
+- **Policy checks evidence**: store each evaluation result in `decisions` with `reason` and evaluation context in JSON.
+
+## Step 2 — Supabase schema & example SQL
+
+### Table: `domains`
+```sql
+create table if not exists domains (
+  id uuid primary key default gen_random_uuid(),
+  domain_name text unique not null,
+  role text not null check (role in (
+    'portal', 'infra', 'asset', 'distribution', 'transaction',
+    'identity', 'security', 'compliance', 'operations'
+  )),
+  status text not null default 'offline' check (status in ('online', 'offline')),
+  last_health_check timestamptz,
+  last_unpublish_reason text,
+  created_at timestamptz not null default now(),
+  updated_at timestamptz not null default now()
+);
+```
+
+### Table: `policies`
+```sql
+create table if not exists policies (
+  id uuid primary key default gen_random_uuid(),
+  domain_id uuid not null references domains(id) on delete cascade,
+  policy_type text not null check (policy_type in (
+    'rate_limit', 'anomaly_threshold', 'legal_flag', 'manual_hold'
+  )),
+  config jsonb not null default '{}'::jsonb,
+  is_active boolean not null default true,
+  created_at timestamptz not null default now(),
+  updated_at timestamptz not null default now()
+);
+```
+
+### Table: `events`
+```sql
+create table if not exists events (
+  id uuid primary key default gen_random_uuid(),
+  domain_id uuid references domains(id) on delete set null,
+  event_type text not null,
+  actor text,
+  metadata jsonb not null default '{}'::jsonb,
+  created_at timestamptz not null default now()
+);
+```
+
+### Table: `decisions`
+```sql
+create table if not exists decisions (
+  id uuid primary key default gen_random_uuid(),
+  domain_id uuid not null references domains(id) on delete cascade,
+  decision text not null check (decision in ('publish', 'unpublish')),
+  reason text not null,
+  evidence jsonb not null default '{}'::jsonb,
+  created_at timestamptz not null default now()
+);
+```
+
+### Table: `metrics_daily`
+```sql
+create table if not exists metrics_daily (
+  id uuid primary key default gen_random_uuid(),
+  domain_id uuid not null references domains(id) on delete cascade,
+  metric_date date not null,
+  hits integer not null default 0,
+  clicks integer not null default 0,
+  posts integer not null default 0,
+  anomalies integer not null default 0,
+  created_at timestamptz not null default now(),
+  unique (domain_id, metric_date)
+);
+```
+
+### Example queries
+**Log a new event**
+```sql
+insert into events (domain_id, event_type, actor, metadata)
+values (
+  (select id from domains where domain_name = 'semestaorbit.com'),
+  'bot_posted',
+  'telegram-bot-1',
+  '{"channel":"@semestaorbit","product_id":"SKU123","disclosure_shown":true}'::jsonb
+);
+```
+
+**Record a publish/unpublish decision**
+```sql
+insert into decisions (domain_id, decision, reason, evidence)
+values (
+  (select id from domains where domain_name = 'semestaorbit.com'),
+  'unpublish',
+  'Anomaly threshold exceeded',
+  '{"anomalies_today":15,"threshold":10}'::jsonb
+);
+
+update domains
+set status = 'offline',
+    last_unpublish_reason = 'Anomaly threshold exceeded',
+    updated_at = now()
+where domain_name = 'semestaorbit.com';
+```
+
+**Get current allowed domains**
+```sql
+select domain_name, role
+from domains
+where status = 'online'
+order by role, domain_name;
+```
+
+## Step 3 — Portal gateway backend (Python)
+
+### Example FastAPI service
+```python
+import os
+from datetime import date
+from fastapi import FastAPI, HTTPException
+from fastapi.responses import RedirectResponse, JSONResponse
+from supabase import create_client
+
+SUPABASE_URL = os.environ["SUPABASE_URL"]
+SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
+
+supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
+app = FastAPI()
+
+ANOMALY_THRESHOLD = 10
+
+@app.get("/go/{domain}")
+def go(domain: str):
+    domain_row = (
+        supabase.table("domains")
+        .select("id, domain_name, status")
+        .eq("domain_name", domain)
+        .single()
+        .execute()
+    )
+    if not domain_row.data:
+        raise HTTPException(status_code=404, detail="Domain not found")
+
+    if domain_row.data["status"] != "online":
+        return JSONResponse(
+            status_code=423,
+            content={"status": "offline", "reason": "Temporarily unpublished"},
+        )
+
+    metrics = (
+        supabase.table("metrics_daily")
+        .select("anomalies")
+        .eq("domain_id", domain_row.data["id"])
+        .eq("metric_date", date.today().isoformat())
+        .single()
+        .execute()
+    )
+
+    anomalies = metrics.data["anomalies"] if metrics.data else 0
+    if anomalies >= ANOMALY_THRESHOLD:
+        return JSONResponse(
+            status_code=423,
+            content={
+                "status": "offline",
+                "reason": "Compliance hold due to anomalies",
+            },
+        )
+
+    return RedirectResponse(url=f"https://{domain}", status_code=302)
+
+
+@app.post("/admin/recalc")
+def recalc():
+    domains = supabase.table("domains").select("id, domain_name").execute().data
+    for domain in domains:
+        metrics = (
+            supabase.table("metrics_daily")
+            .select("anomalies")
+            .eq("domain_id", domain["id"])
+            .eq("metric_date", date.today().isoformat())
+            .single()
+            .execute()
+        )
+        anomalies = metrics.data["anomalies"] if metrics.data else 0
+        decision = "publish" if anomalies < ANOMALY_THRESHOLD else "unpublish"
+        reason = (
+            "Anomalies within threshold"
+            if decision == "publish"
+            else "Anomaly threshold exceeded"
+        )
+
+        supabase.table("decisions").insert(
+            {
+                "domain_id": domain["id"],
+                "decision": decision,
+                "reason": reason,
+                "evidence": {"anomalies_today": anomalies, "threshold": ANOMALY_THRESHOLD},
+            }
+        ).execute()
+
+        supabase.table("domains").update(
+            {
+                "status": "online" if decision == "publish" else "offline",
+                "last_unpublish_reason": None
+                if decision == "publish"
+                else "Anomaly threshold exceeded",
+            }
+        ).eq("id", domain["id"]).execute()
+
+    return {"status": "ok"}
+```
+
+## Step 4 — Bot integration (Telegram/Discord)
+
+### Bot behavior (compliant)
+- **Before posting**: call portal API to fetch allowed domains and content.
+- **Always include disclosure**: “Ini adalah link afiliasi, kami bisa mendapatkan komisi jika kamu membeli melalui link ini.”
+- **Rate limit**: max 3 posts/day per channel, 1 per 6 hours per channel.
+- **Log every post** to `events` with disclosure flag and product ID.
+
+### Telegram (python-telegram-bot) snippet
+```python
+import os
+import requests
+from supabase import create_client
+from telegram import Bot
+
+SUPABASE_URL = os.environ["SUPABASE_URL"]
+SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
+PORTAL_API = os.environ["PORTAL_API"]
+
+supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
+bot = Bot(token=os.environ["TELEGRAM_TOKEN"])
+
+DISCLOSURE = "Ini adalah link afiliasi, kami bisa mendapatkan komisi jika kamu membeli melalui link ini."
+
+allowed = requests.get(f"{PORTAL_API}/allowed").json()
+if "semestaorbit.com" in allowed:
+    product = supabase.table("affiliate_products").select("id, title, url").limit(1).execute().data[0]
+    message = f"{product['title']}\\n{product['url']}\\n\\n{DISCLOSURE}"
+    bot.send_message(chat_id="@semestaorbit", text=message)
+
+    supabase.table("events").insert(
+        {
+            "event_type": "bot_posted",
+            "actor": "telegram-bot-1",
+            "metadata": {
+                "product_id": product["id"],
+                "channel": "@semestaorbit",
+                "disclosure_shown": True,
+            },
+        }
+    ).execute()
+```
+
+### Discord (discord.py) snippet
+```python
+import os
+import requests
+from supabase import create_client
+import discord
+
+SUPABASE_URL = os.environ["SUPABASE_URL"]
+SUPABASE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
+PORTAL_API = os.environ["PORTAL_API"]
+
+supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
+client = discord.Client(intents=discord.Intents.default())
+
+DISCLOSURE = "Ini adalah link afiliasi, kami bisa mendapatkan komisi jika kamu membeli melalui link ini."
+
[+@client.event](mailto:+@client.event)
+async def on_ready():
+    allowed = requests.get(f"{PORTAL_API}/allowed").json()
+    if "semestaorbit.com" in allowed:
+        product = supabase.table("affiliate_products").select("id, title, url").limit(1).execute().data[0]
+        channel = client.get_channel(int(os.environ["DISCORD_CHANNEL_ID"]))
+        await channel.send(f"{product['title']}\\n{product['url']}\\n\\n{DISCLOSURE}")
+
+        supabase.table("events").insert(
+            {
+                "event_type": "bot_posted",
+                "actor": "discord-bot-1",
+                "metadata": {
+                    "product_id": product["id"],
+                    "channel": os.environ["DISCORD_CHANNEL_ID"],
+                    "disclosure_shown": True,
+                },
+            }
+        ).execute()
+
+client.run(os.environ["DISCORD_TOKEN"])
+```
+
+## Step 5 — Concrete digital product ideas (7 sites)
+
+1. **Digital Infrastructure Operations (spiralstadion1a)**
+   - **Product**: “Uptime & Incident Response Checklist Pack”
+   - **Type**: PDF + SOP templates
+   - **Monetization**: One-time purchase
+   - **Compliance logging**: log file delivery and terms acceptance.
+
+2. **Digital Asset Content Handling (spiralstadion2a)**
+   - **Product**: “Copyright-Safe Content Formatting Guide”
+   - **Type**: Mini-course + checklists
+   - **Monetization**: One-time purchase
+   - **Compliance logging**: consent + license acknowledgement.
+
+3. **Digital Distribution Delivery (spiralstadion3a)**
+   - **Product**: “Geo-Blocking & Export Rules Playbook”
+   - **Type**: Report + template notices
+   - **Monetization**: One-time purchase
+   - **Compliance logging**: user download logs + jurisdiction disclaimer.
+
+4. **Digital Transaction Access Control (spiralstadion4a)**
+   - **Product**: “Payment Gateway Configuration Workbook”
+   - **Type**: Spreadsheet templates + checklist
+   - **Monetization**: One-time purchase + optional affiliate links
+   - **Compliance logging**: acknowledgment of PCI guidance limitation.
+
+5. **Digital Identity Trust Management (spiralstadion5a)**
+   - **Product**: “Role & Access Policy Starter Kit”
+   - **Type**: Policy templates
+   - **Monetization**: One-time purchase
+   - **Compliance logging**: log acceptance of security disclaimer.
+
+6. **Digital Security Risk Management (spiralstadion6a)**
+   - **Product**: “Threat Log & Audit Journal Pack”
+   - **Type**: Notion/CSV templates
+   - **Monetization**: Subscription for updates
+   - **Compliance logging**: subscriber consent + update delivery logs.
+
+7. **Digital Compliance Governance (spiralstadion7a)**
+   - **Product**: “Policy Evidence Binder Toolkit”
+   - **Type**: Template + evidence checklist
+   - **Monetization**: One-time purchase
+   - **Compliance logging**: consent + versioned download logs.
+
+## Step 6 — 90-day roadmap
+
+### Phase 1 (0–30 days)
+- Deploy portal gateway API with `/go/{domain}` and `/admin/recalc`.
+- Build minimal Supabase schema and start logging events.
+- Publish semestaorbit.com + 1–2 digital product sites.
+- Add compliance pages and affiliate disclosure.
+
+### Phase 2 (31–60 days)
+- Expand logging with metrics aggregation job.
+- Add policy evaluation cron and automated publish/unpublish decisions.
+- Integrate 4–5 additional spiralstadion sites.
+- Add Telegram + Discord bots with strict rate limits.
+
+### Phase 3 (61–90 days)
+- Add anomaly detection automation (simple thresholds).
+- Harden audit log viewer and compliance reporting.
+- Introduce external cloud services only when usage justifies it (cost control, logs, and legal compliance).
 
EOF
)
