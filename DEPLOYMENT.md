# LinkShield deployment

Target: GitHub `kaushalbyte/LinkShield`, Netlify frontend, one free Render backend instance. These instructions describe configuration, not evidence that a deployment is live.

## Render backend

Create a Node web service from the GitHub repository's `main` branch. Choose **Free**; do not add paid resources.

| Setting | Value |
| --- | --- |
| Root directory | Repository root (leave blank) |
| Build command | `npm ci --omit=dev --prefix backend` |
| Start command | `npm start --prefix backend` |
| Health-check path | `/health` |
| `NODE_ENV` | `production` |
| `NODE_VERSION` | `22` |
| `SAFE_BROWSING_API_KEY` | Private value from your existing local configuration |
| `ALLOWED_ORIGINS` | Exact live Netlify HTTPS origin, no trailing slash |

Keep the repository root because the server also supports local same-origin hosting of sibling frontend files. Its public routes explicitly allow only frontend files. Backend files and `.env` are never served. Render supplies `PORT`; the app binds on `0.0.0.0`.

Store secrets in Render's private environment settings. Never copy the entire `.env` into GitHub or Netlify. Restrict the Google key to Safe Browsing and review quota/usage alerts. If IP restrictions are used, configure them for the actual Render outbound addresses.

Render's free service sleeps after inactivity and can take about a minute to start. The frontend allows 90 seconds; Google's own timeout remains 15 seconds. Free hosting has usage limits. See [Render free service documentation](https://render.com/docs/free).

## Netlify frontend

Import the GitHub repository using the free plan. Select `main`, leave the base directory blank and use `netlify.toml`:

| Setting | Value |
| --- | --- |
| Build command | `node scripts/build-frontend.cjs` |
| Publish directory | `dist` |
| `API_BASE_URL` | Actual Render HTTPS origin, without `/api/check-url` |

`API_BASE_URL` is public configuration. Never set the Google key on Netlify. The build fails if the origin is missing, not HTTPS, or contains credentials, a path, query or fragment. It copies only the two HTML pages, stylesheet and two browser JavaScript files. Source HTML remains suitable for same-origin local development.

Once Netlify assigns the domain, set Render's `ALLOWED_ORIGINS` to that exact origin and redeploy the backend configuration. Wildcards are not supported. Preview and branch domains are not automatically allowed. Redeploy Netlify when changing its API origin; configuration is inserted at build time.

## Rate limiting and reverse proxies

Requests are limited to 30 per minute per resolved client IP, JSON bodies to 8 KB and URLs to 4,096 characters. Only HTTP/HTTPS URLs without embedded credentials are accepted. Submitted websites are never fetched.

Forwarded IP headers are deliberately untrusted by default. Behind Render, this conservative default can share the 30-request limit across users arriving through the same proxy. Do not trust arbitrary headers or guess a hop count. Before enabling per-client proxy handling, verify the host topology and header sanitization, set `TRUST_PROXY` to verified proxy IPs/CIDRs and test counters from different clients. Until then, this is a conservative demo limit, not verified production per-user limiting. See [Express proxy guidance](https://expressjs.com/en/guide/behind-proxies/).

Counters and verdict caches are in memory, reset on restarts and are not shared across replicas. Keep one instance; distributed deployment needs shared abuse protection. CORS does not block non-browser callers or authenticate users.

## Google requirements and disclosure

A compact pre-use accuracy notice and Google attribution link to full privacy details on `privacy.html`. Google-positive warnings have attribution; local heuristic warnings do not. A missing match is never described as guaranteed safety.

The working v5 protobuf schema and decoder are preserved. Successful verdicts are cached for Google's duration, capped at 30 minutes; errors are not cached. The frontend expires old verdicts. The cache holds at most 1,000 entries with URL hashes as keys and normalized URL/verdict values.

Safe Browsing is non-commercial unless a separate Google agreement permits otherwise. The owner must personally review/accept applicable terms and confirm permitted use. Google may use/share submitted URLs and associated data. Do not submit private links or tokens.

- [Safe Browsing terms](https://developers.google.com/safe-browsing/terms)
- [v5 URL search](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search)
- [Warning and attribution guidance](https://developers.google.com/safe-browsing/v4/usage-limits)

## Release checks

Run `npm test --prefix backend`, review staged files for secrets and confirm `.env`, dependencies and `dist` are ignored. Never commit private provider CLI configuration.

Verify the deployed commit, HTTPS health endpoint, allowed/rejected CORS preflights, normal scans, invalid input, API failures, rapid scans and mobile layout. Check `https://example.com` and Google's official Safe Browsing test URL through the analyzer; do not open flagged URLs directly. Passing local tests alone does not prove public hosting is correct.
