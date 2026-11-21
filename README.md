# LinkShield — URL Security Analyzer

LinkShield is a beginner-built, non-commercial learning project that checks a URL for suspicious patterns and known Google Safe Browsing threats. It combines an independent heuristic score with a separate database verdict. Neither a low score nor an absent database match guarantees safety.

<img width="955" height="442" alt="linkshield" src="https://github.com/user-attachments/assets/2ea7e308-2d45-46f7-9b94-83ad74102022" />


## Features

- Responsive dark frontend built with HTML, CSS and plain JavaScript.
- HTTP/HTTPS URL validation, rejecting invalid inputs and embedded credentials.
- Local checks for missing HTTPS, IPv4 hostnames, suspicious wording, long URLs and excessive hostname labels.
- Google Safe Browsing v5 URL search with server-side protobuf decoding.
- Latest-scan protection, request cancellation, separate error states and expiring database results.
- JSON API, request-size limits, basic rate limiting, explicit CORS origins and a health endpoint.

## Technology and structure

```text
index.html                   Scan interface
privacy.html                 Privacy and service limitations
css/style.css                Existing responsive styles
js/app.js                    Interaction and API results
js/analyzer.js               Independent heuristic scoring
backend/server.js            Node.js + Express API
backend/safe-browsing.proto   Google response schema
backend/test/                Automated checks
scripts/build-frontend.cjs    Public-files-only Netlify build
netlify.toml                 Netlify build and response headers
```

The backend contacts Google's fixed API endpoint. It never fetches the submitted website. The API key stays on the backend.

## Run locally

Use Node.js 22 LTS or a newer supported LTS release.

```sh
npm ci --prefix backend
```

For a new checkout only, copy `backend/.env.example` to `backend/.env`. Set `SAFE_BROWSING_API_KEY` using a Google Cloud project with Safe Browsing enabled. Preserve an existing `.env`; never commit it or put the key in frontend code.

```sh
npm start --prefix backend
```

Open `http://localhost:3000`. The frontend uses the same-origin `/api/check-url` endpoint locally. Do not open HTML as a `file://` URL.

## Tests

```sh
npm test --prefix backend
```

Automated tests use mocked Google responses and need no real key. They cover validation, protobuf decoding, errors, caching, rate limits, CORS, result expiry and rapid-scan races. Verify a real Google check separately after deployment.

## API

`GET /health` returns `{"status":"ok"}` when the server is running. It does not test Google availability.

`POST /api/check-url` accepts JSON such as `{"url":"https://example.com"}`. Successful checks return `success`, the normalized `url`, `isThreat`, a `threats` array and an `expiresAt` timestamp. Actual verdicts and expiry come from the API.

Errors return a non-2xx status with `success: false`, `isThreat: null`, `threats: []`, an error message and an error code. A failed request is never a clean database check.

## Deploy

Use GitHub for source, a free Render Node web service for the backend, and a Netlify static site for the frontend. See [DEPLOYMENT.md](DEPLOYMENT.md) for exact settings.

- Render uses `PORT` and stores `SAFE_BROWSING_API_KEY` privately.
- Netlify receives only the public `API_BASE_URL` and publishes generated `dist` files.
- Render's `ALLOWED_ORIGINS` must contain the actual Netlify HTTPS origin.
- Never publish the repository root as a static directory.
- Free hosting has usage limits and cold starts; it is suitable for this learning/demo project, not a production availability promise.

## Privacy and limitations

Scanned URLs go to the backend and Google. Do not submit private URLs, tokens or personal information. Google may use or share submitted URLs and associated data. Results are cached briefly in server memory; there is no persistent scan history. Hosts may keep operational logs. See [privacy.html](privacy.html) and [Google's terms](https://developers.google.com/safe-browsing/terms).

The score is a set of indicators, not a probability or a complete security assessment. Legitimate URLs can contain suspicious keywords; HTTPS alone does not make a site trustworthy. LinkShield does not inspect page contents, follow redirects or guarantee detection of new threats.

Google Safe Browsing is restricted to non-commercial use unless a separate agreement permits otherwise. Commercial projects should review [Google Web Risk](https://cloud.google.com/web-risk). Google attribution applies to its database warnings, not independent heuristic findings.

The cache and request counters are local to one server process. They reset on restarts and are not shared across replicas. CORS is a browser access rule, not authentication. Basic rate limiting does not eliminate abuse or quota exhaustion.

## Learning and AI assistance

This project was built while learning HTML, CSS, JavaScript and Node.js. AI tools were used as learning and development assistants for explanations, debugging, implementation suggestions, tests and deployment preparation. This remains a learning exercise; AI assistance does not replace independent review or make its security results authoritative.
