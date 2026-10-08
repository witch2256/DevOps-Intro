# Render service configuration

**Service URL:** https://quicknotes-v0-1-0-jd2o.onrender.com
**Image:** `ghcr.io/witch2256/devops-intro/quicknotes:v0.1.0`
**Region:** Frankfurt
**Instance type:** Free
**Health check path:** `/health`
**Auto-deploy:** Off (deploys triggered by release workflow via deploy hook)

## Environment variables

| Key | Value | Reason |
|---|---|---|
| `ADDR` | `:10000` | Render routes traffic to port 10000; QuickNotes defaults to `:8080`. Setting `ADDR` avoids editing the code. |
| `DATA_PATH` | `/tmp/notes.json` | Free tier has ephemeral disk; `/tmp` is writable by the nonroot user. |
| `SEED_PATH` | `/tmp/seed.json` | No seed shipped — app starts with empty store. |

## Why existing image (not from-repo build)

- Reproducibility: the deployed artifact is the same digest that CI built and Lab 9 scanned with Trivy.
- Speed: Render skips the build — deploy completed in 10.6s.
- Consistency: local, Lab 6 compose, Lab 8 monitoring, and Render all run `sha256:2af69f73...`.

## Deploy hook (wired in `.github/workflows/release.yml`)

The release workflow calls Render's deploy hook **after** pushing the image, so a new tag redeploys the service. The hook URL is stored as a GitHub Actions secret (`RENDER_DEPLOY_HOOK`), never committed.

Hook call (reference — actual secret lives in repo settings):


