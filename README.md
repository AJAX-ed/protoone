# protoone — Secure JEE/NEET Self-Study MVP

A secure self-study platform skeleton for JEE/NEET aspirants, featuring session-based authentication, a protected dashboard, and SQLite persistence.

## Live Deployment

- **URL:** https://protoone.onrender.com
- **Host:** Render (Free tier — spins down after 15 min inactivity; first request after idle may take ~50s to respond)

## Project Structure

- `frontend/` — Node.js + Express SSR app (EJS views, auth routes, dashboard routes, SQLite db layer)
- `backend/` — Reserved for future FastAPI/Postgres services per architecture plan (not yet implemented)
- `ARCHITECTURE.md` — Target system architecture and design notes
- `docker-compose.yml` — Local multi-service orchestration (WIP)

## Tech Stack (frontend)

- Express 4, EJS templates
- Helmet, CSRF protection, express-rate-limit
- bcrypt password hashing, JWT sessions
- better-sqlite3 for persistence

## Local Development

```bash
cd frontend
cp .env.example .env   # fill in JWT_SECRET etc.
npm install
npm run dev
```

App runs on `http://localhost:3000` by default.

## Deployment Notes

Deployed on Render as a Node Web Service:

- Root directory: `frontend`
- Build command: `npm install`
- Start command: `npm start`
- Env vars: `JWT_SECRET`, `NODE_ENV=production`, `NODE_VERSION=20.11.1`

> `NODE_VERSION` is pinned to 20.11.1 because `better-sqlite3` fails to compile against newer Node versions (v8 API changes) on Render's default build image.

## Status

- [x] Auth (register/login/logout) with bcrypt + JWT
- [x] Protected dashboard route
- [x] SQLite persistence
- [x] Deployed to production (Render free tier)
- [ ] Study module content
- [ ] Backend/Postgres migration per ARCHITECTURE.md
