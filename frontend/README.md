# Frontend - Secure JEE/NEET Self-Study MVP

Express-based server-rendered (EJS) frontend with cookie-based JWT authentication, CSRF protection, and security headers via Helmet.

## Features

- Server-side rendering with EJS
- JWT authentication stored in httpOnly, sameSite=strict cookies
- CSRF protection on all state-changing requests
- Helmet security headers (CSP, HSTS in production)
- Global and auth-specific rate limiting
- Password hashing with bcrypt
- Persistent user storage with SQLite (better-sqlite3)

## Setup

1. Install dependencies:

   npm install

2. Copy the example environment file and fill in real values:

   cp .env.example .env

   Generate a strong JWT_SECRET, e.g.:

   openssl rand -hex 32

3. Start the development server (auto-restarts with nodemon):

   npm run dev

   Or start in production mode:

   npm start

4. Visit http://localhost:3000

## Project Structure

    frontend/
    ├── data/             SQLite database file (gitignored, auto-created)
    ├── public/css/       Static stylesheets
    └── src/
        ├── server.js     App entry point, middleware setup
        ├── db.js         SQLite connection and user queries
        ├── routes/       Route handlers (auth, dashboard)
        └── views/        EJS templates

## Environment Variables

- PORT - server port (default 3000)
- NODE_ENV - development or production
- JWT_SECRET - required, used to sign auth tokens
- DATABASE_PATH - optional, overrides default SQLite file location (data/app.db)

## Notes

- User accounts are now persisted in a local SQLite database at `data/app.db` (auto-created on first run). The database file itself is gitignored.
- Never commit a real `.env` file. Only `.env.example` should be tracked in version control.
- The `/health` endpoint can be used for uptime checks.

## Roadmap

- [x] Persistent database for users (SQLite)
- [ ] Automated tests (Jest/Supertest) for auth flow
- [ ] Study module content and dashboard features
- [ ] Migrate to a networked database (Postgres) if scaling beyond a single instance
