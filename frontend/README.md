# Frontend - Secure JEE/NEET Self-Study MVP

Express-based server-rendered (EJS) frontend with cookie-based JWT authentication, CSRF protection, and security headers via Helmet.

## Features

- Server-side rendering with EJS
- JWT authentication stored in httpOnly, sameSite=strict cookies
- CSRF protection on all state-changing requests
- Helmet security headers (CSP, HSTS in production)
- Global and auth-specific rate limiting
- Password hashing with bcrypt

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
    ├── public/css/       Static stylesheets
    └── src/
        ├── server.js     App entry point, middleware setup
        ├── routes/       Route handlers (auth, dashboard)
        └── views/        EJS templates

## Notes

- The current user store in `src/routes/auth.js` is an in-memory placeholder and resets on every server restart. Replace it with a persistent database before any real deployment.
- Never commit a real `.env` file. Only `.env.example` should be tracked in version control.
- The `/health` endpoint can be used for uptime checks.

## Roadmap

- [ ] Persistent database for users (SQLite/Postgres)
- [ ] Automated tests (Jest/Supertest) for auth flow
- [ ] Study module content and dashboard features
