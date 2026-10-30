# Chat App v2 (PostgreSQL – permanent data)

Group room + private chats, accounts, PostgreSQL, real-time WebSocket.

## Env variables
- DATABASE_URL  (PostgreSQL connection string, e.g. from Neon)
- JWT_SECRET    (long random string)

## Run locally
    npm install
    DATABASE_URL="postgres://..." JWT_SECRET="xxxx" npm start

## Deploy
See the step-by-step guide: GitHub -> Neon (database) -> Render (server) -> UptimeRobot (keep awake).
Health check URL: /health
