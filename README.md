# PawMate
Verified breeding-partner platform for dogs: email or phone login, password reset, per-field privacy, photos, document verification, match requests, chat, blocking and reporting.

## Run on your computer
    npm install
    cp .env.example .env      # open .env and fill in JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD
    npm start                 # open http://localhost:3000

* Owners use the main page. The admin signs in at /admin with ADMIN_EMAIL and ADMIN_PASSWORD (email and password only).
* All data (database, photos, documents) lives in the folder set by DATA_DIR (default `./data`). Back it up by copying that folder.
* Without email/SMS settings, reset links and phone codes are printed in the terminal (test mode only).

<<<<<<< HEAD
## Go live (Render / Railway / Fly / any VPS)
1. Push this folder to GitHub, create a Node web service, start command `npm start`.
2. Set env vars from `.env.example` (JWT_SECRET must be long and random).
3. Attach a **persistent disk** and point DATA_DIR at it. It holds the SQLite database, photos and documents. Back it up regularly.
4. Serve over HTTPS (all hosts above do this). Cookies are Secure in production.
=======
## Going live on a small budget
**IMPORTANT: before the site is reachable from the internet, set NODE_ENV=production.** In test mode phone codes appear on screen, which would let anyone log in as any phone number.

Option 1, free: run it on your own computer and share it with a free Cloudflare Tunnel (cloudflared). Data stays in `./data` on your machine. The site is online only while your computer is on and the app is running. Set BASE_URL to the tunnel address.
Option 2, about $7 a month: Render "Starter" web service plus a 1 GB disk (about $0.25 a month) mounted at /var/data, with DATA_DIR=/var/data. Render's free plan cannot keep files, so data would be wiped on every restart.
Option 3, about $5 a month: a small VPS. Install Node 22.9 or newer, copy the folder, run it with pm2, and put Caddy in front for https. Data stays on the server’s disk in ./data.
Check current prices on each provider before paying.

Settings to add on any host: NODE_ENV=production, JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, BASE_URL (your public address), DATA_DIR. For password-reset emails add SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM (Gmail with an App Password works for free at small scale). For SMS codes add TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM; until then phone login is switched off in production and people use email.

## Moving to a physical disk later
Stop the app, copy the whole DATA_DIR folder to the new disk, set DATA_DIR to the new path, start the app. Nothing else changes.

## Not included yet
Email verification at signup, push notifications, automated tests, terms of service and privacy policy.
>>>>>>> 84fd142 (Added Logo and restructured the code base)
