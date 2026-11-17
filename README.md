# PawMate
Verified breeding-partner platform for dogs: accounts, per-field privacy, photos, document verification, match requests and in-app chat.

## Run locally
    npm install
    cp .env.example .env   # then set values; export them or use `node --env-file=.env server.js` (Node 20.6+)
    npm start              # http://localhost:3000

Sign up with the email you set as ADMIN_EMAIL: that account gets an **Admin** tab to approve or reject uploaded documents.

## Go live (Render / Railway / Fly / any VPS)
1. Push this folder to GitHub, create a Node web service, start command `npm start`.
2. Set env vars from `.env.example` (JWT_SECRET must be long and random).
3. Attach a **persistent disk** and point DATA_DIR at it. It holds the SQLite database, photos and documents. Back it up regularly.
4. Serve over HTTPS (all hosts above do this). Cookies are Secure in production.

## Privacy model (enforced on the server)
Each field is Public, Matches only or Only me. A "match" exists only after the dog's owner accepts a request. Hidden fields are never sent to the browser. Photos and documents are served through checked routes, and documents are visible only to the owner and admin. Chat opens only after acceptance.

## Not included yet
Phone OTP / email verification and password reset (needs an SMS/email provider), user blocking and reporting, push notifications, and automated tests.
