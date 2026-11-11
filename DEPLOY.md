# Moving Kim's Speed Dating to Cloudflare (free plan)

This folder holds the whole app: one Cloudflare Worker, one Durable Object (the database), and the page.
It runs on the free Cloudflare plan at an address like `https://kims-speed-dating.YOURNAME.workers.dev`.
No custom domain, no credit card.

**Golden rule: if any screen asks for a credit card or says "Upgrade", "Workers Paid" or "Start free trial", stop and do not continue.**
Nothing in these steps needs one. If you hit that screen, close it and ask for help.

Do not paste any key, token or password into a chat. Everything secret below is typed only into your own terminal.

---

## YOUR STEPS

Words in `CAPITALS` are things you replace with your own value.
"Terminal" means Terminal on Mac, or PowerShell on Windows.

### Step 1. Get the code on your computer

1. Install Node.js (the "LTS" button) from https://nodejs.org and open a new terminal afterwards.
2. Install Git from https://git-scm.com if you do not have it.
3. In the terminal, run these one at a time. The repository may be private, so Git can ask you to sign in to GitHub.

```bash
git clone https://github.com/jervin1616/KimsSpeedDating.git
```

```bash
cd KimsSpeedDating
```

```bash
git checkout claude/friendly-tesla-31j2vk
```

```bash
npm install
```

4. Copy your backup file (for example `speed-dating-backup-2026-11-10.json`) into the folder named `data` inside `KimsSpeedDating`.
   The `data` folder is ignored by Git on purpose, so your daters' names never go on GitHub.

### Step 2. Make a free Cloudflare account

1. Go to https://dash.cloudflare.com/sign-up
2. Enter an email and a password, click **Sign up**, then click the link in the email Cloudflare sends you.
3. If Cloudflare shows a page offering plans, choose **Free**. You never need to enter a card.

### Step 3. Log in from the terminal

```bash
npx wrangler login
```

A browser tab opens. Click **Allow**. The terminal then says you are logged in.

### Step 4. First deploy (this tells you your address)

```bash
npx wrangler deploy
```

- If it asks you to register a **workers.dev subdomain**, type a short name (letters and numbers), for example `kimsdating`.
  Your address will be `https://kims-speed-dating.THATNAME.workers.dev`.
- At the end it prints a line starting with `https://kims-speed-dating.`. **Copy that whole address.** It is called YOUR ADDRESS below.
- Nothing works yet if you open it. That is expected. Sign-in is set up in the next steps.

To double check you are on the free plan: in the Cloudflare dashboard click **Workers & Pages**, then **Plans**. It should say **Free**.

### Step 5. Create the Google sign-in (Google Cloud)

You need a Google account. This part is also free and needs no card.
If Google Cloud ever shows "Activate free trial" or asks for billing, close it and skip it. You do not need it.

1. Go to https://console.cloud.google.com and sign in. Accept the terms if asked.
2. At the top, click the project picker, then **New project**. Name it `Kims Speed Dating` and click **Create**. Make sure it is the selected project.
3. In the search bar at the top, type `Google Auth Platform` and open it. Click **Get started**.
4. Fill in:
   - **App name:** `Kim's Speed Dating`
   - **User support email:** your email
   - **Audience:** choose **External**
   - **Contact email:** your email
   - Tick the agreement box, click **Continue**, then **Create**.
5. In the left menu click **Branding** and fill in (Google requires these before it lets you publish):
   - **App homepage:** `https://kims-speed-dating.THATNAME.workers.dev/`
   - **Application privacy policy link:** `https://kims-speed-dating.THATNAME.workers.dev/privacy.html`
   - **Authorized domains:** click **Add domain** and enter `THATNAME.workers.dev`
   - **Developer contact information:** your email
   - Click **Save**.
   The privacy page is part of this project (`public/privacy.html`), so it must be deployed first (`npx wrangler deploy`).
6. In the left menu click **Audience**. Click **Publish app**, then **Confirm**.
   This matters: if the app stays in "Testing", only people you list by hand can sign in. Publishing is free and needs no review for plain Google sign-in.
   If Google refuses to publish, you can stay in Testing instead: on the same Audience page add every person from your `ROLES` list under **Test users**
   (up to 100). It works the same, you just keep the list in two places.
7. In the left menu click **Clients**, then **Create client**.
   - **Application type:** `Web application`
   - **Name:** `Kims Speed Dating web`
   - Under **Authorized JavaScript origins** click **Add URI** and enter YOUR ADDRESS exactly, like
     `https://kims-speed-dating.THATNAME.workers.dev`
     with no slash at the end and nothing after `.dev`.
   - Leave **Authorized redirect URIs** empty.
   - Click **Create**.
8. A box shows a **Client ID** that ends in `.apps.googleusercontent.com`. Copy the Client ID.
   You do not need the client secret. Ignore it.
9. Google can take a few minutes (rarely a few hours) to start accepting a new origin. If sign-in says "origin not allowed" later, wait and try again.

### Step 6. Put the Client ID in the config

1. Open the file `wrangler.jsonc` in a text editor (Notepad, TextEdit, VS Code).
2. Find the line `"GOOGLE_CLIENT_ID": "",` and put your Client ID between the second pair of quotes:

```
"GOOGLE_CLIENT_ID": "1234567890-abcdefg.apps.googleusercontent.com",
```

3. Save the file. The Client ID is public by design, so it is fine for it to be in this file.

### Step 7. Set the three secrets

Secrets are stored by Cloudflare, never in the code.
Each command asks you to type or paste the value, and nothing is shown on screen as you paste. That is normal.

**7a. The session key.** Make a random value and copy it:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the long line it prints, then:

```bash
npx wrangler secret put SESSION_SECRET
```

Paste the long line when it asks and press Enter.

**7b. The list of who can use the app (the mod list and roles).** Run:

```bash
npx wrangler secret put ROLES
```

When it asks for the value, type one line like this, using the real Google email addresses:

```
you@gmail.com=owner,kim@gmail.com=owner,eddey@gmail.com=owner,mod1@gmail.com=contributor
```

Put the three people who may create Editors (you, Kim and Eddey) as `owner`. Everyone else is added later on the access page, so the secret only needs the owners.

What the roles mean:

| Role | What they can do |
|---|---|
| `owner` | Everything an editor can do, plus the access page (`/admin.html`) where roles are assigned. Owners can only be set here, in the secret |
| `editor` | Everything: seat daters, edit daters, match log, past streams, questions, backups. Cannot manage access |
| `contributor` | Add questions, ask and randomize questions. Cannot seat daters. Cannot read the daters list |
| `viewer` | Watch the board and the current question, and use a private "Random question for me" button that does not change the stream. Cannot write anything |

Rules: separate people with commas, write `email=role` with no spaces around `=`.
Use the exact address the person signs in with. Gmail dots and `+` tricks do not match, so `k.im@gmail.com` is not `kim@gmail.com`.
Anyone who signs in with a Google account but is not on the list gets the default role, which in this project is `viewer` (set in `wrangler.jsonc`). Change `"DEFAULT_ROLE"` to `"none"` and redeploy if you want unlisted people locked out completely.

**7c. The import key (needed only for the import in step 9).** Make a value and keep it visible for the next steps.

Mac or Linux terminal:

```bash
export ADMIN_KEY=$(node -e "console.log(require('crypto').randomBytes(24).toString('hex'))")
```

```bash
echo $ADMIN_KEY
```

Windows PowerShell:

```powershell
$env:ADMIN_KEY = node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
```

```powershell
$env:ADMIN_KEY
```

Copy the printed value, then:

```bash
npx wrangler secret put ADMIN_KEY
```

Paste it when asked. **Keep this same terminal window open** for step 9. It remembers `ADMIN_KEY` only while it is open.

### Step 8. Deploy again so the Client ID is live

```bash
npx wrangler deploy
```

Now open YOUR ADDRESS in a browser. You should see "Host access only" and a **Sign in with Google** button.

### Step 9. Import your data

Use the same terminal window as step 7c, from inside the `KimsSpeedDating` folder.

First a practice run that sends nothing:

```bash
node scripts/import.mjs --dry-run
```

It should print something like `Ready to import 741 records: daters 230, questions 500, matches 4, seats 6, game 1`.

Now the real import (replace the address):

```bash
node scripts/import.mjs --url https://kims-speed-dating.THATNAME.workers.dev
```

It ends with `Check passed`. Running it twice is safe: it updates by id and never makes duplicates.
It never deletes anything unless you add both `--replace --yes`, which you should not need.

### Step 10. Switch the import key off

```bash
npx wrangler secret delete ADMIN_KEY
```

Type `y` to confirm. With the key gone, the import door is closed.

### Step 11. Check that it worked

1. Open YOUR ADDRESS and click **Sign in with Google** with Kim's account. The pill at the top should say **Host view**.
2. Daters should show 230 (or your number). Questions should show 500 total. Match log and Past streams should have their entries.
3. Open the same address on your phone, sign in, and seat a dater in a panel seat on one device. It should appear on the other within a second.
4. Sign in as a mod account (a Contributor). The pill says **Limited view**. They can press **Random question** but there is no Daters tab and no seat controls.
5. Sign in with an account that is not on the list. It says the account is not on the list.
6. Open `YOUR ADDRESS/backup.html`, sign in as Kim, click **Download backup**. A file `speed-dating-backup-DATE.json` downloads.
   Do this at the end of every stream night.

### Step 12. Going live

The Claude version stays exactly as it is until you are happy. When you are, give people the new address.
Keep the Claude version around for at least two good streams (see Rolling back below).

---

## Rolling back if something fails on stream night

Keep the old Claude link handy. Fast path, takes under a minute:

1. Close the Cloudflare tab and open the old Claude version. It still has all the data it had before you moved.
2. Carry on the stream from there.

Things to know, so you are not surprised:

- **Data does not copy back by itself.** Anything you entered on the Cloudflare version (new daters, new questions, logged matches) is not in the Claude version.
  Your data is not lost: it is still on Cloudflare. Download it from `/backup.html` later, and re-add the few things you need by hand.
- The Claude version has the data from the day you exported it. That is another reason to keep the Claude version unused until you are ready, or to only roll back for a night.
- **If a new version of the Worker caused the problem** (you changed something and deployed), you do not need the Claude version at all. Run this in the terminal and the previous Worker version is live again within seconds:

```bash
npx wrangler rollback
```

- **If sign-in is the problem on the night** (for example Google is slow), you cannot work around it by design: nobody gets in without a verified Google sign-in. Use the Claude version.

---

## Pre-stream checklist (do this 30 minutes before going live)

- [ ] Open YOUR ADDRESS on the computer you stream from and sign in. The pill says **Host view**.
- [ ] Daters count and Questions total look right (compare to last stream).
- [ ] Open the address on your phone too. Seat a test dater on one device and watch it appear on the other. Clear the seats afterwards.
- [ ] Every mod signs in once and sees **Limited view**. Every viewer sees **View only**.
- [ ] Anyone who cannot get in: check their exact email is in the `ROLES` list (step 7b).
- [ ] Download a backup from `/backup.html` and keep it somewhere private.
- [ ] Check the free limits: Cloudflare dashboard, **Workers & Pages**, click `kims-speed-dating`, **Metrics**. Requests should be nowhere near 100,000 for the day.
- [ ] Do not change the `ROLES` secret or deploy during the stream. Both restart the database for a moment and everyone reconnects.
- [ ] Have the Claude link open in a tab, just in case.

If the connection drops mid-stream the page shows "Connection lost. Reconnecting..." and then "Back online. Board refreshed." on its own. You do not need to reload.

---

## Who can use the app, and how to change it

Three places decide someone's role, strongest first:

1. **The `ROLES` secret.** Owners live here, so nobody can be locked out by mistake. People here are locked on the access page.
2. **The access page, `YOUR ADDRESS/admin.html`.** Owners only (the server enforces it, not just the button). An owner types an email, picks a role, and clicks Save. It takes effect immediately, even for people who are already on the app: their page tells them to reload, and anyone you remove is disconnected at once.
3. **`DEFAULT_ROLE`** in `wrangler.jsonc`, for any other Google account. It is `viewer` here, so anyone who signs in can watch and use the private question picker. It can only be `none`, `viewer` or `contributor`, never `editor`.

The access page also shows **"Signed in recently, not on any list"**: everyone who signed in with Google but is not on the secret or the page's list (up to the latest 300), with how many times and when.
Pick a role and click **Add** to move them onto the list, or **Forget** to clear the entry. Those emails are only kept for this purpose, and the privacy page says so.
Anyone already on a list does not appear there. If you set `DEFAULT_ROLE` to `none`, this list is where people waiting for approval show up.

Only owners can use the access page. Editors, Contributors and Viewers cannot, even if they type the address. Nobody can change people listed in the secret from the page (edit the secret for that).

To change the owners or fix a locked person, run this and type the whole new list (it replaces the old one). Do it before a stream, not during one:

```bash
npx wrangler secret put ROLES
```

---

## Tips for hosts using the console

- **Seating:** tap an empty heart to open a picker. It lists the newest daters first, with search. For a panel seat the best fits (green) come first. Tap someone to seat them in the heart you tapped. **Add new dater** inside the picker opens the form, and when you save, the new dater goes straight into that seat. The Panel and Hot seat buttons on each dater still work.
- **Adding daters:** the form is hidden until you tap **+ Add dater**. Edit and Remove are under **More** on each dater.
- **Bottom bar (hosts only):** two big buttons stay pinned at the bottom: **Remove hot seat** and **Match**. Remove hot seat is greyed out when the hot seat is empty, empties it in one tap, and shows an **Undo** for a few seconds. Match works like the Match button beside the hot seat: tap it (it turns green and says Pick?), then tap the heart that was picked.
- **Connection dot:** a small green dot by the role label means you are live. If the connection drops it turns amber and says Reconnecting, then red and says Offline after 10 seconds. It fixes itself when the network returns.

## Signing out

Everyone has a **Sign out** pill at the top of the console (and a button on the access and backup pages). It asks first, then signs that one browser out and clears its saved login.
It does not sign the same person out on their other devices.
Signing out only clears this device. To cut someone off everywhere right now, remove them on `/admin.html`: their open pages are disconnected at once.

## Staying on the free plan

Checked against Cloudflare's own docs (Workers Free plan, Durable Objects with SQLite):

| What | Free limit | Your expected use |
|---|---|---|
| Worker requests | 100,000 per day (static page files are free and unlimited) | Hundreds |
| Durable Object requests | 100,000 per day. Incoming WebSocket messages count 1 for every 20 | Hundreds |
| Durable Object running time | 13,000 GB-s per day. Idle connections do not count (hibernation) | A few hundred, and even running 24 hours a day is about 10,800 |
| Database rows read | 5,000,000 per day | About 750 each time an Editor connects |
| Database rows written | 100,000 per day | A few thousand on a busy stream night |
| Stored data | 5 GB | Under 1 MB |

The one way to burn through the limits is a connection that keeps dropping and reconnecting all day.
The page waits longer between each retry (up to 15 seconds) to prevent that.
If a limit is ever hit, Cloudflare stops that kind of operation until midnight UTC. It does not charge you on the free plan.

---

## What is in this folder

| Path | What it is |
|---|---|
| `public/index.html` | The page. Same as before except sign-in text and a small Google button on the sign-in screen, "connection lost / back online" messages, and a private question picker that only Viewers see |
| `public/db-shim.js` | Replaces the Claude runtime. Keeps the same calls the page already used |
| `public/backup.html` | Editor-only page that downloads a backup |
| `public/privacy.html` | Privacy page that Google requires for the sign-in app |
| `public/admin.html` | Access page: owners assign roles |
| `src/worker.js` | The API: sign-in, sessions, WebSocket door, export, import |
| `src/auth.js` | Checks Google tokens, maps emails to roles, signs sessions |
| `src/database.js` | The Durable Object: SQLite storage and live sync |
| `src/rules.js` | Who may read and write what, and size and path checks |
| `wrangler.jsonc` | Cloudflare config (no secrets) |
| `scripts/import.mjs` | Loads the `data` folder into the database |
| `test/run.mjs` | The full automated test (`npm test`) |
| `legacy/` | The original Claude version of the page, untouched, for reference |
| `data/` | Your private backups. Ignored by Git |

## Rules the server enforces

| Collection | Read | Write |
|---|---|---|
| `daters` | Editor | Editor |
| `matches` | Editor | Editor |
| `seats` (including past stream summaries) | Anyone signed in with a role | Editor |
| `game` (the one document `question`) | Anyone signed in with a role | Contributor or higher |
| `questions` | Anyone signed in with a role (includes the chat handles that came with each question) | Contributor or higher |
| anything else | rejected | rejected |

Roles go Editor, then Contributor, then Viewer (read only). People not on the list have no role and get nothing.

Other protections: the Google token is checked for a real Google signature, your Client ID, a verified email and expiry.
The WebSocket only opens from this site's own address (Origin check). Document ids and shapes are validated, documents over 32 KB are refused,
messages over 64 KB close the connection, and each connection has a message rate limit.
Logins last 12 hours and renew quietly while the page is open, for up to 7 days, so a long stream is never signed out.
Removing someone from `ROLES` takes effect on their next action.

## Running the tests yourself

```bash
npm test
```

This starts the app locally, imports your `data` folder (or sample data if there is none), runs about 200 checks with three kinds of user
in real browser windows, and writes the result to `test/last-run.txt`.
The one thing it cannot test is the real Google button, because that needs your real Client ID and address (step 11 covers it).

## Troubleshooting

| You see | Do this |
|---|---|
| Sign in button says "Sign-in is not set up yet" | Step 6 and step 8: Client ID missing from `wrangler.jsonc` or not deployed |
| Google says "origin not allowed" or "Error 400: origin_mismatch" | The address in step 5 item 7 must match exactly. Wait a few minutes after saving |
| "This Google account is not on the list" | Only appears if `DEFAULT_ROLE` is `none`. Add the email on `/admin.html`, or set the default to `viewer` |
| Google says only test users can sign in | Step 5 item 6: publish the app, or add the person as a test user |
| Everything loads but nothing saves | Check `SESSION_SECRET` was set (step 7a), then `npx wrangler deploy` |
| `npx wrangler secret put` says no Worker exists | Do step 4 first |
| Want to see errors live | `npx wrangler tail` while you reproduce the problem |
