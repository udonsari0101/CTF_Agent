# Skill Module: osint (open-source intelligence)

Field manual for OSINT: follow a public-data trail across platforms to a person, place, or flag. There's no "bug" — there's a chain of pivots (handle → account → linked account → post/avatar/route → flag). Base methodology governs; this is tools and pivots. By role: any lookup/decode/scrape script → `solver.py`; the trail so far + every confirmed identity/location/lead → `notes/ANALYSIS.md`; ranked next pivots, dead-ends, and POISON flags → `notes/NEXT.md`. Scratch/scrapes → `tmp/`.

**Headless limits — mark `[human]` steps.** Reverse image search (Google Lens/Yandex), Google Maps pin-drop / Street View, Telegram/Discord bot chat, and login-walled sites need a browser you don't have. When the trail hits one, write the exact ask in `notes/NEXT.md` (attach the image + which region to crop, or the coords to convert), and if it's blocking use `request-remote "<the browser action needed>"` to alert the operator. Do every headless step (APIs, curl, dig, decode) yourself first.

## Identify the unknown first
Before chasing, name what you're holding — the challenge often hands you a bare string:
- 40 hex → SHA-1 (**Tor relay fingerprint**); 64 hex → SHA-256; 32 hex → MD5; `AA:BB:..` colon-hex → SSH/TLS fingerprint (→ Shodan, below).
- `4V FH 246 677`-style → **MGRS** grid → online converter → lat/long. `XXXX+XX`-style (alphabet `23456789CFGHJMPQRVWX`, always a `+`) → **Google Plus Code**. `word.word.word` → **What3Words** (3m square).
- Big numeric ID → a **snowflake** (platform user/post ID, timestamped — decode below).
- Challenge title is usually a hint ("Linked Traces"→LinkedIn, "On The Grid"→MGRS, a name→search it verbatim in quotes).

## Username / handle enumeration
The core loop: one handle → find every account that reuses it → each may link to the next.
```bash
curl -s "https://whatsmyname.app/api/lookup?username=<user>"   # 700+ sites, headless
```
Also `namechk.com`, `sherlock <user>` (CLI), and `"<user>"` quoted on each platform's own search. **Priority platforms:** X/Twitter, Tumblr, GitHub, Reddit, BlueSky, Mastodon, Spotify, SoundCloud, Steam, Keybase, **Strava/Garmin/MapMyRun (GPS → physical location)**, Pastebin, LinkedIn, TikTok, bio-links (linktr.ee, bio.link, about.me).
- **Mine the handle itself:** trailing digits = ZIP/postal (`LinXiayu35170`→Bruz FR), birth year, area/country code — cross-ref a gazetteer.
- **Chain on rename:** a discovered alias → re-enumerate ALL platforms again; repeat until the platform holding the flag. Persistent numeric IDs survive renames (below).
- **Flag hiding spots per platform:** Spotify playlist name/description or artist bio, BlueSky post text, Tumblr avatar image (visual stego) or post text, Reddit comment, SoundCloud track description.

**Platform false positives** (return 200 with no real profile — verify body, don't trust status): Telegram `t.me/USER` (always 200; check "View" vs "Contact @" in title), TikTok ("Couldn't find this account"), Smule ("Not Found"), Instagram (login wall), linkin.bio (redirects to Later.com).

## Social platform APIs (headless)
**Snowflake timestamps** — decode any big ID to its creation time:
```python
# Twitter/X: epoch 1288834974657 ; Discord: epoch 1420070400000
unix_ms = (ID >> 22) + EPOCH
```
- **X/Twitter:** permanent numeric ID → `x.com/i/user/<id>` works after any rename. Find the ID + creation date + old usernames in Wayback JSON-LD (`"author":{"identifier"}`) and in `t.co` redirect targets (they encode the username at post time). Read tweets without login via Nitter (`nitter.poast.org/USER`) or syndication API (`syndication.twitter.com/srv/timeline-profile/screen-name/USER`). `memory.lol` / `twitter.lolarchiver.com` track handle history. **Twitter strips EXIF on upload** — don't stego its images.
- **BlueSky (public API, no auth):**
  ```bash
  curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=<q>&sort=latest" | jq '.posts[].record.text'
  curl -s "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?q=<q>" | jq '.actors[].handle'
  curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=<handle>&limit=50" | jq '.feed[].post.record.text'
  ```
  Check ALL **replies** to official posts, not just the post. BlueSky rkey/TID is base32-sortable microseconds = creation time.
- **Tumblr:** `curl -sI USER.tumblr.com` → `x-tumblr-user` header confirms existence even when API 401s. Avatar (common flag carrier, visual stego) at `USER.tumblr.com/avatar/512` — pull 512 and zoom all corners. Post data is JSON in page HTML (search `"content":[`).
- **Discord (needs a user token — `[human]` to obtain):** flags hide in role names, message embeds, server description, and **animated emoji 2nd frame** (extract GIF frames). `curl -H "Authorization: $TOKEN" https://discord.com/api/v10/guilds/<id>/{roles,emojis}` and `.../messages/search?content=flag`.
- **Unicode homoglyph stego in posts:** text looks normal but has non-ASCII codepoints (Cyrillic `а`U+0430, `о`U+043E, `е`U+0435; Math monospace). Convention: ASCII bit=0, homoglyph bit=1, MSB-first into bytes. Skip platform smart-quotes (`'`U+2019). Decode in `solver.py`.
- **Strava/fitness:** public activity maps expose GPS routes; start/end points leak home/work. Profile `strava.com/athletes/<id>`; segment leaderboards reveal location without following. Verify the endpoint via Google Maps photos `[human]`.

## Reverse image search & geolocation
No EXIF? Geolocate from pixels. **The engine step is `[human]` (browser):** crop to the ONE distinctive element (shop sign, facade, unique landmark) — Google Lens does far better on a tight crop than a full scene. Engines: Google Lens (landmarks/shops), Google Images, TinEye (exact), **Yandex** (faces, E. Europe), **Baidu / `graph.baidu.com`** (China — blue plates, simplified Chinese). Also check corners/edges at full res for tiny low-contrast text (visual stego, not binary).

Headless prep and cross-checks you CAN do:
```bash
exiftool image.jpg          # GPS, serial, maker — do this before assuming pixel-geolocation
convert input.jpg -flop flipped.jpg    # un-mirror reflected sign text (water/glass), then search the readable prefix quoted
curl "http://ip-api.com/json/<ip>"      # IP → coarse geo/ASN ; ipinfo.io/<ip>/json
```
- **Country-ID shortcuts:** Kanji+blue highway signs→Japan · Cyrillic+wide boulevards/brutalist panel blocks→Russia/CIS · white X crossing sign→Canada · yellow diamond warnings→US/Canada · green autobahn→Germany · left-hand traffic→JP/UK/AU. Named business/brand in frame → search `"<brand>" locations` → cross-ref coastline/terrain to the exact branch.
- **Infra maps:** [openinframap.org](https://openinframap.org) (power), [openrailwaymap.org](https://www.openrailwaymap.org) (rail) — narrow by country, then intersect features.
- **Overpass Turbo** ([overpass-turbo.eu](https://overpass-turbo.eu)) — pinpoint a POI type near another POI in a known city; the `around` proximity filter replaces hours of map browsing:
  ```text
  [out:json][timeout:25];
  {{geocodeArea:Barcelona}}->.a;
  node["railway"="subway_entrance"](area.a)->.metros;
  ( node(around.metros:10)["shop"~"newsagent|kiosk"]; );
  out body;
  ```
  Useful tags: `shop=newsagent|kiosk|bakery`, `amenity=cafe|atm|pharmacy`, `tourism=hotel|attraction|viewpoint`, `railway=station|subway_entrance`. Verify each hit in Street View `[human]`.
- **Convert to the flag's coordinate system** `[human]` on Google Maps: drop a pin → **Plus Code** appears in the details panel (free, no key); or enter coords at what3words.com for the **W3W** 3-word address. W3W is exact to 3m — match the camera's spot, not the subject's; try adjacent squares.
- **Crowd-sourced photos** `[human]`: when non-visual OSINT (a Strava route, an address) names a candidate place, open it on Google Maps → Photos tab → match scene elements. Works when reverse-image fails (challenge image is original, not scraped) — search by place name, not by image.

## Web / DNS / infra
```bash
# Wayback CDX — deleted posts, old profiles, prior handles
curl "http://web.archive.org/cdx/search/cdx?url=twitter.com/USER*&output=json&fl=timestamp,original,statuscode"
# DNS — flags live in TXT of SUBdomains, and in zone transfers
dig -t txt sub.ctf.domain.com ; dig -t any domain.com ; dig axfr @ns.domain.com domain.com
whois domain.com            # registrant/creation-date timeline; whois <ip> → NetName/Org/CIDR; reverse-WHOIS by email
```
- **Google dorking** `[human]`: `site: filetype: intitle:"index of" inurl:`. Image tab `&tbs=itp:face` strips logos/banners → profile photos only; combine with `site:linkedin.com after:YYYY-MM-DD`.
- **Google Docs/Sheets** leak via `/export?format=csv`, `/pub`, `/gviz/tq?tqx=out:csv`, `/htmlview` — try these on any linked sheet ID.
- **Tor relay:** `metrics.torproject.org/rs.html#simple/<40-hex-fingerprint>` — check the relay **family** and sort by "first seen" for ordered flags.
- **GitHub:** mine issue/PR comments, wiki edits, commit messages: `gh api repos/OWNER/REPO/issues/comments`. (Author-email mining → next section.)
- **CTFd host itself:** if the CTF runs on CTFd, its REST API can hand you hint text, tags, and attachment URLs that steer the trail: `curl -s <base>/api/v1/challenges` and `.../api/v1/challenges/<id>` (submission still goes through `submit-flag`, per base).

**De-anon a service by fingerprint (real IP behind Tor/CDN):** SSH host keys and TLS certs are unique per host — if a hidden/CDN-fronted service also exposes SSH or the same cert, its fingerprint on Shodan/Censys reveals the origin IP.
```bash
ssh-keyscan -t rsa target.onion 2>/dev/null | ssh-keygen -lf - -E md5   # get the fingerprint
shodan search 'ssh.fingerprint:"ab:cd:ef:..."'      # or ssl.cert.fingerprint:"<sha256>"
shodan search 'hostname:target.com' ; shodan host <ip>
```
**Fake service banner:** never trust the port number — a "22/SSH" may be a custom banner holding the flag. `nmap -sV -sC -p <port> host` (version detection), or just `nc host port` / `echo | nc -w3 host port` to read the raw banner.

## Leaked-file metadata (a filename/author/dir-listing is a lead)
- **`.DS_Store`** leaks a directory's file listing (names, not contents) even when the server hides paths — grab it everywhere and parse: `curl -sO https://target/.DS_Store && python3 -m dsstore .DS_Store` (try `/`, `/uploads/`, `/static/`). Exposes hidden panels, backups, uploaded flags.
- **Git author mining:** every commit is a signed log of who touched it; recovered emails are candidate logins for the target's other services. `git clone` then `git shortlog -sne` and `git log --format="%an <%ae>%n%cn <%ce>" | sort -u`; also `.mailmap`, `git log --show-signature`, and GitHub-wide `gh api users/<u>/events/public --paginate | jq -r '.[].payload.commits[]?.author.email' | sort -u`.
- **Document metadata:** `exiftool` (images: GPS/serial/software), `pdfinfo`/`pdftotext` (author/producer, white-on-white text), `mediainfo` (video). Office `.docx/.xlsx` are ZIPs — `unzip -l` then read `docProps/core.xml`.

## Pitfalls
- Chasing a `[human]` browser step while headless leads (APIs, Wayback CDX, dig, whois, exiftool, git) are untried — do those first, hand off the rest with an exact ask.
- Trusting HTTP 200 as "account exists" (false positives above) — read the body.
- Stego-hunting a Twitter-served image (EXIF stripped); missing a Tumblr avatar (metadata preserved).
- Full-scene reverse image search instead of a tight crop of the one distinctive element.
- Stopping at the first account — the flag is usually one more pivot along (rename → alias → linked platform). Log each confirmed hop in `notes/ANALYSIS.md`, each untried pivot and dead-end in `notes/NEXT.md`.

## When to pivot (cross-category)
- You now hold the files/pcap and need extraction/carving/stego → `../../skills/forensics.md`.
- The trail becomes an active/exploitable HTTP service → `../../skills/web.md`.
- You recovered an encoded/encrypted blob that isn't the flag → decode reflexively (base64/32/85, hex, ROT13) and re-`file`; if it's real crypto → `../../skills/crypto.md`.

A flag from any local build is fake (base §1).
