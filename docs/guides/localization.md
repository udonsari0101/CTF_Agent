# Interface language packs

The web UI reads its language list from `ctf_agent/web/i18n/manifest.json` and its translations from `ctf_agent/web/i18n/<code>.json`. English and Korean are included. The browser language selects the initial pack; the language selector saves a user's choice in local storage.

To add a language, copy `en.json` to a new `<code>.json`, set its `locale` field, translate the values in `messages`, and add the code and display name to `manifest.json`. The keys are the existing Korean UI strings. Missing entries fall back to the source text. Date and time formatting currently uses Korean or English locale formats, so add a format choice in the web modules when introducing another language.

The packs contain interface text only. Challenge descriptions, files, notes, solver output, flags, and write-ups are never sent to a translation service. Keep any new translation files UTF-8 encoded and verify the main screens at desktop and mobile widths.
