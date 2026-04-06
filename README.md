# Petscan – Deployment-Anleitung

## Alles was du brauchst

- GitHub-Account (kostenlos auf github.com)
- Railway-Account (kostenlos auf railway.app)
- Anthropic API-Key (von platform.anthropic.com)
- Domain petscan.de (~12 €/Jahr auf united-domains.de)

---

## Schritt 1 — GitHub Repository anlegen

1. Gehe auf https://github.com → oben rechts "+" → "New repository"
2. Name: `petscan`
3. "Public" auswählen
4. "Create repository" klicken
5. Alle diese Dateien hochladen:
   - index.html
   - petscan-app.html
   - petscan-admin-dashboard.html
   - server.py
   - requirements.txt
   - Procfile

---

## Schritt 2 — Railway deployen

1. Gehe auf https://railway.app → kostenlos registrieren
2. "New Project" → "Deploy from GitHub repo"
3. Dein `petscan` Repository auswählen
4. Railway erkennt automatisch das Procfile und startet

**Environment Variables setzen** (sehr wichtig!):
- Klicke auf dein Projekt → "Variables"
- Variable hinzufügen: `ANTHROPIC_API_KEY` = dein Key von platform.anthropic.com
- Variable hinzufügen: `SECRET_KEY` = ein langer zufälliger Text (z.B. `meinGeheimesPasswort2025xyz`)

5. Railway gibt dir eine URL: `https://petscan-xyz.railway.app`
6. Teste ob es funktioniert: `https://petscan-xyz.railway.app/health`

---

## Schritt 3 — Domain verbinden

1. Kaufe `petscan.de` auf united-domains.de
2. In Railway: Projekt → Settings → Domains → "Add Custom Domain"
3. Trage `petscan.de` ein
4. Railway zeigt dir einen CNAME-Eintrag
5. Gehe zu united-domains.de → DNS-Einstellungen → diesen CNAME eintragen
6. Nach 10-30 Minuten ist petscan.de live

---

## Fertig!

Deine Software ist unter petscan.de erreichbar:

| Seite | URL |
|---|---|
| Startseite | petscan.de |
| KI-Plattform | petscan.de/petscan-app.html |
| Admin | petscan.de/petscan-admin-dashboard.html |

---

## Zugangsdaten (Demo)

| Rolle | E-Mail | Passwort |
|---|---|---|
| Tierarzt | dr.mueller@tierklinik.de | demo123 |
| Admin | admin@petscan.de | admin123 |

---

## Kosten im Überblick

| | Kosten |
|---|---|
| Railway (Hobby-Plan) | 5 €/Monat |
| Domain petscan.de | ~1 €/Monat |
| Anthropic API | ~0,01 € pro Analyse |
| **Gesamt** | **~6 €/Monat + Nutzung** |

---

## Anthropic API-Key holen

1. Gehe auf https://platform.anthropic.com
2. Registrieren / Einloggen
3. Links im Menü: "API Keys"
4. "Create Key" → Key kopieren
5. In Railway als `ANTHROPIC_API_KEY` eintragen
