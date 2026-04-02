# Datenschutzerklärung

**KomDesk – Software von Komvera IT GmbH**

Stand: April 2026

---

## 1. Verantwortlicher

Verantwortlicher im Sinne der Datenschutz-Grundverordnung (DSGVO) für die Verarbeitung personenbezogener Daten beim Betrieb der Software **KomDesk** ist:

**Komvera IT GmbH**  
Von-Kerckering-Weg 3  
33442 Herzebrock-Clarholz  
Deutschland

E-Mail: komdesk@komvera.de  
Telefon: +49 5245 9247331  
Webseite: https://komvera.de

---

## 2. Überblick über die Datenverarbeitung

KomDesk ist eine Sitzplatzverwaltungssoftware für Büroumgebungen. Sie wird lokal auf den Servern des Betreibers (Lizenznehmer) installiert und betrieben.

**Wichtiger Hinweis zur Datenarchitektur:**  
Komvera IT GmbH erhält durch den Betrieb der Software **keine** personenbezogenen Daten der Mitarbeiter oder Endnutzer des Kunden. Alle Mitarbeiterdaten (Namen, Jobtitel, Buchungen) verbleiben ausschließlich auf dem Server des Betreibers (Lizenznehmer).

Die einzige Verbindung von der Software zu externen Diensten im Zusammenhang mit Komvera betrifft die **Lizenzvalidierung**: Dabei wird lediglich ein technischer Machine-Fingerprint (anonymisierter Hash) an den Lizenzdienst Keygen.sh übermittelt – kein Bezug zu Mitarbeiter- oder Nutzerdaten.

Die nachfolgend beschriebenen Datenverarbeitungen (Abschnitte 3.1 bis 3.4) betreffen den Betrieb der Software beim Kunden und dienen dem Kunden als Information und Vorlage für seine eigene Datenschutzpflicht als Betreiber.

---

## 3. Verarbeitete personenbezogene Daten

### 3.1 Sitzplatzbuchungen (Mitarbeiterdaten)

**Welche Daten:** Vorname und Nachname (oder beliebige Eingabe), Berufsbezeichnung/Jobtitel, Zeitstempel der Buchung, Raumzuweisung.

**Zweck:** Anzeige der aktuellen Bürobelegung, Verwaltung von Arbeitsplätzen.

**Rechtsgrundlage:** Art. 6 Abs. 1 lit. b DSGVO (Erfüllung eines Vertrags / berechtigtes Interesse des Betreibers) oder Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an der Büroorganisation).

**Speicherort:** Lokal auf dem Server des Betreibers (Datei `rooms.json`), unverschlüsselt.

**Speicherdauer:** Bis zur manuellen Freigabe des Sitzplatzes durch den Nutzer oder Administrator.

---

### 3.2 Administrator-Konten

**Welche Daten:** Benutzername, Anzeigename, Passwort-Hash (bcrypt, kein Klartext), Berechtigungen.

**Zweck:** Authentifizierung und Autorisierung von Administratoren.

**Rechtsgrundlage:** Art. 6 Abs. 1 lit. b DSGVO (Vertragserfüllung) / Art. 6 Abs. 1 lit. f DSGVO.

**Speicherort:** Lokal auf dem Server des Betreibers (Datei `admins.json`).

**Speicherdauer:** Bis zur Löschung des Kontos durch einen Administrator.

---

### 3.3 Microsoft Single Sign-On (SSO) – optional

Wenn der Betreiber die Microsoft-SSO-Integration aktiviert, werden beim Buchungsvorgang über Microsoft-Login folgende Daten von der Microsoft Graph API abgerufen und verarbeitet:

**Welche Daten:** Anzeigename (`displayName`), Vorname, Nachname, E-Mail-Adresse (`mail`, `userPrincipalName`), Berufsbezeichnung (`jobTitle`).

**Zweck:** Automatisches Ausfüllen des Buchungsformulars mit den Profildaten des Nutzers.

**Rechtsgrundlage:** Art. 6 Abs. 1 lit. a DSGVO (Einwilligung des Nutzers durch aktives Anmelden via Microsoft).

**Übermittlung an Dritte:** Die Authentifizierung erfolgt über Microsoft Azure AD. Daten werden an Microsoft Ireland Operations Limited übermittelt. Microsoft ist unter dem EU-U.S. Data Privacy Framework zertifiziert. Weitere Informationen: [https://privacy.microsoft.com](https://privacy.microsoft.com).

**Speicherdauer:** Die abgerufenen Profilinformationen werden nur zur Vorausfüllung des Buchungsformulars verwendet und nicht dauerhaft in der Microsoft-Verbindung gespeichert. Die im Buchungsformular eingetragenen Daten unterliegen Ziffer 3.1.

---

### 3.4 Sitzungsdaten (Sessions)

**Welche Daten:** Benutzername des angemeldeten Administrators, Authentifizierungsstatus, CSRF-Token.

**Zweck:** Aufrechterhaltung der Anmeldesitzung im Admin-Bereich.

**Rechtsgrundlage:** Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an der Sicherheit des Administrationsbereichs).

**Speicherort:** Lokal auf dem Server des Betreibers (In-Memory oder Dateisystem, Ordner `sessions/`).

**Speicherdauer:** 24 Stunden, danach automatische Löschung.

---

### 3.5 Lizenzvalidierung (Keygen.sh)

Zur Aktivierung und Validierung der Softwarelizenz kommuniziert KomDesk mit dem Dienst **Keygen.sh** der Keygen, LLC (USA).

**Welche Daten werden übermittelt:**
- Lizenzschlüssel
- Machine-Fingerprint (SHA-256-Hash aus Hostname und MAC-Adresse des Servers)
- Hostname des Servers
- Betriebssystem-Plattform

**Zweck:** Aktivierung, Validierung und Deaktivierung der Softwarelizenz; täglicher Heartbeat zur Bestätigung des aktiven Lizenzstatus.

**Rechtsgrundlage:** Art. 6 Abs. 1 lit. b DSGVO (Erfüllung des Lizenzvertrags).

**Drittlandübermittlung:** Keygen, LLC hat Sitz in den USA. Die Übermittlung erfolgt auf Grundlage geeigneter Garantien (Standardvertragsklauseln gemäß Art. 46 DSGVO). Weitere Informationen: [https://keygen.sh/privacy](https://keygen.sh/privacy).

**Speicherdauer:** Die Daten werden bei Keygen.sh für die Laufzeit der Lizenz gespeichert und bei Deaktivierung gelöscht.

---

### 3.6 Update-Prüfung (GitHub)

KomDesk prüft automatisch auf neue Softwareversionen durch Abruf einer Versionsdatei von GitHub.

**Welche Daten:** IP-Adresse des Servers (technisch unvermeidbar bei HTTP-Anfragen).

**Zweck:** Prüfung auf verfügbare Software-Updates.

**Rechtsgrundlage:** Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an der Aktualität der Software).

**Drittlandübermittlung:** GitHub, Inc. (USA) ist unter dem EU-U.S. Data Privacy Framework zertifiziert. Weitere Informationen: [https://docs.github.com/de/site-policy/privacy-policies/github-general-privacy-statement](https://docs.github.com/de/site-policy/privacy-policies/github-general-privacy-statement).

**Speicherdauer:** Gemäß GitHub-Datenschutzrichtlinie.

---

### 3.7 TRMNL-Terminals (optional)

Wenn der Betreiber physische TRMNL-Displaygeräte konfiguriert, werden bei Belegungsänderungen Raumdaten per Webhook an die konfigurierten Endpunkte übermittelt.

**Welche Daten:** Raumbezeichnung, Sitzplatzstatus (Name/Frei, Jobtitel), Logo-Grafik.

**Zweck:** Echtzeitanzeige der Raumbelegung auf externen Displays.

**Rechtsgrundlage:** Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse des Betreibers an der Raumanzeige).

**Hinweis:** Die Webhook-URLs und der Empfänger der Daten liegen im Verantwortungsbereich des Betreibers/Lizenznehmers.

---

## 4. Empfänger personenbezogener Daten

| Empfänger | Zweck | Sitz | Rechtsgrundlage Drittland |
|-----------|-------|------|--------------------------|
| Keygen, LLC | Lizenzvalidierung | USA | SCCs / DPF |
| Microsoft Ireland Operations Limited | SSO (optional) | Irland / USA | EU-U.S. DPF |
| GitHub, Inc. | Update-Prüfung | USA | EU-U.S. DPF |
| TRMNL (Webhooks) | Displayanzeige (optional) | Konfiguriert durch Betreiber | — |

---

## 5. Betroffenenrechte

Gemäß DSGVO haben betroffene Personen folgende Rechte:

- **Art. 15 DSGVO** – Auskunftsrecht: Sie können Auskunft über die zu Ihrer Person gespeicherten Daten verlangen.
- **Art. 16 DSGVO** – Berichtigungsrecht: Sie können die Berichtigung unrichtiger Daten verlangen.
- **Art. 17 DSGVO** – Recht auf Löschung: Sie können die Löschung Ihrer personenbezogenen Daten verlangen, soweit keine Aufbewahrungspflichten entgegenstehen.
- **Art. 18 DSGVO** – Recht auf Einschränkung der Verarbeitung.
- **Art. 20 DSGVO** – Recht auf Datenübertragbarkeit.
- **Art. 21 DSGVO** – Widerspruchsrecht gegen Verarbeitungen auf Basis von Art. 6 Abs. 1 lit. f DSGVO.
- **Art. 77 DSGVO** – Beschwerderecht bei einer Aufsichtsbehörde.

Zur Ausübung Ihrer Rechte wenden Sie sich an: komdesk@komvera.de

**Zuständige Aufsichtsbehörde:**  
Landesbeauftragte für Datenschutz und Informationsfreiheit Nordrhein-Westfalen (LDI NRW)  
Kavalleriestraße 2–4, 40213 Düsseldorf  
https://www.ldi.nrw.de

---

## 6. Hinweis für Betreiber (Lizenznehmer)

KomDesk wird lokal beim Lizenznehmer betrieben. Der Lizenznehmer ist selbst **Verantwortlicher** im Sinne der DSGVO für die durch seine Mitarbeiter eingegebenen Daten. Die Komvera IT GmbH tritt in dieser Konstellation als **Auftragsverarbeiter** im Sinne von Art. 28 DSGVO auf, sofern sie Zugriff auf die Daten erhält (z.B. im Rahmen von Support).

Ein **Auftragsverarbeitungsvertrag (AVV)** nach Art. 28 DSGVO zwischen dem Lizenznehmer und der Komvera IT GmbH kann auf Anfrage bereitgestellt werden.

---

## 7. Datensicherheit

Die Software verwendet folgende Sicherheitsmaßnahmen:

- Passwort-Hashing mit bcrypt (Kostenfaktor 12)
- AES-256-GCM-Verschlüsselung für Konfigurationsdaten und Lizenzinformationen
- CSRF-Schutz für alle administrativen Formulare
- HttpOnly-Cookies zum Schutz vor XSS
- HTTP-Security-Header (Helmet.js)
- Rate-Limiting für Login und SSH-Token-Erzeugung

---

## 8. Änderungen dieser Datenschutzerklärung

Komvera IT GmbH behält sich vor, diese Datenschutzerklärung bei technischen Änderungen der Software oder geänderten Rechtsgrundlagen zu aktualisieren. Die jeweils aktuelle Version ist im Software-Paket und auf der Webseite von Komvera IT GmbH verfügbar.

---

*Komvera IT GmbH – Stand: April 2026*
