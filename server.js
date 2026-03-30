const express = require('express');
const cors = require('cors');
const session = require('express-session');
const { ConfidentialClientApplication } = require('@azure/msal-node');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');
const sharp = require('sharp');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const BCRYPT_ROUNDS = 12;

if (process.env.HTTPS_ENABLED === 'true') {
    app.set('trust proxy', 1);
}

app.use((req, res, next) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    next();
});

app.use(helmet({
    contentSecurityPolicy: false
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Zu viele Login-Versuche. Bitte 15 Minuten warten.',
    standardHeaders: true,
    legacyHeaders: false,
});

const setupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: 'Zu viele Setup-Versuche. Bitte 1 Stunde warten.',
    standardHeaders: true,
    legacyHeaders: false,
});

/*
==================================================
DATEIEN
==================================================
*/
const DATA_DIR = __dirname;
const PUBLIC_DIR = path.join(__dirname, 'public');
const LOGO_FILE = path.join(PUBLIC_DIR, 'logo.png');
const ROOMS_FILE = path.join(DATA_DIR, 'rooms.json');
const ADMINS_FILE = path.join(DATA_DIR, 'admins.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const KEY_FILE = path.join(DATA_DIR, 'app.key');

/*
==================================================
BERECHTIGUNGEN
==================================================
*/
const PERMISSION_GROUPS = [
    {
        title: 'Allgemein',
        permissions: [
            {
                key: 'dashboard.view',
                label: 'Dashboard anzeigen',
                description: 'Darf die Startseite des Adminbereichs öffnen.'
            }
        ]
    },
    {
        title: 'Räume',
        permissions: [
            {
                key: 'rooms.view',
                label: 'Räume anzeigen',
                description: 'Darf alle Räume und deren Belegung sehen.'
            },
            {
                key: 'rooms.create',
                label: 'Räume erstellen',
                description: 'Darf neue Räume anlegen.'
            },
            {
                key: 'rooms.edit',
                label: 'Räume bearbeiten',
                description: 'Darf Abteilung und Raumnummer bestehender Räume ändern.'
            },
            {
                key: 'rooms.delete',
                label: 'Räume löschen',
                description: 'Darf komplette Räume entfernen.'
            },
            {
                key: 'rooms.clearSeat',
                label: 'Plätze leeren',
                description: 'Darf belegte Sitzplätze wieder freigeben.'
            }
        ]
    },
    {
        title: 'Raumlinks / Ansichten',
        permissions: [
            {
                key: 'links.view',
                label: 'Raumlinks anzeigen',
                description: 'Darf die Übersicht mit allen Raumansichten, APIs und Sitzplatzlinks sehen.'
            }
        ]
    },
    {
        title: 'Admins',
        permissions: [
            {
                key: 'admins.view',
                label: 'Admins anzeigen',
                description: 'Darf die Adminverwaltung öffnen.'
            },
            {
                key: 'admins.create',
                label: 'Admins erstellen',
                description: 'Darf neue Admins anlegen.'
            },
            {
                key: 'admins.edit',
                label: 'Admins bearbeiten',
                description: 'Darf Berechtigungen anderer normaler Admins ändern.'
            },
            {
                key: 'admins.delete',
                label: 'Admins löschen',
                description: 'Darf normale Admins löschen. Der Master ist ausgenommen.'
            }
        ]
    },
    {
        title: 'Microsoft',
        permissions: [
            {
                key: 'microsoft.view',
                label: 'Microsoft-Konfiguration anzeigen',
                description: 'Darf die gespeicherten Microsoft-/Entra-Daten sehen.'
            },
            {
                key: 'microsoft.edit',
                label: 'Microsoft-Konfiguration bearbeiten',
                description: 'Darf Client-ID, Tenant-ID, Secret und Callback ändern.'
            }
        ]
    },
    {
        title: 'System',
        permissions: [
            {
                key: 'system.settings',
                label: 'System-Einstellungen',
                description: 'Darf Session Secret ändern.'
            },
            {
                key: 'system.logo',
                label: 'Logo verwalten',
                description: 'Darf das Logo der Anwendung hochladen und ersetzen.'
            }
        ]
    }
];

const AVAILABLE_PERMISSIONS = PERMISSION_GROUPS.flatMap(group =>
    group.permissions.map(permission => permission.key)
);

/*
==================================================
DEFAULTS
==================================================
*/
const DEFAULT_ROOMS = {
    room1: {
        id: 'room1',
        abteilung: 'IT',
        roomnumber: 'R.201',
        seats: [
            { name: 'Frei', title: '' },
            { name: 'Frei', title: '' },
            { name: 'Frei', title: '' },
            { name: 'Frei', title: '' }
        ]
    },
    room2: {
        id: 'room2',
        abteilung: 'Buchhaltung',
        roomnumber: 'R.103',
        seats: [
            { name: 'Frei', title: '' },
            { name: 'Frei', title: '' },
            { name: 'Frei', title: '' },
            { name: 'Frei', title: '' }
        ]
    }
};

const DEFAULT_CONFIG = {
    sessionSecret: '',
    seatClearInterval: 'never',
    microsoftLoginEnabled: false,
    microsoft: {
        clientID: '',
        tenantID: '',
        clientSecret: '',
        callbackURL: ''
    }
};

const SEAT_CLEAR_OPTIONS = [
    { value: 'never', label: 'Nie' },
    { value: '1h',    label: '1 Stunde' },
    { value: '2h',    label: '2 Stunden' },
    { value: '8h',    label: '8 Stunden' },
    { value: '24h',   label: '24 Stunden (1 Tag)' },
    { value: '1w',    label: '1 Woche' },
];

function seatClearIntervalMs() {
    switch (String(appConfig.seatClearInterval || 'never')) {
        case '1h':  return 1 * 60 * 60 * 1000;
        case '2h':  return 2 * 60 * 60 * 1000;
        case '8h':  return 8 * 60 * 60 * 1000;
        case '24h': return 24 * 60 * 60 * 1000;
        case '1w':  return 7 * 24 * 60 * 60 * 1000;
        default:    return null;
    }
}

function runSeatAutoClear() {
    const ms = seatClearIntervalMs();
    if (!ms) return;
    const now = Date.now();
    let changed = false;
    Object.values(rooms).forEach(room => {
        room.seats.forEach((seat, i) => {
            if (seat.name && seat.name !== 'Frei' && seat.since && (now - seat.since) >= ms) {
                room.seats[i] = { name: 'Frei', title: '' };
                changed = true;
            }
        });
    });
    if (changed) saveRooms();
}

/*
==================================================
VERSCHLÜSSELUNG
==================================================
*/
function getOrCreateEncryptionKey() {
    if (fs.existsSync(KEY_FILE)) {
        const key = fs.readFileSync(KEY_FILE);
        if (key.length === 32) return key;
    }
    const key = crypto.randomBytes(32);
    fs.writeFileSync(KEY_FILE, key);
    return key;
}

function encryptValue(plaintext) {
    if (!plaintext) return '';
    try {
        const key = getOrCreateEncryptionKey();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        return 'enc:' + iv.toString('hex') + ':' + authTag + ':' + encrypted;
    } catch (err) {
        console.error('Verschlüsselung fehlgeschlagen:', err);
        return plaintext;
    }
}

function decryptValue(ciphertext) {
    if (!ciphertext) return '';
    if (!String(ciphertext).startsWith('enc:')) return String(ciphertext);
    try {
        const key = getOrCreateEncryptionKey();
        const parts = ciphertext.slice(4).split(':');
        if (parts.length < 3) return '';
        const ivHex = parts[0];
        const authTagHex = parts[1];
        const encrypted = parts.slice(2).join(':');
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error('Entschlüsselung fehlgeschlagen:', err);
        return '';
    }
}

/*
==================================================
JSON FUNKTIONEN
==================================================
*/
function deepClone(value) {
    return JSON.parse(JSON.stringify(value));
}

function ensureJsonFile(filePath, defaultValue) {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2), 'utf8');
        return deepClone(defaultValue);
    }

    try {
        const raw = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        console.error(`Fehler beim Laden von ${filePath}:`, err);
        fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2), 'utf8');
        return deepClone(defaultValue);
    }
}

function writeJsonFile(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

/*
==================================================
DATEN LADEN
==================================================
*/
let rooms = ensureJsonFile(ROOMS_FILE, DEFAULT_ROOMS);
let admins = ensureJsonFile(ADMINS_FILE, []);
let appConfig = ensureJsonFile(CONFIG_FILE, DEFAULT_CONFIG);

if (!appConfig || typeof appConfig !== 'object') {
    appConfig = deepClone(DEFAULT_CONFIG);
}

if (typeof appConfig.sessionSecret !== 'string') {
    appConfig.sessionSecret = '';
}
appConfig.sessionSecret = decryptValue(appConfig.sessionSecret);

if (!appConfig.microsoft || typeof appConfig.microsoft !== 'object') {
    appConfig.microsoft = deepClone(DEFAULT_CONFIG.microsoft);
}

let microsoftConfig = {
    ...appConfig.microsoft,
    clientSecret: decryptValue(appConfig.microsoft.clientSecret || '')
};

/*
==================================================
EXPRESS BASIS
==================================================
*/
app.use(express.static('public'));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/*
==================================================
UPLOAD
==================================================
*/
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024
    },
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = [
            'image/png',
            'image/jpeg',
            'image/jpg',
            'image/webp'
        ];

        if (!allowedMimeTypes.includes(file.mimetype)) {
            return cb(new Error('Nur PNG, JPG, JPEG oder WEBP sind erlaubt.'));
        }

        cb(null, true);
    }
});

/*
==================================================
HILFSFUNKTIONEN
==================================================
*/
function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/*
==================================================
CSRF
==================================================
*/
function getCsrfToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
}

function csrfField(req) {
    return `<input type="hidden" name="_csrf" value="${getCsrfToken(req)}">`;
}

function requireCsrf(req, res, next) {
    const token = String(req.body._csrf || req.query._csrf || '');
    if (!token || !req.session.csrfToken || token !== req.session.csrfToken) {
        return res.status(403).send('Ungültige Anfrage (CSRF-Fehler). Bitte Seite neu laden.');
    }
    next();
}

function ensurePublicDir() {
    if (!fs.existsSync(PUBLIC_DIR)) {
        fs.mkdirSync(PUBLIC_DIR, { recursive: true });
    }
}

async function saveLogoFromBuffer(fileBuffer) {
    ensurePublicDir();

    await sharp(fileBuffer)
        .png()
        .toFile(LOGO_FILE);
}

function renderSupportFooter(extraText = '') {
    return `
        <div class="support-footer">
            ${extraText ? `<div class="support-footer-text">${extraText}</div>` : ''}
            <div>
                &copy; ${new Date().getFullYear()} Komvera IT GmbH ·
                <a href="https://www.komvera.de" target="_blank" rel="noopener noreferrer">www.komvera.de</a> ·
                <a href="mailto:info@komvera.de">info@komvera.de</a>
            </div>
        </div>
    `;
}

function saveRooms() {
    writeJsonFile(ROOMS_FILE, rooms);
}

function saveAdmins() {
    writeJsonFile(ADMINS_FILE, admins);
}

function saveAppConfig() {
    const toWrite = {
        ...appConfig,
        sessionSecret: encryptValue(appConfig.sessionSecret || ''),
        microsoft: {
            ...microsoftConfig,
            clientSecret: encryptValue(microsoftConfig.clientSecret || '')
        }
    };
    writeJsonFile(CONFIG_FILE, toWrite);
}

function saveMicrosoftConfig() {
    appConfig.microsoft = microsoftConfig;
    saveAppConfig();
}

function hasAnyAdmins() {
    return Array.isArray(admins) && admins.length > 0;
}

function getRoom(roomId) {
    return rooms[roomId] || null;
}


function normalizeAdmin(admin) {
    return {
        username: String(admin?.username || '').trim(),
        displayName: String(admin?.displayName || '').trim(),
        passwordHash: String(admin?.passwordHash || ''),
        master: Boolean(admin?.master),
        permissions: Array.isArray(admin?.permissions)
            ? admin.permissions.filter(p => AVAILABLE_PERMISSIONS.includes(p))
            : []
    };
}

function getAdminUser(username) {
    return admins.find(a => a.username === username) || null;
}

function getCurrentAdmin(req) {
    if (!req.session?.adminUsername) {
        return null;
    }
    return getAdminUser(req.session.adminUsername);
}

function hasPermission(req, permission) {
    const admin = getCurrentAdmin(req);

    if (!admin) {
        return false;
    }

    if (admin.master) {
        return true;
    }

    return admin.permissions.includes(permission);
}

function isSetupRequired() {
    return !hasAnyAdmins() || !String(appConfig.sessionSecret || '').trim();
}

function generateStrongSecret() {
    return crypto.randomBytes(64).toString('hex');
}

function ensureSingleMasterAdmin() {
    admins = Array.isArray(admins) ? admins.map(normalizeAdmin) : [];

    const masters = admins.filter(a => a.master);

    if (masters.length <= 1) {
        saveAdmins();
        return;
    }

    const firstMaster = masters[0];

    admins = admins.map(admin => ({
        ...admin,
        master: admin.username === firstMaster.username
    }));

    saveAdmins();
}

function isMicrosoftLoginEnabled() {
    return appConfig.microsoftLoginEnabled === true;
}

function hasMicrosoftConfig() {
    return Boolean(
        String(microsoftConfig.clientID || '').trim() &&
        String(microsoftConfig.tenantID || '').trim() &&
        String(microsoftConfig.clientSecret || '').trim() &&
        String(microsoftConfig.callbackURL || '').trim()
    );
}

function requireAdmin(req, res, next) {
    if (req.session && req.session.adminAuthenticated && getCurrentAdmin(req)) {
        return next();
    }
    return res.redirect('/admin/login');
}

function requirePermission(permission) {
    return (req, res, next) => {
        if (hasPermission(req, permission)) {
            return next();
        }

        return res.status(403).send(`
            <html lang="de">
            <head>
                <meta charset="UTF-8">
                <title>Keine Berechtigung</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding-top: 60px;
                    }
                    .support-footer {
                        margin-top: 30px;
                        padding-top: 18px;
                        border-top: 1px solid #e5e7eb;
                        text-align: center;
                        font-size: 14px;
                        color: #6b7280;
                    }
                    .support-footer a {
                        color: #2563eb;
                        text-decoration: none;
                    }
                    .support-footer a:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <h2>Keine Berechtigung</h2>
                <p>Dir fehlt die Berechtigung: ${escapeHtml(permission)}</p>
                <p><a href="/admin">Zurück zum Adminbereich</a></p>
                ${renderSupportFooter()}
            </body>
            </html>
        `);
    };
}

function renderPermissionCheckboxes(selectedPermissions = []) {
    const allKeys = PERMISSION_GROUPS.flatMap(g => g.permissions.map(p => p.key));
    const allSelected = allKeys.every(k => selectedPermissions.includes(k));

    const groupsHtml = PERMISSION_GROUPS.map((group, gi) => {
        const groupKeys = group.permissions.map(p => p.key);
        const groupSelected = groupKeys.every(k => selectedPermissions.includes(k));
        return `
        <div class="perm-group">
            <div class="perm-group-header" onclick="permToggleGroup(this)">
                <span class="perm-group-arrow">&#9654;</span>
                <span class="perm-group-title-text">${escapeHtml(group.title)}</span>
                <button type="button" class="perm-group-all-btn" onclick="event.stopPropagation();permToggleGroupAll(this)"
                    data-group="${gi}" ${groupSelected ? 'data-all="1"' : ''}>
                    ${groupSelected ? 'Alle abwählen' : 'Alle wählen'}
                </button>
            </div>
            <div class="perm-group-list" style="display:none;">
                ${group.permissions.map(permission => `
                    <label class="perm-item">
                        <div class="perm-text">
                            <div class="perm-label">
                                ${escapeHtml(permission.label)}
                                <span class="perm-info-wrap">
                                    <span class="perm-info-btn" tabindex="0" aria-label="Info">&#x24D8;</span>
                                    <span class="perm-tooltip">${escapeHtml(permission.description)}</span>
                                </span>
                            </div>
                        </div>
                        <div class="perm-check">
                            <input
                                type="checkbox"
                                name="permissions"
                                value="${escapeHtml(permission.key)}"
                                data-group="${gi}"
                                onchange="permSyncGroupBtn(${gi})"
                                ${selectedPermissions.includes(permission.key) ? 'checked' : ''}
                            >
                        </div>
                    </label>
                `).join('')}
            </div>
        </div>
    `}).join('');

    return `
        <div class="perm-global-bar">
            <button type="button" class="perm-all-btn" id="permAllBtn" onclick="permToggleAll(this)"
                ${allSelected ? 'data-all="1"' : ''}>
                ${allSelected ? '&#10007; Alle abwählen' : '&#10003; Alle Berechtigungen'}
            </button>
        </div>
        ${groupsHtml}
    `;
}

function formatAdminPermissions(admin) {
    if (admin.master) {
        return '<span class="badge badge-master">Alle Rechte</span>';
    }

    const granted = PERMISSION_GROUPS.map(group => {
        const matches = group.permissions.filter(permission =>
            admin.permissions.includes(permission.key)
        );

        if (matches.length === 0) {
            return '';
        }

        return `
            <div style="margin-bottom:10px;">
                <div style="font-weight:700;margin-bottom:4px;">${escapeHtml(group.title)}</div>
                ${matches.map(item => `<div class="muted">• ${escapeHtml(item.label)}</div>`).join('')}
            </div>
        `;
    }).filter(Boolean).join('');

    return granted || '<span class="muted">Keine Rechte</span>';
}

function renderSidebar(req) {
    const logoExists = fs.existsSync(LOGO_FILE);
    const currentAdmin = getCurrentAdmin(req);

    const items = [
        hasPermission(req, 'dashboard.view') ? `<a href="/admin">&#9632; Dashboard</a>` : '',
        hasPermission(req, 'rooms.view') ? `<a href="/admin/rooms">&#9632; Räume</a>` : '',
        hasPermission(req, 'links.view') ? `<a href="/admin/links">&#9632; Raumlinks</a>` : '',
        hasPermission(req, 'admins.view') ? `<a href="/admin/admins">&#9632; Admins</a>` : '',
        hasPermission(req, 'microsoft.view') ? `<a href="/admin/microsoft">&#9632; Microsoft</a>` : '',
        hasPermission(req, 'system.settings') ? `<a href="/admin/system">&#9632; System</a>` : '',
        hasPermission(req, 'system.logo') ? `<a href="/admin/logo">&#9632; Logo</a>` : '',
        `<a href="/admin/account">&#9632; Mein Konto</a>`,
        `<a href="/admin/logout" style="color:#f87171;">&#9632; Logout</a>`
    ].filter(Boolean).join('');

    return `
        <aside class="sidebar">
            <div class="sidebar-brand">
                ${logoExists ? `<img src="/logo.png" alt="Logo" class="sidebar-logo">` : ''}
                <span class="brand-text">DeskView Admin</span>
            </div>
            ${currentAdmin ? `<div class="sidebar-user">${escapeHtml(currentAdmin.displayName || currentAdmin.username)}${currentAdmin.master ? ' <span class="badge-master-sm">MASTER</span>' : ''}<div style="font-size:11px;opacity:0.6;margin-top:2px;">@${escapeHtml(currentAdmin.username)}</div></div>` : ''}
            <nav class="nav">
                ${items}
            </nav>
            <div class="sidebar-footer">
                <button class="theme-toggle" onclick="toggleTheme()" title="Hell/Dunkel umschalten">&#9790; Modus</button>
            </div>
        </aside>
    `;
}

function renderAdminLayout(req, title, content) {
    return `
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${escapeHtml(title)} – DeskView Admin</title>
        <style>
            * { box-sizing: border-box; }
            :root {
                --bg: #f4f6f8;
                --card-bg: #ffffff;
                --text: #1f2937;
                --muted: #6b7280;
                --border: #e5e7eb;
                --primary: #2563eb;
                --primary-hover: #1d4ed8;
                --sidebar-bg: #0f172a;
                --sidebar-hover: #1e293b;
                --sidebar-text: #cbd5e1;
                --input-bg: #ffffff;
                --input-border: #d1d5db;
                --notice-bg: #eff6ff;
                --notice-text: #1d4ed8;
                --notice-border: #bfdbfe;
                --warn-bg: #fff7ed;
                --warn-text: #9a3412;
                --warn-border: #fdba74;
                --code-bg: #111827;
                --code-text: #f9fafb;
                --perm-bg: #f9fafb;
                --perm-item-bg: #ffffff;
                --shadow: 0 10px 30px rgba(0,0,0,0.07);
                --th-bg: #f9fafb;
            }
            [data-theme="dark"] {
                --bg: #0f172a;
                --card-bg: #1e293b;
                --text: #f1f5f9;
                --muted: #94a3b8;
                --border: #334155;
                --primary: #3b82f6;
                --primary-hover: #2563eb;
                --sidebar-bg: #020617;
                --sidebar-hover: #0f172a;
                --sidebar-text: #94a3b8;
                --input-bg: #0f172a;
                --input-border: #334155;
                --notice-bg: #1e3a5f;
                --notice-text: #93c5fd;
                --notice-border: #1e40af;
                --warn-bg: #431407;
                --warn-text: #fdba74;
                --warn-border: #92400e;
                --code-bg: #020617;
                --code-text: #f8fafc;
                --perm-bg: #0f172a;
                --perm-item-bg: #1e293b;
                --shadow: 0 10px 30px rgba(0,0,0,0.4);
                --th-bg: #0f172a;
            }
            body {
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                background: var(--bg);
                color: var(--text);
                transition: background 0.2s, color 0.2s;
            }
            .layout {
                display: flex;
                min-height: 100vh;
            }
            .sidebar {
                width: 260px;
                background: var(--sidebar-bg);
                color: var(--sidebar-text);
                padding: 0;
                display: flex;
                flex-direction: column;
                position: sticky;
                top: 0;
                height: 100vh;
                overflow-y: auto;
                flex-shrink: 0;
            }
            .sidebar-brand {
                display: flex;
                flex-direction: column;
                align-items: center;
                padding: 24px 18px 16px 18px;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                gap: 10px;
            }
            .sidebar-logo {
                max-width: 180px;
                max-height: 80px;
                width: auto;
                height: auto;
                object-fit: contain;
            }
            .brand-text {
                font-size: 13px;
                font-weight: 600;
                color: #64748b;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            }
            .sidebar-user {
                padding: 10px 18px;
                font-size: 13px;
                color: #64748b;
                border-bottom: 1px solid rgba(255,255,255,0.06);
            }
            .badge-master-sm {
                background: #854d0e;
                color: #fef3c7;
                font-size: 10px;
                padding: 2px 6px;
                border-radius: 4px;
                font-weight: 700;
                vertical-align: middle;
            }
            .nav {
                flex: 1;
                padding: 12px 12px;
                display: flex;
                flex-direction: column;
                gap: 2px;
            }
            .nav a {
                display: block;
                color: var(--sidebar-text);
                text-decoration: none;
                padding: 10px 14px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 500;
                transition: background 0.15s, color 0.15s;
            }
            .nav a:hover {
                background: var(--sidebar-hover);
                color: #f1f5f9;
            }
            .sidebar-footer {
                padding: 16px 18px;
                border-top: 1px solid rgba(255,255,255,0.08);
            }
            .theme-toggle {
                width: 100%;
                padding: 8px 12px;
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 8px;
                color: var(--sidebar-text);
                font-size: 13px;
                cursor: pointer;
                text-align: left;
                transition: background 0.15s;
            }
            .theme-toggle:hover {
                background: rgba(255,255,255,0.12);
            }
            .main {
                flex: 1;
                padding: 30px;
                display: flex;
                flex-direction: column;
                min-height: 100vh;
                overflow-x: hidden;
            }
            .page-content {
                flex: 1;
            }
            .page-title {
                margin-top: 0;
                margin-bottom: 24px;
                font-size: 28px;
                font-weight: 700;
                color: var(--text);
            }
            .card {
                background: var(--card-bg);
                border-radius: 16px;
                padding: 22px;
                box-shadow: var(--shadow);
                margin-bottom: 22px;
                border: 1px solid var(--border);
            }
            .grid-2 {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 22px;
            }
            .grid-3 {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 22px;
            }
            .stat {
                font-size: 34px;
                font-weight: bold;
                margin-top: 10px;
                color: var(--primary);
            }
            label {
                display: block;
                margin-bottom: 6px;
                font-weight: 600;
                font-size: 14px;
                color: var(--text);
            }
            input, textarea, select {
                width: 100%;
                padding: 11px 14px;
                border: 1px solid var(--input-border);
                border-radius: 10px;
                margin-bottom: 14px;
                font-size: 15px;
                background: var(--input-bg);
                color: var(--text);
                transition: border-color 0.15s, background 0.2s, color 0.2s;
            }
            input:focus, textarea:focus, select:focus {
                outline: none;
                border-color: var(--primary);
            }
            input[type="file"] {
                padding: 10px;
                background: var(--input-bg);
            }
            button {
                padding: 11px 18px;
                border: none;
                border-radius: 10px;
                background: var(--primary);
                color: white;
                font-weight: 700;
                font-size: 14px;
                cursor: pointer;
                transition: background 0.15s, transform 0.1s;
            }
            button:hover {
                background: var(--primary-hover);
            }
            button:active {
                transform: scale(0.98);
            }
            .btn-danger {
                background: #dc2626;
            }
            .btn-danger:hover {
                background: #b91c1c;
            }
            .btn-secondary {
                background: #6b7280;
            }
            .btn-secondary:hover {
                background: #4b5563;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th {
                text-align: left;
                padding: 10px 12px;
                border-bottom: 2px solid var(--border);
                font-size: 13px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.04em;
                color: var(--muted);
                background: var(--th-bg);
            }
            td {
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid var(--border);
                vertical-align: top;
                color: var(--text);
            }
            tr:last-child td {
                border-bottom: none;
            }
            .muted {
                color: var(--muted);
            }
            .topbar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
                gap: 16px;
            }
            .small-link {
                color: var(--primary);
                text-decoration: none;
                font-size: 14px;
            }
            .small-link:hover {
                text-decoration: underline;
            }
            .inline-form {
                display: inline;
            }
            .badge {
                display: inline-block;
                padding: 4px 10px;
                border-radius: 999px;
                background: #eef2ff;
                color: #3730a3;
                font-size: 12px;
                font-weight: 700;
            }
            .badge-master {
                background: #fef3c7;
                color: #92400e;
            }
            .links-row a {
                display: inline-block;
                margin-right: 10px;
                margin-bottom: 10px;
            }
            .permission-box {
                background: var(--perm-bg);
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 16px;
            }
            .toggle-switch { position:relative; display:inline-block; width:44px; height:24px; flex-shrink:0; }
            .toggle-switch input { opacity:0; width:0; height:0; }
            .toggle-slider { position:absolute; cursor:pointer; inset:0; background:var(--border); border-radius:24px; transition:.2s; }
            .toggle-slider:before { content:''; position:absolute; width:18px; height:18px; left:3px; bottom:3px; background:#fff; border-radius:50%; transition:.2s; }
            .toggle-switch input:checked + .toggle-slider { background:var(--primary); }
            .toggle-switch input:checked + .toggle-slider:before { transform:translateX(20px); }
            .perm-global-bar {
                margin-bottom: 12px;
            }
            .perm-all-btn {
                background: var(--primary);
                color: #fff;
                border: none;
                border-radius: 8px;
                padding: 7px 14px;
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.15s, opacity 0.15s;
            }
            .perm-all-btn:hover { opacity: 0.88; }
            .perm-group {
                margin-bottom: 6px;
                border: 1px solid var(--border);
                border-radius: 12px;
                overflow: hidden;
            }
            .perm-group:last-child {
                margin-bottom: 0;
            }
            .perm-group-header {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 11px 14px;
                cursor: pointer;
                background: var(--perm-item-bg);
                user-select: none;
                transition: background 0.15s;
            }
            .perm-group-header:hover { background: var(--border); }
            .perm-group-arrow {
                font-size: 10px;
                color: var(--muted);
                transition: transform 0.2s;
                display: inline-block;
                flex-shrink: 0;
            }
            .perm-group-header.open .perm-group-arrow {
                transform: rotate(90deg);
            }
            .perm-group-title-text {
                font-size: 14px;
                font-weight: 700;
                color: var(--text);
                text-transform: uppercase;
                letter-spacing: 0.05em;
                flex: 1;
            }
            .perm-group-all-btn {
                background: none;
                border: 1px solid var(--border);
                border-radius: 6px;
                padding: 4px 10px;
                font-size: 12px;
                font-weight: 600;
                color: var(--muted);
                cursor: pointer;
                transition: border-color 0.15s, color 0.15s;
                white-space: nowrap;
            }
            .perm-group-all-btn:hover { border-color: var(--primary); color: var(--primary); }
            .perm-group-list {
                display: flex;
                flex-direction: column;
                gap: 0;
                border-top: 1px solid var(--border);
            }
            .perm-item {
                border-bottom: 1px solid var(--border);
            }
            .perm-item:last-child {
                border-bottom: none;
            }
            .perm-item {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 16px;
                background: var(--perm-item-bg);
                padding: 12px 14px;
                margin: 0;
                font-weight: normal;
                transition: background 0.15s;
            }
            .perm-item:hover {
                background: var(--card-bg);
            }
            .perm-text {
                flex: 1;
            }
            .perm-label {
                font-weight: 700;
                color: var(--text);
                font-size: 14px;
                display: flex;
                align-items: center;
                gap: 6px;
            }
            .perm-info-wrap {
                position: relative;
                display: inline-flex;
                align-items: center;
            }
            .perm-info-btn {
                font-size: 14px;
                color: var(--muted);
                cursor: default;
                line-height: 1;
                user-select: none;
                transition: color 0.15s;
            }
            .perm-info-wrap:hover .perm-info-btn,
            .perm-info-wrap:focus-within .perm-info-btn {
                color: var(--primary);
            }
            .perm-tooltip {
                display: none;
                position: absolute;
                left: calc(100% + 10px);
                top: 50%;
                transform: translateY(-50%);
                background: var(--surface);
                border: 1px solid var(--border);
                color: var(--text);
                font-size: 13px;
                font-weight: 400;
                line-height: 1.5;
                padding: 9px 13px;
                border-radius: 10px;
                white-space: normal;
                width: 210px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.15);
                z-index: 20;
                pointer-events: none;
            }
            .perm-tooltip::before {
                content: '';
                position: absolute;
                right: 100%;
                top: 50%;
                transform: translateY(-50%);
                border: 6px solid transparent;
                border-right-color: var(--border);
            }
            .perm-tooltip::after {
                content: '';
                position: absolute;
                right: 100%;
                top: 50%;
                transform: translateY(-50%);
                border: 5px solid transparent;
                border-right-color: var(--surface);
                margin-right: -1px;
            }
            .perm-info-wrap:hover .perm-tooltip,
            .perm-info-wrap:focus-within .perm-tooltip {
                display: block;
            }
            .perm-check {
                flex-shrink: 0;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .perm-check input[type="checkbox"] {
                width: 18px;
                height: 18px;
                margin: 0;
                accent-color: var(--primary);
            }
            .notice {
                padding: 12px 14px;
                border-radius: 10px;
                background: var(--notice-bg);
                color: var(--notice-text);
                margin-bottom: 16px;
                border: 1px solid var(--notice-border);
                font-size: 14px;
            }
            .notice-warn {
                background: var(--warn-bg);
                color: var(--warn-text);
                border-color: var(--warn-border);
            }
            .code-box {
                background: var(--code-bg);
                color: var(--code-text);
                padding: 14px;
                border-radius: 12px;
                overflow: auto;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 13px;
                word-break: break-all;
            }
            .support-footer {
                margin-top: 30px;
                padding-top: 18px;
                border-top: 1px solid var(--border);
                text-align: center;
                font-size: 13px;
                color: var(--muted);
            }
            .support-footer a {
                color: var(--primary);
                text-decoration: none;
            }
            .support-footer a:hover {
                text-decoration: underline;
            }
            .support-footer-text {
                margin-bottom: 8px;
            }
            .field-wrap {
                position: relative;
                margin-bottom: 14px;
            }
            .field-wrap input {
                margin-bottom: 0;
                padding-right: 48px;
            }
            .eye-btn {
                position: absolute;
                right: 0;
                top: 0;
                height: 100%;
                padding: 0 13px;
                background: none;
                border: none;
                border-left: 1px solid var(--input-border);
                border-radius: 0 10px 10px 0;
                cursor: pointer;
                color: var(--muted);
                font-size: 16px;
                display: flex;
                align-items: center;
                transition: color 0.15s, background 0.15s;
            }
            .eye-btn:hover {
                color: var(--text);
                background: rgba(0,0,0,0.04);
            }
            .mobile-topbar {
                display: none;
            }
            @media (max-width: 900px) {
                .layout {
                    display: block;
                }
                .sidebar {
                    display: none;
                    position: fixed;
                    z-index: 500;
                    width: 280px;
                    top: 0;
                    left: 0;
                    height: 100vh;
                    box-shadow: 4px 0 30px rgba(0,0,0,0.4);
                }
                .sidebar.sidebar-open {
                    display: flex;
                }
                .sidebar-overlay {
                    display: none;
                    position: fixed;
                    inset: 0;
                    background: rgba(0,0,0,0.5);
                    z-index: 499;
                }
                .sidebar-overlay.open {
                    display: block;
                }
                .mobile-topbar {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    background: var(--card-bg);
                    border-bottom: 1px solid var(--border);
                    padding: 0 16px;
                    height: 56px;
                    position: sticky;
                    top: 0;
                    z-index: 100;
                }
                .hamburger-btn {
                    background: none;
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    padding: 8px 12px;
                    cursor: pointer;
                    color: var(--text);
                    font-size: 18px;
                    line-height: 1;
                    transition: background 0.15s;
                }
                .hamburger-btn:hover {
                    background: var(--border);
                }
                .mobile-topbar-title {
                    font-size: 15px;
                    font-weight: 700;
                    color: var(--text);
                }
                .grid-2, .grid-3 {
                    grid-template-columns: 1fr;
                }
                .main {
                    padding: 20px;
                    min-height: auto;
                }
                .perm-item {
                    align-items: flex-start;
                }
                .perm-check {
                    padding-top: 2px;
                }
            }
            @media (min-width: 901px) {
                .hamburger-btn { display: none; }
                .sidebar-overlay { display: none !important; }
            }
        </style>
        <script>
            (function() {
                var saved = localStorage.getItem('deskview-theme') || 'light';
                document.documentElement.setAttribute('data-theme', saved);
            })();
        </script>
    </head>
    <body>
        <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>
        <div class="layout">
            ${renderSidebar(req)}
            <main class="main">
                <div class="mobile-topbar">
                    <button class="hamburger-btn" onclick="openSidebar()">&#9776;</button>
                    <span class="mobile-topbar-title">DeskView Admin</span>
                    <button class="hamburger-btn" onclick="toggleTheme()" style="font-size:14px;">&#9790;</button>
                </div>
                <div class="page-content">
                    ${content}
                </div>
                ${renderSupportFooter()}
            </main>
        </div>
        <script>
            function toggleTheme() {
                var current = document.documentElement.getAttribute('data-theme');
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                localStorage.setItem('deskview-theme', next);
            }
            function toggleVis(id) {
                var inp = document.getElementById(id);
                if (!inp) return;
                inp.type = inp.type === 'password' ? 'text' : 'password';
                var btn = document.querySelector('[data-eye="' + id + '"]');
                if (btn) btn.textContent = inp.type === 'password' ? '\uD83D\uDC41' : '\uD83D\uDE48';
            }
            function openSidebar() {
                document.querySelector('.sidebar').classList.add('sidebar-open');
                document.getElementById('sidebarOverlay').classList.add('open');
            }
            function closeSidebar() {
                document.querySelector('.sidebar').classList.remove('sidebar-open');
                document.getElementById('sidebarOverlay').classList.remove('open');
            }
            function permToggleGroup(header) {
                var list = header.nextElementSibling;
                var isOpen = header.classList.toggle('open');
                list.style.display = isOpen ? 'flex' : 'none';
            }
            function permToggleAll(btn) {
                var isAll = btn.getAttribute('data-all') === '1';
                var newState = !isAll;
                document.querySelectorAll('input[name="permissions"]').forEach(function(cb) {
                    cb.checked = newState;
                });
                btn.setAttribute('data-all', newState ? '1' : '');
                btn.innerHTML = newState ? '&#10007; Alle abwählen' : '&#10003; Alle Berechtigungen';
                document.querySelectorAll('.perm-group-all-btn').forEach(function(b) {
                    b.setAttribute('data-all', newState ? '1' : '');
                    b.textContent = newState ? 'Alle abwählen' : 'Alle wählen';
                });
            }
            function permToggleGroupAll(btn) {
                var gi = btn.getAttribute('data-group');
                var isAll = btn.getAttribute('data-all') === '1';
                var newState = !isAll;
                document.querySelectorAll('input[name="permissions"][data-group="' + gi + '"]').forEach(function(cb) {
                    cb.checked = newState;
                });
                btn.setAttribute('data-all', newState ? '1' : '');
                btn.textContent = newState ? 'Alle abwählen' : 'Alle wählen';
                permSyncGlobalBtn();
            }
            function permSyncGroupBtn(gi) {
                var boxes = document.querySelectorAll('input[name="permissions"][data-group="' + gi + '"]');
                var allChecked = Array.from(boxes).every(function(cb) { return cb.checked; });
                var btn = document.querySelector('.perm-group-all-btn[data-group="' + gi + '"]');
                if (btn) {
                    btn.setAttribute('data-all', allChecked ? '1' : '');
                    btn.textContent = allChecked ? 'Alle abwählen' : 'Alle wählen';
                }
                permSyncGlobalBtn();
            }
            function permSyncGlobalBtn() {
                var allBoxes = document.querySelectorAll('input[name="permissions"]');
                var allChecked = Array.from(allBoxes).every(function(cb) { return cb.checked; });
                var btn = document.getElementById('permAllBtn');
                if (btn) {
                    btn.setAttribute('data-all', allChecked ? '1' : '');
                    btn.innerHTML = allChecked ? '&#10007; Alle abwählen' : '&#10003; Alle Berechtigungen';
                }
            }

            function trmnlModeChange(roomId) {
                var sel = document.getElementById('trmnlMode_' + roomId);
                if (!sel) return;
                var mode = sel.value;
                var pollingEl = document.getElementById('trmnl_polling_' + roomId);
                var webhookEl = document.getElementById('trmnl_webhook_' + roomId);
                if (pollingEl) pollingEl.style.display = mode === 'polling' ? 'block' : 'none';
                if (webhookEl) webhookEl.style.display = mode === 'webhook' ? 'block' : 'none';
            }

            async function saveSleepSchedule(roomId) {
                var resultEl = document.getElementById('trmnlTestResult_' + roomId);
                var form = document.getElementById('trmnlSleepForm_' + roomId);
                resultEl.style.display = 'block';
                resultEl.textContent = 'Speichere Sleep Schedule...';
                try {
                    var fd = new FormData(form);
                    var r = await fetch('/admin/save-sleep-schedule', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams(fd).toString()
                    });
                    var text = await r.text();
                    var data;
                    try { data = JSON.parse(text); } catch(e) { data = text; }
                    resultEl.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
                } catch(e) {
                    resultEl.textContent = 'Fehler: ' + e.message;
                }
            }

            async function testTrmnlPush(roomId) {
                var resultEl = document.getElementById('trmnlTestResult_' + roomId);
                var form = document.getElementById('trmnlTestForm_' + roomId);
                resultEl.style.display = 'block';
                resultEl.textContent = 'Teste Push...';
                try {
                    var fd = new FormData(form);
                    var r = await fetch('/admin/test-trmnl-push', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams(fd).toString()
                    });
                    var text = await r.text();
                    var data;
                    try { data = JSON.parse(text); } catch(e) { data = text; }
                    resultEl.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
                } catch(e) {
                    resultEl.textContent = 'Fehler: ' + e.message;
                }
            }
        </script>
    </body>
    </html>
    `;
}

function renderRoomApiJson(room) {
    const result = {
        abteilung: room.abteilung,
        roomnumber: room.roomnumber,
        seats: room.seats.map(s => ({ name: s.name, title: s.title }))
    };
    // Legacy-Felder für ältere Clients
    room.seats.forEach((seat, i) => {
        result[`name${i + 1}`] = seat.name;
        result[`title${i + 1}`] = seat.title;
    });
    return result;
}

/*
==================================================
TRMNL PUSH
==================================================
*/
async function pushToTrmnl(room) {
    const mode = room.trmnlMode || 'none';
    if (mode === 'none') return;

    const payload = renderRoomApiJson(room);

    if (mode === 'webhook') {
        // Webhook URL (Daten direkt pushen)
        if (room.trmnlWebhookUrl) {
            try {
                await fetch(room.trmnlWebhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ merge_variables: payload })
                });
            } catch (err) {
                console.error(`TRMNL Webhook Push Fehler (${room.id}):`, err.message);
            }
        }

    }
    // mode === 'polling': TRMNL holt Daten selbst, kein Push nötig
}

async function fetchMicrosoftUser(accessToken) {
    const response = await fetch(
        'https://graph.microsoft.com/v1.0/me?$select=displayName,givenName,surname,jobTitle,mail,userPrincipalName',
        {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        }
    );

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Microsoft Graph Fehler: ${response.status} ${text}`);
    }

    return response.json();
}

/*
==================================================
MSAL – Microsoft Auth (ersetzt passport-azure-ad)
==================================================
*/
let msalClient = null;

function buildMsalClient() {
    if (!hasMicrosoftConfig()) {
        return null;
    }

    return new ConfidentialClientApplication({
        auth: {
            clientId: microsoftConfig.clientID,
            authority: `https://login.microsoftonline.com/${microsoftConfig.tenantID}`,
            clientSecret: microsoftConfig.clientSecret
        }
    });
}

function refreshMsalClient() {
    msalClient = buildMsalClient();
}

/*
==================================================
SESSION
==================================================
*/
ensureSingleMasterAdmin();
const bootstrapSessionSecret = generateStrongSecret();

function buildSessionMiddleware() {
    return session({
        secret: String(appConfig.sessionSecret || '').trim() || bootstrapSessionSecret,
        resave: false,
        saveUninitialized: true,
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.HTTPS_ENABLED === 'true'
        }
    });
}

let sessionMiddleware = buildSessionMiddleware();
app.use((req, res, next) => sessionMiddleware(req, res, next));

/*
==================================================
SETUP ERZWINGEN
==================================================
*/
app.use((req, res, next) => {
    if (!isSetupRequired()) {
        return next();
    }

    const allowedPaths = [
        '/admin/setup',
        '/favicon.ico'
    ];

    const staticAllowed =
        req.path === '/logo.png' ||
        req.path.startsWith('/public/');

    if (allowedPaths.includes(req.path) || staticAllowed) {
        return next();
    }

    return res.redirect('/admin/setup');
});

/*
==================================================
STARTSEITE
==================================================
*/
app.get('/', (req, res) => {
    const logoExists = fs.existsSync(LOGO_FILE);
    const roomList = Object.values(rooms);

    const roomCards = roomList.map(room => {
        const seatLinks = room.seats.map((seat, i) => {
            const num = i + 1;
            const occupied = seat.name && seat.name !== 'Frei';
            return `
                <a href="/${encodeURIComponent(room.id)}/sit/${num}" class="seat-pill ${occupied ? 'seat-pill-occ' : ''}">
                    Platz ${num}${occupied ? ` – ${escapeHtml(seat.name)}` : ' – Frei'}
                </a>
            `;
        }).join('');

        const freeCount = room.seats.filter(s => !s.name || s.name === 'Frei').length;

        return `
            <div class="room-card">
                <div class="room-card-header">
                    <div>
                        <div class="room-card-name">${escapeHtml(room.abteilung)}</div>
                        <div class="room-card-num">Raum ${escapeHtml(room.roomnumber)}</div>
                    </div>
                    <div class="room-card-badge">${freeCount} frei</div>
                </div>
                <div class="room-seats">
                    ${seatLinks}
                </div>
                <a href="/${encodeURIComponent(room.id)}" class="room-card-link">Raum öffnen &#8594;</a>
            </div>
        `;
    }).join('');

    res.send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Komvera DeskView</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                :root {
                    --bg: #f0f4f8;
                    --surface: #ffffff;
                    --text: #1e293b;
                    --muted: #64748b;
                    --border: #e2e8f0;
                    --primary: #2563eb;
                    --primary-hover: #1d4ed8;
                    --accent: #0ea5e9;
                    --card-shadow: 0 4px 24px rgba(0,0,0,0.08);
                    --header-bg: #ffffff;
                    --pill-free: #dcfce7;
                    --pill-free-text: #166534;
                    --pill-occ: #fee2e2;
                    --pill-occ-text: #991b1b;
                    --room-header: #f8fafc;
                }
                [data-theme="dark"] {
                    --bg: #0f172a;
                    --surface: #1e293b;
                    --text: #f1f5f9;
                    --muted: #94a3b8;
                    --border: #334155;
                    --primary: #3b82f6;
                    --primary-hover: #2563eb;
                    --card-shadow: 0 4px 24px rgba(0,0,0,0.4);
                    --header-bg: #1e293b;
                    --pill-free: #14532d;
                    --pill-free-text: #86efac;
                    --pill-occ: #450a0a;
                    --pill-occ-text: #fca5a5;
                    --room-header: #0f172a;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    background: var(--bg);
                    color: var(--text);
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    transition: background 0.2s, color 0.2s;
                }
                header {
                    background: var(--header-bg);
                    border-bottom: 1px solid var(--border);
                    padding: 0 32px;
                    height: 64px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    position: sticky;
                    top: 0;
                    z-index: 100;
                    box-shadow: 0 1px 8px rgba(0,0,0,0.05);
                }
                .header-logo {
                    max-height: 52px;
                    max-width: 220px;
                    width: auto;
                    height: auto;
                    object-fit: contain;
                }
                .header-logo-text {
                    font-size: 20px;
                    font-weight: 700;
                    color: var(--text);
                }
                .header-right {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }
                .btn-theme {
                    background: none;
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    padding: 7px 14px;
                    cursor: pointer;
                    color: var(--muted);
                    font-size: 14px;
                    transition: border-color 0.15s, color 0.15s;
                }
                .btn-theme:hover {
                    border-color: var(--primary);
                    color: var(--primary);
                }
                .btn-admin {
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 8px 18px;
                    font-size: 14px;
                    font-weight: 600;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    transition: background 0.15s;
                }
                .btn-admin:hover {
                    background: var(--primary-hover);
                }
                main {
                    flex: 1;
                    padding: 40px 32px;
                    max-width: 1100px;
                    margin: 0 auto;
                    width: 100%;
                }
                .hero {
                    text-align: center;
                    margin-bottom: 48px;
                }
                .hero h1 {
                    font-size: 32px;
                    font-weight: 800;
                    color: var(--text);
                    margin-bottom: 8px;
                }
                .hero p {
                    font-size: 16px;
                    color: var(--muted);
                }
                .rooms-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
                    gap: 24px;
                }
                .room-card {
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: 16px;
                    overflow: hidden;
                    box-shadow: var(--card-shadow);
                    color: var(--text);
                    display: flex;
                    flex-direction: column;
                    transition: transform 0.15s, box-shadow 0.15s;
                }
                .room-card:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 12px 32px rgba(0,0,0,0.12);
                }
                .room-card-link {
                    display: block;
                    padding: 12px 20px;
                    text-align: center;
                    font-size: 14px;
                    font-weight: 600;
                    color: var(--primary);
                    text-decoration: none;
                    border-top: 1px solid var(--border);
                    transition: background 0.15s;
                }
                .room-card-link:hover {
                    background: var(--room-header);
                }
                .room-card-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    padding: 20px 20px 16px 20px;
                    background: var(--room-header);
                    border-bottom: 1px solid var(--border);
                }
                .room-card-name {
                    font-size: 18px;
                    font-weight: 700;
                    color: var(--text);
                }
                .room-card-num {
                    font-size: 13px;
                    color: var(--muted);
                    margin-top: 3px;
                }
                .room-card-badge {
                    background: var(--pill-free);
                    color: var(--pill-free-text);
                    font-size: 12px;
                    font-weight: 700;
                    padding: 4px 10px;
                    border-radius: 999px;
                    white-space: nowrap;
                }
                .room-seats {
                    padding: 16px 20px;
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                }
                .seat-pill {
                    display: block;
                    padding: 10px 14px;
                    border-radius: 10px;
                    font-size: 14px;
                    font-weight: 500;
                    text-decoration: none;
                    background: var(--pill-free);
                    color: var(--pill-free-text);
                    border: 1px solid transparent;
                    transition: opacity 0.15s, transform 0.1s;
                }
                .seat-pill:hover {
                    opacity: 0.85;
                    transform: translateX(3px);
                }
                .seat-pill.seat-pill-occ {
                    background: var(--pill-occ);
                    color: var(--pill-occ-text);
                }
                .empty-state {
                    text-align: center;
                    padding: 60px 20px;
                    color: var(--muted);
                }
                .empty-state p {
                    font-size: 16px;
                    margin-bottom: 16px;
                }
                footer {
                    text-align: center;
                    padding: 24px;
                    font-size: 13px;
                    color: var(--muted);
                    border-top: 1px solid var(--border);
                }
                footer a {
                    color: var(--primary);
                    text-decoration: none;
                }
                footer a:hover {
                    text-decoration: underline;
                }
                @media (max-width: 600px) {
                    header { padding: 0 16px; }
                    main { padding: 24px 16px; }
                    .hero h1 { font-size: 24px; }
                    .rooms-grid { grid-template-columns: 1fr; }
                }
            </style>
            <script>
                (function() {
                    var saved = localStorage.getItem('deskview-theme') || 'light';
                    document.documentElement.setAttribute('data-theme', saved);
                })();
            </script>
        </head>
        <body>
            <header>
                <div>
                    ${logoExists
                        ? `<img src="/logo.png" alt="Komvera DeskView" class="header-logo">`
                        : `<span class="header-logo-text">Komvera DeskView</span>`
                    }
                </div>
                <div class="header-right">
                    <button class="btn-theme" onclick="toggleTheme()">&#9790; Modus</button>
                    <a href="/admin" class="btn-admin">&#9632; Admin</a>
                </div>
            </header>

            <main>
                <div class="hero">
                    <h1>Sitzplatzverwaltung</h1>
                    <p>Wähle einen Raum, um einen Sitzplatz einzuchecken.</p>
                </div>

                ${roomList.length > 0
                    ? `<div class="rooms-grid">${roomCards}</div>`
                    : `<div class="empty-state"><p>Noch keine Räume vorhanden.</p><a href="/admin" class="btn-admin" style="display:inline-flex;">Admin-Bereich öffnen</a></div>`
                }
            </main>

            <footer>
                &copy; ${new Date().getFullYear()} Komvera IT GmbH &middot;
                <a href="https://www.komvera.de" target="_blank" rel="noopener noreferrer">www.komvera.de</a> &middot;
                <a href="mailto:info@komvera.de">info@komvera.de</a>
            </footer>

            <script>
                function toggleTheme() {
                    var current = document.documentElement.getAttribute('data-theme');
                    var next = current === 'dark' ? 'light' : 'dark';
                    document.documentElement.setAttribute('data-theme', next);
                    localStorage.setItem('deskview-theme', next);
                }
            </script>
        </body>
        </html>
    `);
});

/*
==================================================
ERSTEINRICHTUNG
==================================================
*/
app.get('/admin/setup', (req, res) => {
    if (!isSetupRequired()) {
        return res.redirect('/admin/login');
    }

    getCsrfToken(req);
    req.session.save(() => {
    const generatedSecret = generateStrongSecret();

    const logoExists = fs.existsSync(LOGO_FILE);
    res.send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Ersteinrichtung – DeskView</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                :root {
                    --bg: #f0f4f8;
                    --surface: #ffffff;
                    --text: #1e293b;
                    --muted: #64748b;
                    --border: #e2e8f0;
                    --primary: #2563eb;
                    --primary-hover: #1d4ed8;
                    --input-bg: #ffffff;
                    --card-bg: #f8fafc;
                    --notice-bg: #eff6ff;
                    --notice-text: #1d4ed8;
                    --notice-border: #bfdbfe;
                }
                [data-theme="dark"] {
                    --bg: #0f172a;
                    --surface: #1e293b;
                    --text: #f1f5f9;
                    --muted: #94a3b8;
                    --border: #334155;
                    --primary: #3b82f6;
                    --primary-hover: #2563eb;
                    --input-bg: #0f172a;
                    --card-bg: #0f172a;
                    --notice-bg: #1e3a5f;
                    --notice-text: #93c5fd;
                    --notice-border: #1e40af;
                }
                body {
                    min-height: 100vh;
                    background: var(--bg);
                    color: var(--text);
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    padding: 32px 20px;
                    transition: background 0.2s, color 0.2s;
                }
                .page-wrap {
                    max-width: 860px;
                    margin: 0 auto;
                }
                .setup-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 32px;
                }
                .setup-logo img {
                    max-height: 52px;
                    max-width: 180px;
                    width: auto;
                    height: auto;
                    object-fit: contain;
                }
                .setup-logo-text {
                    font-size: 20px;
                    font-weight: 800;
                    color: var(--text);
                }
                .theme-btn {
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    padding: 8px 14px;
                    cursor: pointer;
                    color: var(--muted);
                    font-size: 13px;
                    transition: border-color 0.15s;
                }
                .theme-btn:hover { border-color: var(--primary); color: var(--primary); }
                h1 {
                    font-size: 28px;
                    font-weight: 800;
                    margin-bottom: 8px;
                }
                .subtitle {
                    font-size: 15px;
                    color: var(--muted);
                    margin-bottom: 28px;
                    line-height: 1.6;
                }
                .notice {
                    background: var(--notice-bg);
                    border: 1px solid var(--notice-border);
                    color: var(--notice-text);
                    padding: 14px 16px;
                    border-radius: 12px;
                    margin-bottom: 28px;
                    font-size: 14px;
                    line-height: 1.5;
                }
                .grid-2 {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                    margin-bottom: 20px;
                }
                .card {
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: 16px;
                    padding: 22px;
                    box-shadow: 0 4px 16px rgba(0,0,0,0.06);
                }
                .card h2 {
                    font-size: 16px;
                    font-weight: 700;
                    margin-bottom: 16px;
                    color: var(--text);
                }
                .card-hint {
                    background: var(--card-bg);
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    padding: 12px;
                    margin-bottom: 12px;
                }
                label {
                    display: block;
                    font-size: 13px;
                    font-weight: 600;
                    margin-bottom: 5px;
                    color: var(--muted);
                }
                input {
                    width: 100%;
                    padding: 11px 13px;
                    margin-bottom: 12px;
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    font-size: 14px;
                    background: var(--input-bg);
                    color: var(--text);
                    transition: border-color 0.15s;
                }
                input:focus {
                    outline: none;
                    border-color: var(--primary);
                }
                .optional-tag {
                    font-size: 11px;
                    font-weight: 600;
                    color: var(--muted);
                    background: var(--card-bg);
                    border: 1px solid var(--border);
                    padding: 2px 7px;
                    border-radius: 4px;
                    margin-left: 6px;
                    text-transform: uppercase;
                    vertical-align: middle;
                }
                .submit-btn {
                    width: 100%;
                    padding: 14px;
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 12px;
                    font-weight: 700;
                    font-size: 16px;
                    cursor: pointer;
                    margin-top: 12px;
                    transition: background 0.15s;
                }
                .submit-btn:hover { background: var(--primary-hover); }
                .support-footer {
                    margin-top: 32px;
                    padding-top: 20px;
                    border-top: 1px solid var(--border);
                    text-align: center;
                    font-size: 13px;
                    color: var(--muted);
                }
                .support-footer a { color: var(--primary); text-decoration: none; }
                .support-footer a:hover { text-decoration: underline; }
                .toggle-switch { position:relative; display:inline-block; width:44px; height:24px; flex-shrink:0; }
                .toggle-switch input { opacity:0; width:0; height:0; }
                .toggle-slider { position:absolute; cursor:pointer; inset:0; background:var(--border); border-radius:24px; transition:.2s; }
                .toggle-slider:before { content:''; position:absolute; width:18px; height:18px; left:3px; bottom:3px; background:#fff; border-radius:50%; transition:.2s; }
                .toggle-switch input:checked + .toggle-slider { background:var(--primary); }
                .toggle-switch input:checked + .toggle-slider:before { transform:translateX(20px); }
                @media (max-width: 700px) {
                    .grid-2 { grid-template-columns: 1fr; }
                }
            </style>
            <script>
                (function() {
                    var saved = localStorage.getItem('deskview-theme') || 'light';
                    document.documentElement.setAttribute('data-theme', saved);
                })();
            </script>
        </head>
        <body>
            <div class="page-wrap">
                <div class="setup-header">
                    <div class="setup-logo">
                        ${logoExists
                            ? `<img src="/logo.png" alt="Logo">`
                            : `<span class="setup-logo-text">Komvera DeskView</span>`
                        }
                    </div>
                    <button class="theme-btn" onclick="toggleTheme()">&#9790; Modus</button>
                </div>

                <h1>Ersteinrichtung</h1>
                <p class="subtitle">
                    Richte einmalig den Master-Admin und das Session Secret ein.<br>
                    <strong>rooms.json</strong>, <strong>admins.json</strong> und <strong>config.json</strong> wurden bereits erstellt.
                </p>

                <div class="notice">
                    <strong>Session Secret:</strong> Schützt deine Login-Sessions durch Signierung der Session-Cookies.
                    Der vorgeschlagene Wert ist sicher – du kannst ihn einfach übernehmen.
                </div>

                <form method="POST" action="/admin/setup">
                    ${csrfField(req)}
                    <div class="grid-2">
                        <div class="card">
                            <h2>Master-Admin</h2>
                            <label>Benutzername</label>
                            <input type="text" name="username" placeholder="z. B. admin" required autofocus>
                            <label>Anzeigename <span class="optional-tag">optional</span></label>
                            <input type="text" name="displayName" placeholder="z. B. Max Mustermann">
                            <label>Passwort</label>
                            <input type="password" name="password" placeholder="Mindestens 8 Zeichen" required>
                            <label>Passwort wiederholen</label>
                            <input type="password" name="confirmPassword" placeholder="Passwort bestätigen" required>
                        </div>

                        <div class="card">
                            <h2>Session Secret</h2>
                            <label>Session Secret</label>
                            <input type="text" name="sessionSecret" value="${escapeHtml(generatedSecret)}" required>
                            <div class="card-hint" style="font-size:13px; color:var(--muted); line-height:1.5;">
                                Der vorgeschlagene Wert ist bereits kryptographisch stark.
                                Du kannst ihn übernehmen oder durch einen eigenen ersetzen.
                            </div>

                            <h2 style="margin-top:16px;">Microsoft / Entra <span class="optional-tag">optional</span></h2>

                            <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">
                                <label class="toggle-switch">
                                    <input type="checkbox" name="microsoftLoginEnabled" id="ms_toggle_setup" value="1" onchange="document.getElementById('ms_fields_setup').style.display=this.checked?'block':'none'">
                                    <span class="toggle-slider"></span>
                                </label>
                                <span style="font-size:14px;font-weight:600;color:var(--text);">Microsoft Login aktivieren</span>
                            </div>
                            <div id="ms_fields_setup" style="display:none;">
                                <label>Client ID</label>
                                <input type="text" name="clientID" value="${escapeHtml(microsoftConfig.clientID || '')}" placeholder="Leer lassen falls nicht benötigt">
                                <label>Tenant ID</label>
                                <input type="text" name="tenantID" value="${escapeHtml(microsoftConfig.tenantID || '')}">
                                <label>Client Secret</label>
                                <input type="text" name="clientSecret" value="${escapeHtml(microsoftConfig.clientSecret || '')}">
                                <label>Callback URL</label>
                                <input type="text" name="callbackURL" value="${escapeHtml(microsoftConfig.callbackURL || '')}">
                            </div>
                        </div>
                    </div>

                    <button type="submit" class="submit-btn">Ersteinrichtung abschließen &#8594;</button>
                </form>

                <div class="support-footer">
                    &copy; ${new Date().getFullYear()} Komvera IT GmbH &middot;
                    <a href="https://www.komvera.de" target="_blank" rel="noopener noreferrer">www.komvera.de</a> &middot;
                    <a href="mailto:info@komvera.de">info@komvera.de</a>
                </div>
            </div>

            <script>
                function toggleTheme() {
                    var current = document.documentElement.getAttribute('data-theme');
                    var next = current === 'dark' ? 'light' : 'dark';
                    document.documentElement.setAttribute('data-theme', next);
                    localStorage.setItem('deskview-theme', next);
                }
            </script>
        </body>
        </html>
    `);
    }); // session.save
});

app.post('/admin/setup', setupLimiter, requireCsrf, async (req, res) => {
    try {
        if (!isSetupRequired()) {
            return res.redirect('/admin/login');
        }

        const username = String(req.body.username || '').trim();
        const displayName = String(req.body.displayName || '').trim();
        const password = String(req.body.password || '');
        const confirmPassword = String(req.body.confirmPassword || '');
        const sessionSecret = String(req.body.sessionSecret || '').trim();

        const clientID = String(req.body.clientID || '').trim();
        const tenantID = String(req.body.tenantID || '').trim();
        const clientSecret = String(req.body.clientSecret || '').trim();
        const callbackURL = String(req.body.callbackURL || '').trim();

        if (!username || !password || !confirmPassword || !sessionSecret) {
            return res.status(400).send('Bitte alle Pflichtfelder ausfüllen');
        }

        if (password !== confirmPassword) {
            return res.status(400).send('Die Passwörter stimmen nicht überein');
        }

        if (password.length < 8) {
            return res.status(400).send('Das Passwort muss mindestens 8 Zeichen lang sein');
        }

        if (sessionSecret.length < 32) {
            return res.status(400).send('Das Session Secret sollte mindestens 32 Zeichen lang sein');
        }

        if (hasAnyAdmins()) {
            return res.status(400).send('Es existiert bereits ein Admin');
        }

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        admins = [
            normalizeAdmin({
                username,
                displayName,
                passwordHash,
                master: true,
                permissions: []
            })
        ];
        saveAdmins();

        appConfig.sessionSecret = sessionSecret;
        appConfig.microsoftLoginEnabled = req.body.microsoftLoginEnabled === '1';
        microsoftConfig = {
            clientID,
            tenantID,
            clientSecret,
            callbackURL
        };
        saveAppConfig();
        refreshMsalClient();
        sessionMiddleware = buildSessionMiddleware();

        return res.send(`
            <!DOCTYPE html>
            <html lang="de">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Setup abgeschlossen – DeskView</title>
                <style>
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    :root {
                        --bg: #f0f4f8;
                        --surface: #ffffff;
                        --text: #1e293b;
                        --muted: #64748b;
                        --border: #e2e8f0;
                        --primary: #2563eb;
                        --primary-hover: #1d4ed8;
                        --success-bg: #f0fdf4;
                        --success-border: #bbf7d0;
                        --success-text: #166534;
                        --warn-bg: #fffbeb;
                        --warn-border: #fde68a;
                        --warn-text: #92400e;
                    }
                    [data-theme="dark"] {
                        --bg: #0f172a;
                        --surface: #1e293b;
                        --text: #f1f5f9;
                        --muted: #94a3b8;
                        --border: #334155;
                        --primary: #3b82f6;
                        --primary-hover: #2563eb;
                        --success-bg: #052e16;
                        --success-border: #166534;
                        --success-text: #86efac;
                        --warn-bg: #1c1700;
                        --warn-border: #78350f;
                        --warn-text: #fcd34d;
                    }
                    body {
                        min-height: 100vh;
                        background: var(--bg);
                        color: var(--text);
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        padding: 32px 20px;
                        transition: background 0.2s, color 0.2s;
                    }
                    .card {
                        background: var(--surface);
                        border: 1px solid var(--border);
                        border-radius: 20px;
                        padding: 40px 48px;
                        max-width: 520px;
                        width: 100%;
                        text-align: center;
                        box-shadow: 0 8px 32px rgba(0,0,0,0.10);
                    }
                    .icon {
                        font-size: 52px;
                        margin-bottom: 20px;
                        line-height: 1;
                    }
                    h2 {
                        font-size: 24px;
                        font-weight: 800;
                        margin-bottom: 12px;
                        color: var(--text);
                    }
                    .success-box {
                        background: var(--success-bg);
                        border: 1px solid var(--success-border);
                        color: var(--success-text);
                        border-radius: 12px;
                        padding: 12px 16px;
                        font-size: 14px;
                        margin-bottom: 16px;
                        text-align: left;
                        line-height: 1.5;
                    }
                    .warn-box {
                        background: var(--warn-bg);
                        border: 1px solid var(--warn-border);
                        color: var(--warn-text);
                        border-radius: 12px;
                        padding: 12px 16px;
                        font-size: 14px;
                        margin-bottom: 24px;
                        text-align: left;
                        line-height: 1.5;
                    }
                    .warn-box strong { display: block; margin-bottom: 4px; }
                    .login-btn {
                        display: inline-block;
                        background: var(--primary);
                        color: #fff;
                        text-decoration: none;
                        padding: 13px 32px;
                        border-radius: 12px;
                        font-weight: 700;
                        font-size: 15px;
                        transition: background 0.15s;
                        width: 100%;
                    }
                    .login-btn:hover { background: var(--primary-hover); }
                    .support-footer {
                        margin-top: 28px;
                        padding-top: 20px;
                        border-top: 1px solid var(--border);
                        font-size: 13px;
                        color: var(--muted);
                    }
                    .support-footer a { color: var(--primary); text-decoration: none; }
                    .support-footer a:hover { text-decoration: underline; }
                    .theme-btn {
                        position: fixed;
                        top: 16px;
                        right: 16px;
                        background: var(--surface);
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        padding: 7px 13px;
                        cursor: pointer;
                        color: var(--muted);
                        font-size: 13px;
                        transition: border-color 0.15s;
                    }
                    .theme-btn:hover { border-color: var(--primary); color: var(--primary); }
                </style>
                <script>
                    (function() {
                        var saved = localStorage.getItem('deskview-theme') || 'light';
                        document.documentElement.setAttribute('data-theme', saved);
                    })();
                </script>
            </head>
            <body>
                <button class="theme-btn" onclick="(function(){var c=document.documentElement.getAttribute('data-theme');var n=c==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',n);localStorage.setItem('deskview-theme',n);})()">&#9790; Modus</button>
                <div class="card">
                    <div class="icon">&#10003;</div>
                    <h2>Ersteinrichtung abgeschlossen</h2>
                    <div class="success-box">
                        Master-Admin und Konfiguration wurden erfolgreich gespeichert.
                    </div>
                    <a href="/admin/login" class="login-btn">Zum Login &rarr;</a>
                    ${renderSupportFooter()}
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        console.error(err);
        return res.status(500).send('Ersteinrichtung fehlgeschlagen');
    }
});

/*
==================================================
ADMIN LOGIN
==================================================
*/
app.get('/admin/login', (req, res) => {
    if (isSetupRequired()) {
        return res.redirect('/admin/setup');
    }

    getCsrfToken(req);
    req.session.save(() => {
    const logoExists = fs.existsSync(LOGO_FILE);
    const loginError = String(req.query.error || '');
    const loginErrorField = String(req.query.field || '');
    res.send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Admin Login – DeskView</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                :root {
                    --bg: #f0f4f8;
                    --surface: #ffffff;
                    --text: #1e293b;
                    --muted: #64748b;
                    --border: #e2e8f0;
                    --primary: #2563eb;
                    --primary-hover: #1d4ed8;
                    --input-bg: #ffffff;
                }
                [data-theme="dark"] {
                    --bg: #0f172a;
                    --surface: #1e293b;
                    --text: #f1f5f9;
                    --muted: #94a3b8;
                    --border: #334155;
                    --primary: #3b82f6;
                    --primary-hover: #2563eb;
                    --input-bg: #0f172a;
                }
                body {
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: var(--bg);
                    color: var(--text);
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    padding: 24px;
                    transition: background 0.2s, color 0.2s;
                }
                .box {
                    width: 100%;
                    max-width: 420px;
                    background: var(--surface);
                    border-radius: 20px;
                    padding: 36px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.12);
                    border: 1px solid var(--border);
                }
                .login-logo {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    margin-bottom: 28px;
                    gap: 12px;
                }
                .login-logo img {
                    max-height: 90px;
                    max-width: 300px;
                    width: auto;
                    height: auto;
                    object-fit: contain;
                }
                .login-logo-text {
                    font-size: 20px;
                    font-weight: 700;
                    color: var(--text);
                }
                h2 {
                    font-size: 22px;
                    font-weight: 700;
                    margin-bottom: 24px;
                    text-align: center;
                    color: var(--text);
                }
                label {
                    display: block;
                    font-size: 13px;
                    font-weight: 600;
                    margin-bottom: 5px;
                    color: var(--muted);
                }
                input {
                    width: 100%;
                    padding: 12px 14px;
                    margin-bottom: 14px;
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    font-size: 15px;
                    background: var(--input-bg);
                    color: var(--text);
                    transition: border-color 0.15s;
                }
                input:focus {
                    outline: none;
                    border-color: var(--primary);
                }
                button {
                    width: 100%;
                    padding: 13px;
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 10px;
                    font-weight: 700;
                    font-size: 15px;
                    cursor: pointer;
                    transition: background 0.15s;
                    margin-top: 4px;
                }
                button:hover {
                    background: var(--primary-hover);
                }
                .home-link {
                    text-align: center;
                    margin-top: 16px;
                    font-size: 13px;
                    color: var(--muted);
                }
                .home-link a {
                    color: var(--primary);
                    text-decoration: none;
                }
                .home-link a:hover {
                    text-decoration: underline;
                }
                .theme-btn {
                    position: fixed;
                    top: 16px;
                    right: 16px;
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    padding: 8px 14px;
                    cursor: pointer;
                    color: var(--muted);
                    font-size: 13px;
                    transition: border-color 0.15s;
                }
                .theme-btn:hover {
                    border-color: var(--primary);
                    color: var(--primary);
                }
                .support-footer {
                    margin-top: 24px;
                    padding-top: 16px;
                    border-top: 1px solid var(--border);
                    text-align: center;
                    font-size: 13px;
                    color: var(--muted);
                }
                .support-footer a {
                    color: var(--primary);
                    text-decoration: none;
                }
                .support-footer a:hover {
                    text-decoration: underline;
                }
                .field-wrap {
                    position: relative;
                    margin-bottom: 14px;
                }
                .field-wrap input {
                    margin-bottom: 0;
                    padding-right: 48px;
                }
                .eye-btn {
                    position: absolute;
                    right: 0;
                    top: 0;
                    width: auto;
                    height: 100%;
                    margin: 0;
                    padding: 0 13px;
                    background: none;
                    color: var(--muted);
                    border: none;
                    border-left: 1px solid var(--border);
                    border-radius: 0 10px 10px 0;
                    cursor: pointer;
                    font-size: 16px;
                    display: flex;
                    align-items: center;
                    transition: color 0.15s;
                }
                .eye-btn:hover {
                    color: var(--primary);
                    background: rgba(0,0,0,0.04);
                }
                .field-error {
                    color: #dc2626;
                    font-size: 13px;
                    margin-top: 4px;
                    display: block;
                }
                .input-error {
                    border-color: #dc2626 !important;
                }
            </style>
            <script>
                (function() {
                    var saved = localStorage.getItem('deskview-theme') || 'light';
                    document.documentElement.setAttribute('data-theme', saved);
                })();
            </script>
        </head>
        <body>
            <button class="theme-btn" onclick="toggleTheme()">&#9790; Modus</button>
            <div class="box">
                <div class="login-logo">
                    ${logoExists
                        ? `<img src="/logo.png" alt="Komvera DeskView">`
                        : `<span class="login-logo-text">Komvera DeskView</span>`
                    }
                </div>
                <h2>Admin Login</h2>
                <form method="POST" action="/admin/login">
                    ${csrfField(req)}
                    <label for="username">Benutzername</label>
                    <input type="text" id="username" name="username" placeholder="Benutzername" required autofocus class="${loginErrorField === 'username' ? 'input-error' : ''}">
                    ${loginErrorField === 'username' ? `<span class="field-error">${escapeHtml(loginError)}</span>` : ''}
                    <label for="password">Passwort</label>
                    <div class="field-wrap">
                        <input type="password" id="password" name="password" placeholder="Passwort" required class="${loginErrorField === 'password' ? 'input-error' : ''}">
                        <button type="button" class="eye-btn" data-eye="password" onclick="toggleVis('password')">&#128065;</button>
                    </div>
                    ${loginErrorField === 'password' ? `<span class="field-error">${escapeHtml(loginError)}</span>` : ''}
                    <button type="submit">Anmelden</button>
                </form>
                <div class="home-link">
                    <a href="/">&#8592; Zur Startseite</a>
                </div>
                ${renderSupportFooter()}
            </div>
            <script>
                function toggleTheme() {
                    var current = document.documentElement.getAttribute('data-theme');
                    var next = current === 'dark' ? 'light' : 'dark';
                    document.documentElement.setAttribute('data-theme', next);
                    localStorage.setItem('deskview-theme', next);
                }
                function toggleVis(id) {
                    var inp = document.getElementById(id);
                    if (!inp) return;
                    inp.type = inp.type === 'password' ? 'text' : 'password';
                    var btn = document.querySelector('[data-eye="' + id + '"]');
                    if (btn) btn.textContent = inp.type === 'password' ? '\uD83D\uDC41' : '\uD83D\uDE48';
                }
            </script>
        </body>
        </html>
    `);
    }); // session.save
});

app.post('/admin/login', loginLimiter, requireCsrf, async (req, res) => {
    try {
        if (isSetupRequired()) {
            return res.redirect('/admin/setup');
        }

        const username = String(req.body.username || '').trim();
        const password = String(req.body.password || '');

        const admin = getAdminUser(username);

        if (!admin || !admin.passwordHash) {
            return res.redirect('/admin/login?error=Falsche+Zugangsdaten&field=username');
        }

        const valid = await bcrypt.compare(password, admin.passwordHash);

        if (!valid) {
            return res.redirect('/admin/login?error=Falsches+Passwort&field=password');
        }

        req.session.regenerate((err) => {
            if (err) return res.status(500).send('Login fehlgeschlagen');
            req.session.adminAuthenticated = true;
            req.session.adminUsername = admin.username;
            return res.redirect('/admin');
        });
    } catch (err) {
        console.error(err);
        return res.status(500).send('Login fehlgeschlagen');
    }
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/admin/login');
    });
});

/*
==================================================
ADMIN DASHBOARD
==================================================
*/
app.get('/admin', requireAdmin, requirePermission('dashboard.view'), (req, res) => {
    const occupiedSeats = Object.values(rooms).reduce((sum, room) => {
        return sum + room.seats.filter(s => s.name && s.name !== 'Frei').length;
    }, 0);

    const currentAdmin = getCurrentAdmin(req);

    const content = `
        <div class="topbar">
            <div>
                <h1 class="page-title">Dashboard</h1>
                <div class="muted">
                    Angemeldet als ${escapeHtml(currentAdmin?.displayName || currentAdmin?.username || 'Admin')}
                    ${currentAdmin?.master ? '<span class="badge badge-master">MASTER</span>' : ''}
                </div>
            </div>
        </div>

        <div class="grid-3">
            <div class="card">
                <div class="muted">Räume</div>
                <div class="stat">${Object.keys(rooms).length}</div>
            </div>
            <div class="card">
                <div class="muted">Admins</div>
                <div class="stat">${admins.length}</div>
            </div>
            <div class="card">
                <div class="muted">Belegte Plätze</div>
                <div class="stat">${occupiedSeats}</div>
            </div>
        </div>

        <div class="grid-2">
            <div class="card">
                <h2>Microsoft Konfiguration</h2>
                <p><strong>Client ID:</strong><br>${escapeHtml(microsoftConfig.clientID || '')}</p>
                <p><strong>Tenant ID:</strong><br>${escapeHtml(microsoftConfig.tenantID || '')}</p>
                <p><strong>Callback URL:</strong><br>${escapeHtml(microsoftConfig.callbackURL || '')}</p>
            </div>

            <div class="card">
                <h2>Deine Rechte</h2>
                ${formatAdminPermissions(currentAdmin)}
            </div>
        </div>
    `;

    res.send(renderAdminLayout(req, 'Dashboard', content));
});

/*
==================================================
MEIN KONTO
==================================================
*/
app.get('/admin/account', requireAdmin, (req, res) => {
    const admin = getCurrentAdmin(req);
    const accError = String(req.query.error || '');
    const accField = String(req.query.field || '');

    const content = `
        <div class="topbar">
            <h1 class="page-title">Mein Konto</h1>
        </div>

        <div class="grid-2">
            <div class="card">
                <h2>Kontodaten</h2>
                <p><strong>Benutzername:</strong><br>${escapeHtml(admin.username)}</p>
                <p><strong>Typ:</strong><br>${admin.master ? 'Master-Admin' : 'Admin'}</p>
            </div>

            <div class="card">
                <h2>Eigenes Passwort ändern</h2>
                <form method="POST" action="/admin/account/password">
                    ${csrfField(req)}
                    <label>Aktuelles Passwort</label>
                    <div class="field-wrap">
                        <input type="password" id="acc_cur" name="currentPassword" required class="${accField === 'currentPassword' ? 'input-error' : ''}">
                        <button type="button" class="eye-btn" data-eye="acc_cur" onclick="toggleVis('acc_cur')">&#128065;</button>
                    </div>
                    ${accField === 'currentPassword' ? `<span class="field-error">${escapeHtml(accError)}</span>` : ''}
                    <label>Neues Passwort</label>
                    <div class="field-wrap">
                        <input type="password" id="acc_new" name="newPassword" required class="${accField === 'newPassword' ? 'input-error' : ''}">
                        <button type="button" class="eye-btn" data-eye="acc_new" onclick="toggleVis('acc_new')">&#128065;</button>
                    </div>
                    ${accField === 'newPassword' ? `<span class="field-error">${escapeHtml(accError)}</span>` : ''}
                    <label>Neues Passwort wiederholen</label>
                    <div class="field-wrap">
                        <input type="password" id="acc_con" name="confirmPassword" required class="${accField === 'confirmPassword' ? 'input-error' : ''}">
                        <button type="button" class="eye-btn" data-eye="acc_con" onclick="toggleVis('acc_con')">&#128065;</button>
                    </div>
                    ${accField === 'confirmPassword' ? `<span class="field-error">${escapeHtml(accError)}</span>` : ''}
                    <button type="submit">Passwort ändern</button>
                </form>
            </div>
        </div>
    `;

    res.send(renderAdminLayout(req, 'Mein Konto', content));
});

app.post('/admin/account/password', requireAdmin, requireCsrf, async (req, res) => {
    try {
        const admin = getCurrentAdmin(req);

        const currentPassword = String(req.body.currentPassword || '');
        const newPassword = String(req.body.newPassword || '');
        const confirmPassword = String(req.body.confirmPassword || '');

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.redirect('/admin/account?error=Bitte+alle+Felder+ausf%C3%BCllen&field=currentPassword');
        }

        if (newPassword !== confirmPassword) {
            return res.redirect('/admin/account?error=Die+neuen+Passw%C3%B6rter+stimmen+nicht+%C3%BCberein&field=confirmPassword');
        }

        if (newPassword.length < 8) {
            return res.redirect('/admin/account?error=Das+neue+Passwort+muss+mindestens+8+Zeichen+lang+sein&field=newPassword');
        }

        const valid = await bcrypt.compare(currentPassword, admin.passwordHash);
        if (!valid) {
            return res.redirect('/admin/account?error=Aktuelles+Passwort+ist+falsch&field=currentPassword');
        }

        admin.passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        saveAdmins();

        return res.send(renderAdminLayout(req, 'Passwort geändert', `
            <div class="topbar">
                <h1 class="page-title">Mein Konto</h1>
            </div>
            <div class="card">
                <div class="notice">Dein Passwort wurde erfolgreich geändert.</div>
                <p><a class="small-link" href="/admin/account">Zurück zu Mein Konto</a></p>
            </div>
        `));
    } catch (err) {
        console.error(err);
        return res.status(500).send('Passwort konnte nicht geändert werden');
    }
});

/*
==================================================
SYSTEM
==================================================
*/
app.get('/admin/system', requireAdmin, requirePermission('system.settings'), (req, res) => {
    const content = `
        <div class="topbar">
            <h1 class="page-title">System</h1>
        </div>

        <div class="card">
            <h2>Session Secret</h2>
            <div class="notice notice-warn">
                Das Session Secret schützt die Login-Sessions.
                Nach einer Änderung solltest du den Server neu starten.
            </div>

            <form method="POST" action="/admin/system/session-secret">
                ${csrfField(req)}
                <label>Neues Session Secret</label>
                <div class="field-wrap">
                    <input type="password" id="sys_secret" name="sessionSecret" value="${escapeHtml(appConfig.sessionSecret || '')}" required>
                    <button type="button" class="eye-btn" data-eye="sys_secret" onclick="toggleVis('sys_secret')">&#128065;</button>
                </div>
                <button type="submit">Session Secret speichern</button>
            </form>
        </div>

        <div class="card">
            <h2>Vorschlag für ein starkes Secret</h2>
            <div class="code-box">${escapeHtml(generateStrongSecret())}</div>
        </div>

        <div class="card">
            <h2>Automatisches Leeren der Sitzplätze</h2>
            <p style="font-size:14px;color:var(--muted);margin-bottom:16px;line-height:1.5;">
                Belegte Sitzplätze werden nach der gewählten Zeit automatisch freigegeben.
                Der Zeitpunkt wird beim Einchecken gespeichert.
            </p>
            <form method="POST" action="/admin/system/seat-clear-interval">
                ${csrfField(req)}
                <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px;">
                    ${SEAT_CLEAR_OPTIONS.map(opt => `
                        <label style="display:flex;align-items:center;gap:10px;font-size:14px;font-weight:normal;cursor:pointer;">
                            <input type="radio" name="seatClearInterval" value="${opt.value}"
                                ${(appConfig.seatClearInterval || 'never') === opt.value ? 'checked' : ''}
                                style="width:16px;height:16px;accent-color:var(--primary);">
                            ${escapeHtml(opt.label)}
                        </label>
                    `).join('')}
                </div>
                <button type="submit">Einstellung speichern</button>
            </form>
        </div>
    `;

    res.send(renderAdminLayout(req, 'System', content));
});

app.post('/admin/system/session-secret', requireAdmin, requirePermission('system.settings'), requireCsrf, (req, res) => {
    try {
        const newSecret = String(req.body.sessionSecret || '').trim();

        if (!newSecret) {
            return res.status(400).send('Session Secret fehlt');
        }

        if (newSecret.length < 32) {
            return res.status(400).send('Das Session Secret sollte mindestens 32 Zeichen lang sein');
        }

        appConfig.sessionSecret = newSecret;
        saveAppConfig();

        return res.send(renderAdminLayout(req, 'System', `
            <div class="topbar">
                <h1 class="page-title">System</h1>
            </div>
            <div class="card">
                <div class="notice">Session Secret gespeichert.</div>
                <p>Bitte den Server neu starten, damit nur noch das neue Secret aktiv ist.</p>
                <p><a class="small-link" href="/admin/system">Zurück zu System</a></p>
            </div>
        `));
    } catch (err) {
        console.error(err);
        return res.status(500).send('Session Secret konnte nicht gespeichert werden');
    }
});

app.post('/admin/system/seat-clear-interval', requireAdmin, requirePermission('system.settings'), requireCsrf, (req, res) => {
    try {
        const value = String(req.body.seatClearInterval || 'never');
        const valid = SEAT_CLEAR_OPTIONS.map(o => o.value);

        if (!valid.includes(value)) {
            return res.status(400).send('Ungültiger Wert');
        }

        appConfig.seatClearInterval = value;
        saveAppConfig();

        return res.redirect('/admin/system');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Einstellung konnte nicht gespeichert werden');
    }
});

/*
==================================================
LOGO
==================================================
*/
app.get('/admin/logo', requireAdmin, requirePermission('system.logo'), (req, res) => {
    const logoExists = fs.existsSync(LOGO_FILE);

    const content = `
        <div class="topbar">
            <h1 class="page-title">Logo verwalten</h1>
        </div>

        <div class="card">
            <h2>Aktuelles Logo</h2>
            ${
                logoExists
                    ? `
                    <div style="margin-bottom:20px;">
                        <img src="/logo.png?v=${Date.now()}" alt="Aktuelles Logo" style="max-width:320px; width:100%; height:auto; object-fit:contain; border:1px solid #e5e7eb; border-radius:12px; padding:12px; background:#fff;">
                    </div>
                    `
                    : `<p class="muted">Aktuell ist kein Logo vorhanden.</p>`
            }

            <div class="notice">
                Das hochgeladene Bild wird automatisch als <strong>logo.png</strong> gespeichert und das alte Logo ersetzt.
            </div>

            <form method="POST" action="/admin/logo/upload?_csrf=${getCsrfToken(req)}" enctype="multipart/form-data">
                <label>Neues Logo hochladen</label>
                <input type="file" name="logo" accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp" required>
                <button type="submit">Logo hochladen</button>
            </form>
        </div>
    `;

    res.send(renderAdminLayout(req, 'Logo verwalten', content));
});

app.post(
    '/admin/logo/upload',
    requireAdmin,
    requirePermission('system.logo'),
    requireCsrf,
    (req, res, next) => {
        upload.single('logo')(req, res, function (err) {
            if (err) {
                return res.status(400).send(renderAdminLayout(req, 'Logo verwalten', `
                    <div class="topbar">
                        <h1 class="page-title">Logo verwalten</h1>
                    </div>
                    <div class="card">
                        <div class="notice notice-warn">${escapeHtml(err.message || 'Upload fehlgeschlagen.')}</div>
                        <p><a class="small-link" href="/admin/logo">Zurück zur Logo-Verwaltung</a></p>
                    </div>
                `));
            }
            next();
        });
    },
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).send(renderAdminLayout(req, 'Logo verwalten', `
                    <div class="topbar">
                        <h1 class="page-title">Logo verwalten</h1>
                    </div>
                    <div class="card">
                        <div class="notice notice-warn">Bitte eine Bilddatei auswählen.</div>
                        <p><a class="small-link" href="/admin/logo">Zurück zur Logo-Verwaltung</a></p>
                    </div>
                `));
            }

            await saveLogoFromBuffer(req.file.buffer);

            return res.send(renderAdminLayout(req, 'Logo verwalten', `
                <div class="topbar">
                    <h1 class="page-title">Logo verwalten</h1>
                </div>
                <div class="card">
                    <div class="notice">Logo erfolgreich hochgeladen und ersetzt.</div>
                    <div style="margin-bottom:20px;">
                        <img src="/logo.png?v=${Date.now()}" alt="Neues Logo" style="max-width:320px; width:100%; height:auto; object-fit:contain; border:1px solid #e5e7eb; border-radius:12px; padding:12px; background:#fff;">
                    </div>
                    <p><a class="small-link" href="/admin/logo">Zurück zur Logo-Verwaltung</a></p>
                </div>
            `));
        } catch (err) {
            console.error('Logo Upload Fehler:', err);
            return res.status(500).send(renderAdminLayout(req, 'Logo verwalten', `
                <div class="topbar">
                    <h1 class="page-title">Logo verwalten</h1>
                </div>
                <div class="card">
                    <div class="notice notice-warn">Logo konnte nicht gespeichert werden.</div>
                    <p><a class="small-link" href="/admin/logo">Zurück zur Logo-Verwaltung</a></p>
                </div>
            `));
        }
    }
);

/*
==================================================
RÄUME
==================================================
*/
app.get('/admin/rooms', requireAdmin, requirePermission('rooms.view'), (req, res) => {
    const roomCards = Object.values(rooms).map((room) => {
        const seatRows = room.seats.map((seat, index) => `
            <tr>
                <td>Platz ${index + 1}</td>
                <td>${escapeHtml(seat.name)}</td>
                <td>${escapeHtml(seat.title)}</td>
                <td>
                    ${
                        hasPermission(req, 'rooms.clearSeat')
                            ? `
                            <form method="POST" action="/admin/clear-seat" class="inline-form">
                                ${csrfField(req)}
                                <input type="hidden" name="roomId" value="${escapeHtml(room.id)}">
                                <input type="hidden" name="seat" value="${index + 1}">
                                <button type="submit" class="btn-danger">Leeren</button>
                            </form>
                            `
                            : '<span class="muted">Keine Rechte</span>'
                    }
                </td>
            </tr>
        `).join('');

        return `
            <div class="card">
                <h2>${escapeHtml(room.id)} – ${escapeHtml(room.abteilung)} (${escapeHtml(room.roomnumber)})</h2>

                ${
                    hasPermission(req, 'rooms.edit')
                        ? `
                        <form method="POST" action="/admin/update-room">
                            ${csrfField(req)}
                            <input type="hidden" name="roomId" value="${escapeHtml(room.id)}">

                            <label>Abteilung</label>
                            <input type="text" name="abteilung" value="${escapeHtml(room.abteilung)}" required>

                            <label>Raumnummer</label>
                            <input type="text" name="roomnumber" value="${escapeHtml(room.roomnumber)}" required>

                            <label>TRMNL Update-Modus</label>
                            <select name="trmnlMode" id="trmnlMode_${escapeHtml(room.id)}" onchange="trmnlModeChange('${escapeHtml(room.id)}')" style="margin-bottom:12px;">
                                <option value="none"    ${(room.trmnlMode||'none')==='none'    ? 'selected' : ''}>Kein TRMNL</option>
                                <option value="polling" ${(room.trmnlMode||'none')==='polling' ? 'selected' : ''}>Polling (TRMNL zieht Daten selbst)</option>
                                <option value="webhook" ${(room.trmnlMode||'none')==='webhook' ? 'selected' : ''}>Webhook / Push (sofortige Aktualisierung)</option>
                            </select>

                            <div id="trmnl_polling_${escapeHtml(room.id)}" style="display:${(room.trmnlMode||'none')==='polling' ? 'block' : 'none'}">
                                <p style="font-size:13px;opacity:.7;margin-bottom:8px;">TRMNL fragt das Gerät selbst in einem Intervall ab. Kein Push von DeskView — stelle das Refresh-Intervall direkt in TRMNL ein.</p>
                            </div>

                            <div id="trmnl_webhook_${escapeHtml(room.id)}" style="display:${(room.trmnlMode||'none')==='webhook' ? 'block' : 'none'}">
                                <p style="font-size:13px;opacity:.7;margin-bottom:8px;">Bei jeder Änderung werden die Daten sofort an TRMNL gesendet.</p>

                                <label>Webhook URL <span style="font-weight:400;opacity:.6;">(aus TRMNL Plugin → Webhook-Strategie)</span></label>
                                <input type="text" name="trmnlWebhookUrl" value="${escapeHtml(room.trmnlWebhookUrl || '')}" placeholder="https://trmnl.com/api/custom_plugins/...">
                            </div>

                            <hr style="margin:20px 0;border:none;border-top:1px solid var(--border);">
                            <h3 style="font-size:15px;margin:0 0 10px 0;">Sleep Schedule <span style="font-weight:400;opacity:.6;font-size:13px;">(optional – spart Akku nachts)</span></h3>
                            <p style="font-size:13px;opacity:.7;margin-bottom:10px;">Das Gerät schläft außerhalb der Arbeitszeiten und aktualisiert nicht. Benötigt den TRMNL Device API Key.</p>

                            <label>TRMNL Account API Key <span style="font-weight:400;opacity:.6;">(Account → Settings → API Key)</span></label>
                            <input type="text" name="trmnlDeviceApiKey" value="${escapeHtml(room.trmnlDeviceApiKey || '')}" placeholder="Account API Key aus TRMNL Settings">

                            <label>Device MAC-Adresse</label>
                            <input type="text" name="trmnlDeviceMac" value="${escapeHtml(room.trmnlDeviceMac || '')}" placeholder="z. B. 08:92:72:65:F8:9C">

                            <div style="display:flex;gap:16px;margin-top:4px;">
                                <div style="flex:1;">
                                    <label>Aktiv ab (Morgens)</label>
                                    <input type="time" name="trmnlSleepEnd" value="${escapeHtml(room.trmnlSleepEnd || '07:00')}">
                                </div>
                                <div style="flex:1;">
                                    <label>Schlafen ab (Abends)</label>
                                    <input type="time" name="trmnlSleepStart" value="${escapeHtml(room.trmnlSleepStart || '19:00')}">
                                </div>
                            </div>

                            <button type="submit">Raum speichern</button>
                        </form>

                        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
                            <form id="trmnlTestForm_${escapeHtml(room.id)}" style="margin:0;">
                                <input type="hidden" name="_csrf" value="${getCsrfToken(req)}">
                                <input type="hidden" name="roomId" value="${escapeHtml(room.id)}">
                                <button type="button" onclick="testTrmnlPush('${escapeHtml(room.id)}')" style="background:#6b7280;">TRMNL Push testen</button>
                            </form>
                            <form id="trmnlSleepForm_${escapeHtml(room.id)}" style="margin:0;">
                                <input type="hidden" name="_csrf" value="${getCsrfToken(req)}">
                                <input type="hidden" name="roomId" value="${escapeHtml(room.id)}">
                                <button type="button" onclick="saveSleepSchedule('${escapeHtml(room.id)}')" style="background:#059669;">Sleep Schedule speichern</button>
                            </form>
                        </div>
                        <pre id="trmnlTestResult_${escapeHtml(room.id)}" style="display:none;margin-top:8px;background:#111;color:#0f0;padding:10px;border-radius:6px;font-size:12px;overflow:auto;max-height:200px;"></pre>
                        `
                        : `
                        <p><strong>Abteilung:</strong> ${escapeHtml(room.abteilung)}</p>
                        <p><strong>Raumnummer:</strong> ${escapeHtml(room.roomnumber)}</p>
                        `
                }

                ${
                    hasPermission(req, 'rooms.delete')
                        ? `
                        <form method="POST" action="/admin/delete-room" style="margin-top:16px;">
                            ${csrfField(req)}
                            <input type="hidden" name="roomId" value="${escapeHtml(room.id)}">
                            <button type="submit" class="btn-danger">Raum löschen</button>
                        </form>
                        `
                        : ''
                }

                <table style="margin-top:20px;">
                    <thead>
                        <tr>
                            <th>Platz</th>
                            <th>Name</th>
                            <th>Status</th>
                            <th>Aktion</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${seatRows}
                    </tbody>
                </table>

                ${
                    hasPermission(req, 'rooms.edit')
                        ? `
                        <div style="display:flex; gap:10px; margin-top:16px; align-items:center;">
                            <form method="POST" action="/admin/add-seat" class="inline-form">
                                ${csrfField(req)}
                                <input type="hidden" name="roomId" value="${escapeHtml(room.id)}">
                                <button type="submit" class="btn-secondary">+ Platz hinzufügen</button>
                            </form>
                            ${room.seats.length > 1 ? `
                            <form method="POST" action="/admin/remove-seat" class="inline-form">
                                ${csrfField(req)}
                                <input type="hidden" name="roomId" value="${escapeHtml(room.id)}">
                                <button type="submit" class="btn-danger">− Letzten Platz entfernen</button>
                            </form>
                            ` : ''}
                            <span class="muted" style="font-size:13px;">${room.seats.length} Platz${room.seats.length !== 1 ? 'plätze' : ''}</span>
                        </div>
                        `
                        : ''
                }
            </div>
        `;
    }).join('');

    const content = `
        <div class="topbar">
            <h1 class="page-title">Räume verwalten</h1>
        </div>

        ${
            hasPermission(req, 'rooms.create')
                ? `
                <div class="card">
                    <h2>Neuen Raum anlegen</h2>
                    <form method="POST" action="/admin/create-room">
                        ${csrfField(req)}
                        <label>Raum-ID</label>
                        <input type="text" name="roomId" placeholder="z. B. room3" required>

                        <label>Abteilung</label>
                        <input type="text" name="abteilung" placeholder="z. B. Vertrieb" required>

                        <label>Raumnummer</label>
                        <input type="text" name="roomnumber" placeholder="z. B. R.105" required>

                        <button type="submit">Raum erstellen</button>
                    </form>
                </div>
                `
                : ''
        }

        ${roomCards || '<div class="card"><p>Keine Räume vorhanden.</p></div>'}
    `;

    res.send(renderAdminLayout(req, 'Räume', content));
});

app.post('/admin/create-room', requireAdmin, requirePermission('rooms.create'), requireCsrf, (req, res) => {
    try {
        const roomId = String(req.body.roomId || '').trim();
        const abteilung = String(req.body.abteilung || '').trim();
        const roomnumber = String(req.body.roomnumber || '').trim();

        if (!roomId || !abteilung || !roomnumber) {
            return res.status(400).send('Fehlende Daten');
        }

        if (roomId.length > 64 || abteilung.length > 128 || roomnumber.length > 32) {
            return res.status(400).send('Eingabe zu lang');
        }

        if (!/^[a-zA-Z0-9_\-]+$/.test(roomId)) {
            return res.status(400).send('Raum-ID darf nur Buchstaben, Zahlen, - und _ enthalten');
        }

        if (['__proto__', 'constructor', 'prototype'].includes(roomId)) {
            return res.status(400).send('Ungültige Raum-ID');
        }

        if (rooms[roomId]) {
            return res.status(400).send('Raum existiert bereits');
        }

        rooms[roomId] = {
            id: roomId,
            abteilung,
            roomnumber,
            seats: [
                { name: 'Frei', title: '' },
                { name: 'Frei', title: '' },
                { name: 'Frei', title: '' },
                { name: 'Frei', title: '' }
            ]
        };

        saveRooms();
        return res.redirect('/admin/rooms');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Raum konnte nicht gespeichert werden');
    }
});

app.post('/admin/update-room', requireAdmin, requirePermission('rooms.edit'), requireCsrf, (req, res) => {
    try {
        const roomId = String(req.body.roomId || '').trim();
        const room = getRoom(roomId);

        if (!room) {
            return res.status(404).send('Raum nicht gefunden');
        }

        room.abteilung = String(req.body.abteilung || '').trim();
        room.roomnumber = String(req.body.roomnumber || '').trim();
        room.trmnlMode = ['none','polling','webhook'].includes(req.body.trmnlMode) ? req.body.trmnlMode : 'none';
        room.trmnlWebhookUrl = String(req.body.trmnlWebhookUrl || '').trim();
        room.trmnlDeviceApiKey = String(req.body.trmnlDeviceApiKey || '').trim();
        room.trmnlDeviceMac = String(req.body.trmnlDeviceMac || '').trim();
        room.trmnlSleepStart = String(req.body.trmnlSleepStart || '').trim();
        room.trmnlSleepEnd = String(req.body.trmnlSleepEnd || '').trim();

        saveRooms();
        return res.redirect('/admin/rooms');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Raum konnte nicht aktualisiert werden');
    }
});

app.post('/admin/test-trmnl-push', requireAdmin, requirePermission('rooms.edit'), requireCsrf, async (req, res) => {
    const roomId = String(req.body.roomId || '').trim();
    const room = getRoom(roomId);
    if (!room) return res.status(404).json({ error: 'Raum nicht gefunden' });

    const mode = room.trmnlMode || 'none';
    if (mode === 'none') return res.json({ error: 'Kein TRMNL-Modus konfiguriert' });

    const payload = renderRoomApiJson(room);
    const results = [];

    if (mode === 'webhook' && room.trmnlWebhookUrl) {
        try {
            const r = await fetch(room.trmnlWebhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ merge_variables: payload })
            });
            const text = await r.text();
            results.push({ type: 'Webhook URL', status: r.status, body: text.slice(0, 300) });
        } catch (err) {
            results.push({ type: 'Webhook URL', error: err.message });
        }
    }

    return res.json({ results, payload });
});

app.post('/admin/save-sleep-schedule', requireAdmin, requirePermission('rooms.edit'), requireCsrf, async (req, res) => {
    const roomId = String(req.body.roomId || '').trim();
    const room = getRoom(roomId);
    if (!room) return res.status(404).json({ error: 'Raum nicht gefunden' });
    if (!room.trmnlDeviceApiKey || !room.trmnlDeviceMac) return res.status(400).json({ error: 'Device API Key und MAC-Adresse fehlen' });

    try {
        const headers = { 'Authorization': `Bearer ${room.trmnlDeviceApiKey}`, 'Content-Type': 'application/json' };

        // Gerät per MAC finden
        const listRes = await fetch('https://usetrmnl.com/api/devices', { headers });
        if (!listRes.ok) {
            const errText = await listRes.text();
            return res.json({ error: `TRMNL Fehler: ${listRes.status}`, body: errText.slice(0, 200) });
        }

        const list = await listRes.json();
        const devices = list.devices || list;
        const device = Array.isArray(devices)
            ? devices.find(d => (d.mac_address || '').toUpperCase() === room.trmnlDeviceMac.toUpperCase())
            : null;

        if (!device) return res.json({ error: `Gerät mit MAC ${room.trmnlDeviceMac} nicht gefunden`, all_devices: Array.isArray(devices) ? devices.map(d => d.mac_address) : devices });

        // Zeiten HH:MM → Minuten seit Mitternacht
        const toMinutes = t => { const [h, m] = (t || '00:00').split(':').map(Number); return h * 60 + m; };
        const sleepStart = room.trmnlSleepStart || '19:00';
        const sleepEnd   = room.trmnlSleepEnd   || '07:00';

        const patchRes = await fetch(`https://usetrmnl.com/api/devices/${device.id}`, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
                sleep_mode_enabled: true,
                sleep_start_time: toMinutes(sleepStart),
                sleep_end_time:   toMinutes(sleepEnd)
            })
        });

        const text = await patchRes.text();
        let body;
        try { body = JSON.parse(text); } catch(e) { body = text; }
        return res.json({ status: patchRes.status, body, device_id: device.id, sleep_start: sleepStart, sleep_end: sleepEnd });
    } catch (err) {
        return res.json({ error: err.message });
    }
});

app.post('/admin/delete-room', requireAdmin, requirePermission('rooms.delete'), requireCsrf, (req, res) => {
    try {
        const roomId = String(req.body.roomId || '').trim();

        if (!rooms[roomId]) {
            return res.status(404).send('Raum nicht gefunden');
        }

        delete rooms[roomId];
        saveRooms();

        return res.redirect('/admin/rooms');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Raum konnte nicht gelöscht werden');
    }
});

app.post('/admin/add-seat', requireAdmin, requirePermission('rooms.edit'), requireCsrf, (req, res) => {
    try {
        const roomId = String(req.body.roomId || '').trim();
        const room = getRoom(roomId);

        if (!room) {
            return res.status(404).send('Raum nicht gefunden');
        }

        if (room.seats.length >= 20) {
            return res.status(400).send('Maximal 20 Plätze pro Raum');
        }

        room.seats.push({ name: 'Frei', title: '' });
        saveRooms();
        pushToTrmnl(room);
        return res.redirect('/admin/rooms');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Platz konnte nicht hinzugefügt werden');
    }
});

app.post('/admin/remove-seat', requireAdmin, requirePermission('rooms.edit'), requireCsrf, (req, res) => {
    try {
        const roomId = String(req.body.roomId || '').trim();
        const room = getRoom(roomId);

        if (!room) {
            return res.status(404).send('Raum nicht gefunden');
        }

        if (room.seats.length <= 1) {
            return res.status(400).send('Mindestens 1 Platz erforderlich');
        }

        room.seats.pop();
        saveRooms();
        pushToTrmnl(room);
        return res.redirect('/admin/rooms');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Platz konnte nicht entfernt werden');
    }
});

app.post('/admin/clear-seat', requireAdmin, requirePermission('rooms.clearSeat'), requireCsrf, (req, res) => {
    try {
        const roomId = String(req.body.roomId || '').trim();
        const seat = Number.parseInt(req.body.seat, 10);
        const room = getRoom(roomId);

        if (!room || !Number.isInteger(seat) || seat < 1 || seat > room.seats.length) {
            return res.status(400).send('Ungültige Daten');
        }

        room.seats[seat - 1] = { name: 'Frei', title: '' };
        saveRooms();
        pushToTrmnl(room);

        return res.redirect('/admin/rooms');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Platz konnte nicht geleert werden');
    }
});

/*
==================================================
RAUMLINKS / ANSICHTEN
==================================================
*/
app.get('/admin/links', requireAdmin, requirePermission('links.view'), (req, res) => {
    const roomCards = Object.values(rooms).map((room) => {
        const seatLinks = room.seats.map((_, index) => {
            const seatNumber = index + 1;
            return `
                <a class="small-link" href="/${encodeURIComponent(room.id)}/sit/${seatNumber}" target="_blank">
                    Platz ${seatNumber}
                </a>
            `;
        }).join('');

        return `
            <div class="card">
                <h2>${escapeHtml(room.abteilung)}</h2>
                <p><strong>Raum-ID:</strong> ${escapeHtml(room.id)}</p>
                <p><strong>Raumnummer:</strong> ${escapeHtml(room.roomnumber)}</p>

                <div class="links-row">
                    <a class="small-link" href="/${encodeURIComponent(room.id)}" target="_blank">Raumansicht öffnen</a>
                    <a class="small-link" href="/${encodeURIComponent(room.id)}/api/deskview" target="_blank">DeskView API öffnen</a>
                    <a class="small-link" href="/${encodeURIComponent(room.id)}/api/Komvera" target="_blank">Legacy API öffnen</a>
                </div>

                <p><strong>Sitzplätze:</strong></p>
                <div class="links-row">
                    ${seatLinks}
                </div>
            </div>
        `;
    }).join('');

    const content = `
        <div class="topbar">
            <h1 class="page-title">Raumlinks / Ansichten</h1>
        </div>

        <div class="grid-2">
            ${roomCards || '<div class="card"><p>Keine Räume vorhanden.</p></div>'}
        </div>
    `;

    res.send(renderAdminLayout(req, 'Raumlinks', content));
});

/*
==================================================
ADMINS
==================================================
*/
app.get('/admin/admins', requireAdmin, requirePermission('admins.view'), (req, res) => {
    const adminRows = admins.map((admin) => `
        <tr>
            <td>
                <div style="font-weight:700;">${escapeHtml(admin.displayName || admin.username)}</div>
                <div style="font-size:12px; color:var(--muted);">@${escapeHtml(admin.username)} ${admin.master ? '<span class="badge badge-master">MASTER</span>' : ''}</div>
            </td>
            <td>********</td>
            <td>${formatAdminPermissions(admin)}</td>
            <td>
                ${
                    !admin.master && hasPermission(req, 'admins.edit')
                        ? `
                        <form method="GET" action="/admin/admins/edit/${encodeURIComponent(admin.username)}" class="inline-form">
                            <button type="submit" class="btn-secondary">Bearbeiten</button>
                        </form>
                        `
                        : ''
                }

                ${
                    !admin.master && hasPermission(req, 'admins.delete')
                        ? `
                        <form method="POST" action="/admin/admins/delete" class="inline-form" style="margin-left:8px;">
                            ${csrfField(req)}
                            <input type="hidden" name="username" value="${escapeHtml(admin.username)}">
                            <button type="submit" class="btn-danger">Löschen</button>
                        </form>
                        `
                        : ''
                }

                ${admin.master ? '<span class="muted">Nicht löschbar</span>' : ''}
            </td>
        </tr>
    `).join('');

    const content = `
        <div class="topbar">
            <h1 class="page-title">Admins verwalten</h1>
        </div>

        ${
            hasPermission(req, 'admins.create')
                ? `
                <div class="card">
                    <h2>Neuen Admin anlegen</h2>
                    <div class="notice">
                        Es kann nur genau einen Master-Admin geben. Neue Admins werden immer als normale Admins erstellt.
                    </div>
                    <form method="POST" action="/admin/admins/create">
                        ${csrfField(req)}
                        <label>Benutzername</label>
                        <input type="text" name="username" required>

                        <label>Anzeigename (Vorname Nachname)</label>
                        <input type="text" name="displayName" placeholder="z. B. Max Mustermann">

                        <label>Passwort</label>
                        <div class="field-wrap">
                            <input type="password" id="adm_create_pw" name="password" required>
                            <button type="button" class="eye-btn" data-eye="adm_create_pw" onclick="toggleVis('adm_create_pw')">&#128065;</button>
                        </div>

                        <label>Berechtigungen</label>
                        <div class="permission-box">
                            ${renderPermissionCheckboxes([])}
                        </div>

                        <button type="submit" style="margin-top:16px;">Admin erstellen</button>
                    </form>
                </div>
                `
                : ''
        }

        <div class="card">
            <h2>Vorhandene Admins</h2>
            <table>
                <thead>
                    <tr>
                        <th>Benutzername</th>
                        <th>Passwort</th>
                        <th>Rechte</th>
                        <th>Aktion</th>
                    </tr>
                </thead>
                <tbody>
                    ${adminRows}
                </tbody>
            </table>
        </div>
    `;

    res.send(renderAdminLayout(req, 'Admins', content));
});

app.post('/admin/admins/create', requireAdmin, requirePermission('admins.create'), requireCsrf, async (req, res) => {
    try {
        const username = String(req.body.username || '').trim();
        const displayName = String(req.body.displayName || '').trim();
        const password = String(req.body.password || '');

        let permissions = req.body.permissions || [];
        if (!Array.isArray(permissions)) {
            permissions = permissions ? [permissions] : [];
        }

        permissions = permissions.filter(p => AVAILABLE_PERMISSIONS.includes(p));

        if (!username || !password) {
            return res.status(400).send('Fehlende Daten');
        }

        if (username.length > 64 || displayName.length > 128) {
            return res.status(400).send('Eingabe zu lang');
        }

        if (password.length < 8) {
            return res.status(400).send('Das Passwort muss mindestens 8 Zeichen lang sein');
        }

        if (password.length > 256) {
            return res.status(400).send('Passwort zu lang');
        }

        if (getAdminUser(username)) {
            return res.status(400).send('Admin existiert bereits');
        }

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        admins.push(normalizeAdmin({
            username,
            displayName,
            passwordHash,
            master: false,
            permissions
        }));

        saveAdmins();
        return res.redirect('/admin/admins');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Admin konnte nicht erstellt werden');
    }
});

app.get('/admin/admins/edit/:username', requireAdmin, requirePermission('admins.edit'), (req, res) => {
    const username = String(req.params.username || '').trim();
    const admin = getAdminUser(username);

    if (!admin) {
        return res.status(404).send('Admin nicht gefunden');
    }

    if (admin.master) {
        return res.status(400).send('Master-Admin kann nicht bearbeitet werden');
    }

    const content = `
        <div class="topbar">
            <h1 class="page-title">Admin bearbeiten</h1>
        </div>

        <div class="card">
            <h2>${escapeHtml(admin.username)}</h2>
            <form method="POST" action="/admin/admins/edit">
                ${csrfField(req)}
                <input type="hidden" name="username" value="${escapeHtml(admin.username)}">

                <label>Anzeigename (Vorname Nachname)</label>
                <input type="text" name="displayName" value="${escapeHtml(admin.displayName || '')}" placeholder="z. B. Max Mustermann">

                <label>Neues Passwort</label>
                <div class="field-wrap">
                    <input type="password" id="adm_edit_pw" name="password" placeholder="Leer lassen = unverändert">
                    <button type="button" class="eye-btn" data-eye="adm_edit_pw" onclick="toggleVis('adm_edit_pw')">&#128065;</button>
                </div>

                <label>Berechtigungen</label>
                <div class="permission-box">
                    ${renderPermissionCheckboxes(admin.permissions)}
                </div>

                <button type="submit" style="margin-top:16px;">Änderungen speichern</button>
            </form>
        </div>
    `;

    res.send(renderAdminLayout(req, 'Admin bearbeiten', content));
});

app.post('/admin/admins/edit', requireAdmin, requirePermission('admins.edit'), requireCsrf, async (req, res) => {
    try {
        const username = String(req.body.username || '').trim();
        const admin = getAdminUser(username);

        if (!admin) {
            return res.status(404).send('Admin nicht gefunden');
        }

        if (admin.master) {
            return res.status(400).send('Master-Admin kann nicht bearbeitet werden');
        }

        const password = String(req.body.password || '');
        const displayName = String(req.body.displayName || '').trim();

        let permissions = req.body.permissions || [];
        if (!Array.isArray(permissions)) {
            permissions = permissions ? [permissions] : [];
        }

        permissions = permissions.filter(p => AVAILABLE_PERMISSIONS.includes(p));

        admin.permissions = permissions;
        admin.displayName = displayName;

        if (displayName.length > 128) {
            return res.status(400).send('Anzeigename zu lang');
        }

        if (password.trim()) {
            if (password.length < 8) {
                return res.status(400).send('Das neue Passwort muss mindestens 8 Zeichen lang sein');
            }
            if (password.length > 256) {
                return res.status(400).send('Passwort zu lang');
            }
            admin.passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        }

        saveAdmins();
        return res.redirect('/admin/admins');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Admin konnte nicht bearbeitet werden');
    }
});

app.post('/admin/admins/delete', requireAdmin, requirePermission('admins.delete'), requireCsrf, (req, res) => {
    try {
        const username = String(req.body.username || '').trim();
        const admin = getAdminUser(username);

        if (!admin) {
            return res.status(404).send('Admin nicht gefunden');
        }

        if (admin.master) {
            return res.status(400).send('Master-Admin kann nicht gelöscht werden');
        }

        admins = admins.filter(a => a.username !== username);
        saveAdmins();

        return res.redirect('/admin/admins');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Admin konnte nicht gelöscht werden');
    }
});

/*
==================================================
MICROSOFT
==================================================
*/
app.get('/admin/microsoft', requireAdmin, requirePermission('microsoft.view'), (req, res) => {
    const content = `
        <div class="topbar">
            <h1 class="page-title">Microsoft Konfiguration</h1>
        </div>

        ${hasPermission(req, 'microsoft.edit') ? `
        <div class="card">
            <h2>Microsoft Login</h2>
            <p style="font-size:14px;color:var(--muted);margin-bottom:16px;line-height:1.5;">
                Wenn aktiviert, melden sich Mitarbeiter per Microsoft-Konto an.<br>
                Wenn deaktiviert, geben sie Name und Titel manuell ein.
            </p>
            <form method="POST" action="/admin/microsoft/toggle">
                ${csrfField(req)}
                <div style="display:flex;align-items:center;gap:14px;">
                    <label class="toggle-switch">
                        <input type="checkbox" name="enabled" value="1" onchange="this.form.submit()" ${isMicrosoftLoginEnabled() ? 'checked' : ''}>
                        <span class="toggle-slider"></span>
                    </label>
                    <span style="font-size:14px;font-weight:600;">
                        Microsoft Login ist ${isMicrosoftLoginEnabled() ? '<span style="color:var(--primary)">aktiviert</span>' : '<span style="color:var(--muted)">deaktiviert</span>'}
                    </span>
                </div>
            </form>
        </div>
        ` : ''}

        <div class="card">
            <h2>Entra / Azure AD Daten</h2>

            ${
                hasPermission(req, 'microsoft.edit')
                    ? `
                    <form method="POST" action="/admin/microsoft/update">
                        ${csrfField(req)}
                        <label>Client ID</label>
                        <input type="text" name="clientID" value="${escapeHtml(microsoftConfig.clientID || '')}" required>

                        <label>Tenant ID</label>
                        <input type="text" name="tenantID" value="${escapeHtml(microsoftConfig.tenantID || '')}" required>

                        <label>Client Secret</label>
                        <div class="field-wrap">
                            <input type="password" id="ms_secret" name="clientSecret" value="${escapeHtml(microsoftConfig.clientSecret || '')}" required>
                            <button type="button" class="eye-btn" data-eye="ms_secret" onclick="toggleVis('ms_secret')">&#128065;</button>
                        </div>

                        <label>Callback URL</label>
                        <input type="text" name="callbackURL" value="${escapeHtml(microsoftConfig.callbackURL || '')}" required>

                        <button type="submit">Microsoft Konfiguration speichern</button>
                    </form>
                    `
                    : `
                    <p><strong>Client ID:</strong><br>${escapeHtml(microsoftConfig.clientID || '')}</p>
                    <p><strong>Tenant ID:</strong><br>${escapeHtml(microsoftConfig.tenantID || '')}</p>
                    <p><strong>Client Secret:</strong><br>********</p>
                    <p><strong>Callback URL:</strong><br>${escapeHtml(microsoftConfig.callbackURL || '')}</p>
                    `
            }
        </div>
    `;

    res.send(renderAdminLayout(req, 'Microsoft', content));
});

app.post('/admin/microsoft/update', requireAdmin, requirePermission('microsoft.edit'), requireCsrf, (req, res) => {
    try {
        const clientID = String(req.body.clientID || '').trim();
        const tenantID = String(req.body.tenantID || '').trim();
        const clientSecret = String(req.body.clientSecret || '').trim();
        const callbackURL = String(req.body.callbackURL || '').trim();

        if (!clientID || !tenantID || !clientSecret || !callbackURL) {
            return res.status(400).send('Fehlende Daten');
        }

        microsoftConfig = {
            clientID,
            tenantID,
            clientSecret,
            callbackURL
        };

        saveMicrosoftConfig();
        refreshMsalClient();

        return res.redirect('/admin/microsoft');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Microsoft Konfiguration konnte nicht gespeichert werden');
    }
});

app.post('/admin/microsoft/toggle', requireAdmin, requirePermission('microsoft.edit'), requireCsrf, (req, res) => {
    try {
        appConfig.microsoftLoginEnabled = req.body.enabled === '1';
        saveAppConfig();
        return res.redirect('/admin/microsoft');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Einstellung konnte nicht gespeichert werden');
    }
});

/*
==================================================
DESKVIEW API
==================================================
*/
app.get('/:room/api/deskview', (req, res) => {
    const room = getRoom(req.params.room);

    if (!room) {
        return res.status(404).json({ error: 'Raum nicht gefunden' });
    }

    return res.json(renderRoomApiJson(room));
});

/*
==================================================
LEGACY KOMPATIBILITÄT
==================================================
*/
app.get('/:room/api/Komvera', (req, res) => {
    const room = getRoom(req.params.room);

    if (!room) {
        return res.status(404).json({ error: 'Raum nicht gefunden' });
    }

    return res.json(renderRoomApiJson(room));
});

/*
==================================================
QR / ROOM
==================================================
*/
app.get('/:room', (req, res) => {
    const roomId = req.params.room;
    const room = getRoom(roomId);

    if (!room) {
        return res.status(404).send('Raum nicht gefunden');
    }

    const seatButtons = room.seats.map((seat, index) => {
        const seatNumber = index + 1;
        const occupied = seat.name && seat.name !== 'Frei';

        return `
            <a class="seat-card ${occupied ? 'occupied' : ''}" href="/${escapeHtml(roomId)}/sit/${seatNumber}">
                <div class="seat-number">Platz ${seatNumber}</div>
                <div class="seat-status">
                    ${occupied ? `Belegt<br><strong>${escapeHtml(seat.name)}</strong>` : 'Frei'}
                </div>
            </a>
        `;
    }).join('');

    const logoExists = fs.existsSync(LOGO_FILE);
    res.send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${escapeHtml(room.abteilung)} – Sitzplatz wählen</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                :root {
                    --bg: #f0f4f8;
                    --surface: #ffffff;
                    --text: #1e293b;
                    --muted: #64748b;
                    --border: #e2e8f0;
                    --primary: #2563eb;
                    --primary-hover: #1d4ed8;
                    --card-shadow: 0 4px 24px rgba(0,0,0,0.08);
                    --header-bg: #ffffff;
                    --seat-free-bg: #f0fdf4;
                    --seat-free-border: #bbf7d0;
                    --seat-free-text: #166534;
                    --seat-occ-bg: #fff1f2;
                    --seat-occ-border: #fecdd3;
                    --seat-occ-text: #9f1239;
                }
                [data-theme="dark"] {
                    --bg: #0f172a;
                    --surface: #1e293b;
                    --text: #f1f5f9;
                    --muted: #94a3b8;
                    --border: #334155;
                    --primary: #3b82f6;
                    --primary-hover: #2563eb;
                    --card-shadow: 0 4px 24px rgba(0,0,0,0.4);
                    --header-bg: #1e293b;
                    --seat-free-bg: #14532d;
                    --seat-free-border: #166534;
                    --seat-free-text: #86efac;
                    --seat-occ-bg: #450a0a;
                    --seat-occ-border: #991b1b;
                    --seat-occ-text: #fca5a5;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    background: var(--bg);
                    color: var(--text);
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    transition: background 0.2s, color 0.2s;
                }
                header {
                    background: var(--header-bg);
                    border-bottom: 1px solid var(--border);
                    padding: 0 32px;
                    height: 64px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    position: sticky;
                    top: 0;
                    z-index: 100;
                    box-shadow: 0 1px 8px rgba(0,0,0,0.05);
                }
                .header-logo { max-height: 52px; max-width: 220px; width: auto; height: auto; object-fit: contain; }
                .header-logo-text { font-size: 18px; font-weight: 700; color: var(--text); }
                .header-right { display: flex; align-items: center; gap: 10px; }
                .btn-theme {
                    background: none;
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    padding: 7px 12px;
                    cursor: pointer;
                    color: var(--muted);
                    font-size: 13px;
                    transition: border-color 0.15s;
                }
                .btn-theme:hover { border-color: var(--primary); color: var(--primary); }
                .btn-admin {
                    background: var(--primary);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 8px 16px;
                    font-size: 13px;
                    font-weight: 600;
                    cursor: pointer;
                    text-decoration: none;
                    transition: background 0.15s;
                }
                .btn-admin:hover { background: var(--primary-hover); }
                .content {
                    flex: 1;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 40px 24px;
                }
                .card {
                    width: 100%;
                    max-width: 680px;
                    background: var(--surface);
                    border-radius: 20px;
                    padding: 40px 36px;
                    box-shadow: var(--card-shadow);
                    border: 1px solid var(--border);
                    text-align: center;
                }
                .card-logo { margin-bottom: 28px; }
                .card-logo img { max-height: 90px; max-width: 300px; width: auto; height: auto; object-fit: contain; }
                .back-link {
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    font-size: 13px;
                    color: var(--muted);
                    text-decoration: none;
                    margin-bottom: 24px;
                    transition: color 0.15s;
                }
                .back-link:hover { color: var(--primary); }
                h1 { font-size: 32px; font-weight: 800; color: var(--text); margin-bottom: 6px; }
                .room-num { font-size: 16px; color: var(--muted); margin-bottom: 28px; }
                .hint { font-size: 15px; color: var(--muted); margin-bottom: 24px; }
                .grid {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 14px;
                }
                .seat-card {
                    display: block;
                    text-decoration: none;
                    background: var(--seat-free-bg);
                    border: 2px solid var(--seat-free-border);
                    border-radius: 14px;
                    padding: 20px 16px;
                    color: var(--seat-free-text);
                    transition: transform 0.15s, box-shadow 0.15s;
                    text-align: center;
                }
                .seat-card:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 20px rgba(0,0,0,0.12);
                }
                .seat-card.occupied {
                    background: var(--seat-occ-bg);
                    border-color: var(--seat-occ-border);
                    color: var(--seat-occ-text);
                }
                .seat-number { font-size: 22px; font-weight: 700; margin-bottom: 8px; }
                .seat-status { font-size: 14px; line-height: 1.5; }
                footer {
                    text-align: center;
                    padding: 20px;
                    font-size: 13px;
                    color: var(--muted);
                    border-top: 1px solid var(--border);
                }
                footer a { color: var(--primary); text-decoration: none; }
                footer a:hover { text-decoration: underline; }
                @media (max-width: 600px) {
                    header { padding: 0 16px; }
                    .card { padding: 28px 20px; }
                    h1 { font-size: 26px; }
                    .grid { grid-template-columns: 1fr; }
                }
            </style>
            <script>
                (function() {
                    var saved = localStorage.getItem('deskview-theme') || 'light';
                    document.documentElement.setAttribute('data-theme', saved);
                })();
            </script>
        </head>
        <body>
            <header>
                <div>
                    ${logoExists
                        ? `<img src="/logo.png" alt="Logo" class="header-logo">`
                        : `<span class="header-logo-text">Komvera DeskView</span>`
                    }
                </div>
                <div class="header-right">
                    <button class="btn-theme" onclick="toggleTheme()">&#9790; Modus</button>
                    <a href="/admin" class="btn-admin">&#9632; Admin</a>
                </div>
            </header>

            <div class="content">
                <div class="card">
                    ${logoExists ? `<div class="card-logo"><img src="/logo.png" alt="Logo"></div>` : ''}
                    <a href="/" class="back-link">&#8592; Zur Übersicht</a>
                    <h1>${escapeHtml(room.abteilung)}</h1>
                    <div class="room-num">Raum ${escapeHtml(room.roomnumber)}</div>
                    <div class="hint">Bitte den Sitzplatz auswählen.</div>

                    <div class="grid">
                        ${seatButtons}
                    </div>
                </div>
            </div>

            <footer>
                &copy; ${new Date().getFullYear()} Komvera IT GmbH &middot;
                <a href="https://www.komvera.de" target="_blank" rel="noopener noreferrer">www.komvera.de</a> &middot;
                <a href="mailto:info@komvera.de">info@komvera.de</a>
            </footer>

            <script>
                function toggleTheme() {
                    var current = document.documentElement.getAttribute('data-theme');
                    var next = current === 'dark' ? 'light' : 'dark';
                    document.documentElement.setAttribute('data-theme', next);
                    localStorage.setItem('deskview-theme', next);
                }
            </script>
        </body>
        </html>
    `);
});

/*
==================================================
QR / SIT
==================================================
*/
app.get('/:room/sit/:seat', (req, res) => {
    const roomId = req.params.room;
    const seat = Number.parseInt(req.params.seat, 10);
    const room = getRoom(roomId);

    if (!room) {
        return res.status(404).send('Raum nicht gefunden');
    }

    if (!Number.isInteger(seat) || seat < 1 || seat > room.seats.length) {
        return res.status(400).send('Ungültiger Platz');
    }

    req.session.pendingRoom = roomId;
    req.session.pendingSeat = seat;

    req.session.save((err) => {
        if (err) {
            console.error('Session save error:', err);
            return res.status(500).send('Session konnte nicht gespeichert werden.');
        }

        const logoExists = fs.existsSync(LOGO_FILE);
        res.send(`
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(room.abteilung)} – Platz ${seat}</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
    --bg: #f0f4f8;
    --surface: #ffffff;
    --text: #1e293b;
    --muted: #64748b;
    --border: #e2e8f0;
    --primary: #0078d4;
    --primary-hover: #0062ad;
    --btn-admin: #2563eb;
    --btn-admin-hover: #1d4ed8;
    --card-shadow: 0 4px 24px rgba(0,0,0,0.08);
    --header-bg: #ffffff;
    --badge-bg: #eff6ff;
    --badge-text: #1d4ed8;
}
[data-theme="dark"] {
    --bg: #0f172a;
    --surface: #1e293b;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --border: #334155;
    --primary: #38bdf8;
    --primary-hover: #0ea5e9;
    --card-shadow: 0 4px 24px rgba(0,0,0,0.4);
    --header-bg: #1e293b;
    --badge-bg: #1e3a5f;
    --badge-text: #93c5fd;
}
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    transition: background 0.2s, color 0.2s;
}
header {
    background: var(--header-bg);
    border-bottom: 1px solid var(--border);
    padding: 0 32px;
    height: 64px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 1px 8px rgba(0,0,0,0.05);
}
.header-logo { max-height: 52px; max-width: 220px; width: auto; height: auto; object-fit: contain; }
.header-logo-text { font-size: 18px; font-weight: 700; color: var(--text); }
.header-right { display: flex; align-items: center; gap: 10px; }
.btn-theme {
    background: none;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 7px 12px;
    cursor: pointer;
    color: var(--muted);
    font-size: 13px;
    transition: border-color 0.15s;
}
.btn-theme:hover { border-color: var(--btn-admin); color: var(--btn-admin); }
.btn-admin {
    background: var(--btn-admin);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    transition: background 0.15s;
}
.btn-admin:hover { background: var(--btn-admin-hover); }
.content {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 40px 24px;
}
.card {
    width: 100%;
    max-width: 480px;
    background: var(--surface);
    border-radius: 20px;
    padding: 40px 36px;
    box-shadow: var(--card-shadow);
    border: 1px solid var(--border);
    text-align: center;
}
.card-logo { margin-bottom: 24px; }
.card-logo img { max-height: 80px; max-width: 260px; width: auto; height: auto; object-fit: contain; }
.back-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: var(--muted);
    text-decoration: none;
    margin-bottom: 20px;
    transition: color 0.15s;
}
.back-link:hover { color: var(--btn-admin); }
.room-name { font-size: 28px; font-weight: 800; margin-bottom: 6px; }
.room-info { font-size: 15px; color: var(--muted); margin-bottom: 16px; }
.seat-badge {
    display: inline-block;
    background: var(--badge-bg);
    color: var(--badge-text);
    font-size: 18px;
    font-weight: 700;
    padding: 8px 20px;
    border-radius: 999px;
    margin-bottom: 28px;
}
.ms-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    padding: 16px;
    background: var(--primary);
    color: white;
    text-decoration: none;
    border-radius: 12px;
    font-weight: 700;
    font-size: 16px;
    transition: background 0.2s, transform 0.1s;
}
.ms-btn:hover {
    background: var(--primary-hover);
    transform: translateY(-1px);
}
.ms-btn svg { flex-shrink: 0; }
.hint-text { font-size: 13px; color: var(--muted); margin-top: 14px; }
footer {
    text-align: center;
    padding: 20px;
    font-size: 13px;
    color: var(--muted);
    border-top: 1px solid var(--border);
}
footer a { color: var(--btn-admin); text-decoration: none; }
footer a:hover { text-decoration: underline; }
@media (max-width: 600px) {
    header { padding: 0 16px; }
    .card { padding: 28px 20px; }
    .room-name { font-size: 22px; }
}
</style>
<script>
    (function() {
        var saved = localStorage.getItem('deskview-theme') || 'light';
        document.documentElement.setAttribute('data-theme', saved);
    })();
</script>
</head>
<body>
<header>
    <div>
        ${logoExists
            ? `<img src="/logo.png" alt="Logo" class="header-logo">`
            : `<span class="header-logo-text">Komvera DeskView</span>`
        }
    </div>
    <div class="header-right">
        <button class="btn-theme" onclick="toggleTheme()">&#9790; Modus</button>
        <a href="/admin" class="btn-admin">&#9632; Admin</a>
    </div>
</header>

<div class="content">
    <div class="card">
        ${logoExists ? `<div class="card-logo"><img src="/logo.png" alt="Logo"></div>` : ''}
        <a href="/${encodeURIComponent(roomId)}" class="back-link">&#8592; Zurück zur Raumauswahl</a>
        <div class="room-name">${escapeHtml(room.abteilung)}</div>
        <div class="room-info">Raum ${escapeHtml(room.roomnumber)}</div>
        <div class="seat-badge">Platz ${seat}</div>

        ${isMicrosoftLoginEnabled() ? `
        <a class="ms-btn" href="/auth/login">
            <svg width="20" height="20" viewBox="0 0 21 21" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="1" y="1" width="9" height="9" fill="#F25022"/>
                <rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
                <rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>
                <rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
            </svg>
            Mit Microsoft anmelden
        </a>
        <div class="hint-text">Nach dem Login wird der Platz automatisch eingetragen.</div>
        ` : `
        <form method="POST" action="/${encodeURIComponent(roomId)}/sit/${seat}" style="text-align:left;">
            <input type="hidden" name="_csrf" value="${getCsrfToken(req)}">
            <label style="display:block;font-size:13px;font-weight:600;color:var(--muted);margin-bottom:5px;">Dein Name</label>
            <input type="text" name="name" placeholder="z. B. Max Mustermann" required
                style="width:100%;padding:11px 13px;margin-bottom:12px;border:1px solid var(--border);border-radius:10px;font-size:14px;background:var(--surface);color:var(--text);">
            <label style="display:block;font-size:13px;font-weight:600;color:var(--muted);margin-bottom:5px;">Jobtitel <span style="font-weight:400;opacity:.7;">(optional)</span></label>
            <input type="text" name="title" placeholder="z. B. Entwickler"
                style="width:100%;padding:11px 13px;margin-bottom:20px;border:1px solid var(--border);border-radius:10px;font-size:14px;background:var(--surface);color:var(--text);">
            <button type="submit" class="ms-btn" style="border:none;cursor:pointer;width:100%;">
                Platz belegen
            </button>
        </form>
        `}
    </div>
</div>

<footer>
    &copy; ${new Date().getFullYear()} Komvera IT GmbH &middot;
    <a href="https://www.komvera.de" target="_blank" rel="noopener noreferrer">www.komvera.de</a> &middot;
    <a href="mailto:info@komvera.de">info@komvera.de</a>
</footer>

<script>
    function toggleTheme() {
        var current = document.documentElement.getAttribute('data-theme');
        var next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('deskview-theme', next);
    }
</script>
</body>
</html>
        `);
    });
});

/*
==================================================
MANUELLES EINCHECKEN
==================================================
*/
app.post('/:room/sit/:seat', requireCsrf, (req, res) => {
    if (isMicrosoftLoginEnabled()) {
        return res.status(400).send('Manuelles Einchecken ist deaktiviert.');
    }

    const roomId = req.params.room;
    const seat = Number.parseInt(req.params.seat, 10);
    const room = getRoom(roomId);

    if (!room) return res.status(404).send('Raum nicht gefunden');
    if (!Number.isInteger(seat) || seat < 1 || seat > room.seats.length) return res.status(400).send('Ungültiger Platz');

    const name = String(req.body.name || '').trim();
    const title = String(req.body.title || '').trim();

    if (!name) return res.status(400).send('Name ist erforderlich');
    if (name.length > 128) return res.status(400).send('Name zu lang');
    if (title.length > 128) return res.status(400).send('Jobtitel zu lang');

    room.seats[seat - 1] = { name, title: title || 'Mitarbeiter', since: Date.now() };
    saveRooms();
    pushToTrmnl(room);

    const logoExists = fs.existsSync(LOGO_FILE);
    return res.send(`
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Eingecheckt</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                :root { --bg:#f0f4f8; --surface:#fff; --text:#1e293b; --muted:#64748b; --border:#e2e8f0; --primary:#2563eb; }
                [data-theme="dark"] { --bg:#0f172a; --surface:#1e293b; --text:#f1f5f9; --muted:#94a3b8; --border:#334155; }
                body { min-height:100vh; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif; display:flex; align-items:center; justify-content:center; padding:32px 20px; }
                .card { background:var(--surface); border:1px solid var(--border); border-radius:20px; padding:40px 36px; max-width:440px; width:100%; text-align:center; box-shadow:0 8px 32px rgba(0,0,0,0.08); }
                .icon { font-size:52px; margin-bottom:16px; }
                h2 { font-size:22px; font-weight:800; margin-bottom:8px; }
                .sub { font-size:15px; color:var(--muted); margin-bottom:24px; }
                .back { display:inline-block; color:var(--primary); text-decoration:none; font-size:14px; font-weight:600; }
                .back:hover { text-decoration:underline; }
            </style>
            <script>(function(){var s=localStorage.getItem('deskview-theme')||'light';document.documentElement.setAttribute('data-theme',s);})();</script>
        </head>
        <body>
            <div class="card">
                ${logoExists ? `<div style="margin-bottom:20px;"><img src="/logo.png" alt="Logo" style="max-height:60px;max-width:200px;object-fit:contain;"></div>` : ''}
                <div class="icon">&#10003;</div>
                <h2>Eingecheckt!</h2>
                <p class="sub"><strong>${escapeHtml(name)}</strong> sitzt jetzt auf Platz ${seat}.</p>
                <a href="/${encodeURIComponent(roomId)}" class="back">&#8592; Zurück zur Raumübersicht</a>
                ${renderSupportFooter()}
            </div>
        </body>
        </html>
    `);
});

/*
==================================================
MICROSOFT LOGIN – MSAL (ersetzt passport-azure-ad)
==================================================
*/
app.get('/auth/login', (req, res) => {
    if (!hasMicrosoftConfig()) {
        return res.status(500).send('Microsoft / Entra ist noch nicht konfiguriert.');
    }

    if (!msalClient) {
        refreshMsalClient();
    }

    if (!msalClient) {
        return res.status(500).send('MSAL-Client konnte nicht initialisiert werden.');
    }

    const authCodeUrlParameters = {
        scopes: ['openid', 'profile', 'email', 'https://graph.microsoft.com/User.Read'],
        redirectUri: microsoftConfig.callbackURL,
        state: crypto.randomBytes(16).toString('hex')
    };

    msalClient
        .getAuthCodeUrl(authCodeUrlParameters)
        .then((authUrl) => {
            res.redirect(authUrl);
        })
        .catch((err) => {
            console.error('MSAL getAuthCodeUrl Fehler:', err);
            res.status(500).send('Microsoft Login konnte nicht gestartet werden.');
        });
});

app.get('/auth/callback', async (req, res) => {
    if (!hasMicrosoftConfig()) {
        return res.redirect('/auth/error?msg=' + encodeURIComponent('Microsoft / Entra ist nicht konfiguriert.'));
    }

    if (!msalClient) {
        refreshMsalClient();
    }

    if (!msalClient) {
        return res.redirect('/auth/error?msg=' + encodeURIComponent('MSAL-Client nicht verfügbar.'));
    }

    const code = req.query.code;

    if (!code) {
        return res.redirect('/auth/error?msg=' + encodeURIComponent('Kein Autorisierungscode von Microsoft erhalten.'));
    }

    try {
        const pendingRoom = req.session?.pendingRoom || null;
        const pendingSeat = Number.parseInt(req.session?.pendingSeat, 10);

        const pendingRoomObj = getRoom(pendingRoom);
        if (!pendingRoom || !pendingRoomObj) {
            return res.redirect('/auth/error?msg=' + encodeURIComponent('Kein gültiger Raum in der Session gefunden.'));
        }

        if (!Number.isInteger(pendingSeat) || pendingSeat < 1 || pendingSeat > pendingRoomObj.seats.length) {
            return res.redirect('/auth/error?msg=' + encodeURIComponent('Kein gültiger Platz in der Session gefunden.'));
        }

        const tokenRequest = {
            code: String(code),
            scopes: ['openid', 'profile', 'email', 'https://graph.microsoft.com/User.Read'],
            redirectUri: microsoftConfig.callbackURL
        };

        const tokenResponse = await msalClient.acquireTokenByCode(tokenRequest);

        if (!tokenResponse || !tokenResponse.accessToken) {
            return res.redirect('/auth/error?msg=' + encodeURIComponent('Kein Access Token von Microsoft erhalten.'));
        }

        const graphUser = await fetchMicrosoftUser(tokenResponse.accessToken);

        const room = getRoom(pendingRoom);

        if (!room) {
            return res.redirect('/auth/error?msg=' + encodeURIComponent('Raum nicht mehr vorhanden.'));
        }

        const fullName =
            graphUser.displayName ||
            `${graphUser.givenName || ''} ${graphUser.surname || ''}`.trim() ||
            'Unbekannt';

        const jobTitle = graphUser.jobTitle || 'Mitarbeiter';

        room.seats[pendingSeat - 1] = {
            name: fullName,
            title: jobTitle,
            since: Date.now()
        };

        saveRooms();
        pushToTrmnl(room);

        delete req.session.pendingRoom;
        delete req.session.pendingSeat;

        const logoExists = fs.existsSync(LOGO_FILE);
        return res.send(`
            <!DOCTYPE html>
            <html lang="de">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Eingecheckt</title>
                <style>
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    :root { --bg:#f0f4f8; --surface:#fff; --text:#1e293b; --muted:#64748b; --border:#e2e8f0; --primary:#2563eb; }
                    [data-theme="dark"] { --bg:#0f172a; --surface:#1e293b; --text:#f1f5f9; --muted:#94a3b8; --border:#334155; }
                    body { min-height:100vh; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif; display:flex; align-items:center; justify-content:center; padding:32px 20px; }
                    .card { background:var(--surface); border:1px solid var(--border); border-radius:20px; padding:40px 36px; max-width:440px; width:100%; text-align:center; box-shadow:0 8px 32px rgba(0,0,0,0.08); }
                    .icon { font-size:52px; margin-bottom:16px; }
                    h2 { font-size:22px; font-weight:800; margin-bottom:8px; }
                    .sub { font-size:15px; color:var(--muted); margin-bottom:24px; }
                    .back { display:inline-block; color:var(--primary); text-decoration:none; font-size:14px; font-weight:600; }
                    .back:hover { text-decoration:underline; }
                </style>
                <script>(function(){var s=localStorage.getItem('deskview-theme')||'light';document.documentElement.setAttribute('data-theme',s);})();</script>
            </head>
            <body>
                <div class="card">
                    ${logoExists ? `<div style="margin-bottom:20px;"><img src="/logo.png" alt="Logo" style="max-height:60px;max-width:200px;object-fit:contain;"></div>` : ''}
                    <div class="icon">&#10003;</div>
                    <h2>Eingecheckt!</h2>
                    <p class="sub"><strong>${escapeHtml(fullName)}</strong> sitzt jetzt auf Platz ${pendingSeat}.</p>
                    <a href="/${encodeURIComponent(pendingRoom)}" class="back">&#8592; Zurück zur Raumübersicht</a>
                    ${renderSupportFooter()}
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        console.error('Fehler im Auth-Callback:', err);
        return res.redirect('/auth/error?msg=' + encodeURIComponent('Benutzer konnte nicht gespeichert werden.'));
    }
});

app.get('/auth/error', (req, res) => {
    const msg = req.query.msg ? String(req.query.msg) : 'Unbekannter Fehler';

    res.status(500).send(`
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <title>Login Fehler</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding-top: 60px;
                }
                .support-footer {
                    margin-top: 30px;
                    padding-top: 18px;
                    border-top: 1px solid #e5e7eb;
                    text-align: center;
                    font-size: 14px;
                    color: #6b7280;
                }
                .support-footer a {
                    color: #2563eb;
                    text-decoration: none;
                }
                .support-footer a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <h2>Microsoft Login fehlgeschlagen</h2>
            <p>${escapeHtml(msg)}</p>
            ${renderSupportFooter()}
        </body>
        </html>
    `);
});

/*
==================================================
FEHLER
==================================================
*/
app.use((err, req, res, next) => {
    console.error('Fehler:', err);
    res.status(500).send(`
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <title>Serverfehler</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding-top: 60px;
                }
                .support-footer {
                    margin-top: 30px;
                    padding-top: 18px;
                    border-top: 1px solid #e5e7eb;
                    text-align: center;
                    font-size: 14px;
                    color: #6b7280;
                }
                .support-footer a {
                    color: #2563eb;
                    text-decoration: none;
                }
                .support-footer a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <h2>Interner Serverfehler</h2>
            <p>Ein unerwarteter Fehler ist aufgetreten. Bitte versuche es erneut.</p>
            ${renderSupportFooter()}
        </body>
        </html>
    `);
});

/*
==================================================
START
==================================================
*/
(async () => {
    try {
        ensureSingleMasterAdmin();
        ensurePublicDir();
        refreshMsalClient();

        setInterval(runSeatAutoClear, 60 * 1000);

        app.listen(PORT, '0.0.0.0', () => {
            console.log('Server läuft auf http://0.0.0.0:' + PORT);
            console.log('Beim ersten Start werden fehlende JSON-Dateien automatisch erstellt.');
        });
    } catch (err) {
        console.error('Serverstart fehlgeschlagen:', err);
        process.exit(1);
    }
})();