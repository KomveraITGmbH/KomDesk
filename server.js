const express = require('express');
const cors = require('cors');
const session = require('express-session');
let FileStore;
try { FileStore = require('session-file-store')(session); } catch(e) { console.warn('[Session] session-file-store nicht installiert, nutze MemoryStore. Führe npm install aus.'); }
const { ConfidentialClientApplication } = require('@azure/msal-node');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');
const sharp = require('sharp');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const os = require('os');
const { exec } = require('child_process');

// ---- Server-Log-Buffer ----
const _logBuffer = [];
function _pushLog(level, args) {
    const msg = args.map(a => (a && typeof a === 'object') ? JSON.stringify(a) : String(a)).join(' ');
    _logBuffer.push({ t: Date.now(), level, msg });
    if (_logBuffer.length > 200) _logBuffer.shift();
}
const _origLog  = console.log.bind(console);
const _origErr  = console.error.bind(console);
const _origWarn = console.warn.bind(console);
console.log   = (...a) => { _pushLog('info',  a); _origLog(...a);  };
console.error = (...a) => { _pushLog('error', a); _origErr(...a);  };
console.warn  = (...a) => { _pushLog('warn',  a); _origWarn(...a); };

// ---- CPU-Sampling (alle 3 Sek.) ----
let _cpuPct  = 0;
let _cpuPrev = null;
function _sampleCpu() {
    const cpus = os.cpus();
    const curr = cpus.reduce((acc, cpu) => {
        for (const [k, v] of Object.entries(cpu.times)) acc[k] = (acc[k] || 0) + v;
        return acc;
    }, {});
    if (_cpuPrev) {
        const idle  = curr.idle - _cpuPrev.idle;
        const total = Object.values(curr).reduce((s, v) => s + v, 0)
                    - Object.values(_cpuPrev).reduce((s, v) => s + v, 0);
        _cpuPct = total > 0 ? Math.round((1 - idle / total) * 100) : 0;
    }
    _cpuPrev = curr;
}
setInterval(_sampleCpu, 3000);
_sampleCpu();

function getServerStats() {
    const mem   = process.memoryUsage();
    const total = os.totalmem();
    const free  = os.freemem();
    const used  = total - free;
    const load  = os.loadavg();

    // IP-Adressen (nur IPv4, kein Loopback)
    const nets = os.networkInterfaces();
    const ips  = [];
    for (const iface of Object.values(nets)) {
        for (const addr of iface) {
            if (addr.family === 'IPv4' && !addr.internal) ips.push(addr.address);
        }
    }

    return {
        uptime:      Math.floor(process.uptime()),
        sysUptime:   Math.floor(os.uptime()),
        cpu:         _cpuPct,
        cpuCores:    os.cpus().length,
        load1:       load[0].toFixed(2),
        load5:       load[1].toFixed(2),
        load15:      load[2].toFixed(2),
        ramPct:      Math.round(used / total * 100),
        ramUsed:     Math.round(used  / 1024 / 1024),
        ramTotal:    Math.round(total / 1024 / 1024),
        heapUsed:    Math.round(mem.heapUsed  / 1024 / 1024),
        heapTotal:   Math.round(mem.heapTotal / 1024 / 1024),
        rss:         Math.round(mem.rss       / 1024 / 1024),
        nodeVer:     process.version,
        platform:    os.platform() + ' ' + os.arch(),
        hostname:    os.hostname(),
        ips:         ips,
    };
}

const app = express();
const PORT = 3000;
const BCRYPT_ROUNDS = 12;

if (process.env.HTTPS_ENABLED === 'true') {
    app.set('trust proxy', 1);
}


app.use(helmet({
    contentSecurityPolicy: false
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Zu viele Login-Versuche. Bitte 15 Minuten warten.',
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
});

const setupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: 'Zu viele Setup-Versuche. Bitte 1 Stunde warten.',
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
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
const TERMINALS_FILE = path.join(DATA_DIR, 'terminals.json');

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
            },
            {
                key: 'server.view',
                label: 'Server-Status anzeigen',
                description: 'Darf Laufzeit, Speicher und Logs des DeskView-Servers sehen.'
            },
            {
                key: 'server.restart',
                label: 'DeskView neu starten',
                description: 'Darf den DeskView-Dienst (komvera-deskview) neu starten.'
            },
            {
                key: 'server.reboot',
                label: 'Linux neu starten',
                description: 'Darf den gesamten Linux-Server (sudo reboot) neu starten.'
            }
        ]
    },
    {
        title: 'Terminals',
        permissions: [
            { key: 'terminals.view',   label: 'Terminals anzeigen',   description: 'Darf TRMNL-Terminal-Geräte sehen.' },
            { key: 'terminals.create', label: 'Terminals erstellen',   description: 'Darf neue TRMNL-Terminals anlegen.' },
            { key: 'terminals.edit',   label: 'Terminals bearbeiten',  description: 'Darf TRMNL-Terminal-Einstellungen ändern.' },
            { key: 'terminals.delete', label: 'Terminals löschen',     description: 'Darf TRMNL-Terminals entfernen.' }
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
let terminals = ensureJsonFile(TERMINALS_FILE, {});
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

function saveTerminals() {
    writeJsonFile(TERMINALS_FILE, terminals);
}

function getTerminal(id) {
    return terminals[id] || null;
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
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
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
        return '<span class="badge badge-master">MASTER</span>';
    }

    const perms = admin.permissions || [];
    const allPerms = AVAILABLE_PERMISSIONS;

    if (perms.length === allPerms.length && allPerms.every(p => perms.includes(p))) {
        return '<span class="badge">✓ Alle Berechtigungen</span>';
    }

    if (perms.length === 0) {
        return '<span class="muted">Keine Rechte</span>';
    }

    const groups = PERMISSION_GROUPS.map(group => {
        const matches = group.permissions.filter(p => perms.includes(p.key));
        if (matches.length === 0) return '';
        return `
        <div style="border:1px solid var(--border);border-radius:6px;overflow:hidden;margin-bottom:6px;">
            <div onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none';this.querySelector('.pg-arrow').style.transform=this.nextElementSibling.style.display==='block'?'rotate(90deg)':''"
                style="display:flex;justify-content:space-between;align-items:center;padding:7px 12px;cursor:pointer;font-size:13px;font-weight:600;user-select:none;">
                <span><span class="pg-arrow" style="font-size:11px;opacity:.5;margin-right:6px;display:inline-block;transition:transform .15s;">▶</span>${escapeHtml(group.title)}</span>
                <span style="font-size:11px;opacity:.5;">${matches.length}/${group.permissions.length}</span>
            </div>
            <div style="display:none;padding:6px 12px 10px 12px;border-top:1px solid var(--border);">
                ${matches.map(p => `<div style="font-size:12px;padding:2px 0;opacity:.7;">• ${escapeHtml(p.label)}</div>`).join('')}
            </div>
        </div>`;
    }).filter(Boolean).join('');

    return groups;
}

function renderSidebar(req) {
    const logoExists = fs.existsSync(LOGO_FILE);
    const currentAdmin = getCurrentAdmin(req);

    const items = [
        hasPermission(req, 'dashboard.view') ? `<a href="/admin">&#9632; Dashboard</a>` : '',
        hasPermission(req, 'rooms.view') ? `<a href="/admin/rooms">&#9632; Räume</a>` : '',
        hasPermission(req, 'terminals.view') ? `<a href="/admin/terminals">&#9632; Terminals</a>` : '',
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
                <button class="theme-toggle" id="devModeBtn" onclick="toggleDevMode()" title="Entwicklermodus" style="margin-top:6px;">&#128736; Dev</button>
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

            window._devMode = localStorage.getItem('deskview-devmode') === '1';
            function applyDevMode() {
                var btn = document.getElementById('devModeBtn');
                if (btn) btn.style.opacity = window._devMode ? '1' : '0.45';
                document.querySelectorAll('.dev-only').forEach(function(el) {
                    el.style.display = window._devMode ? '' : 'none';
                });
            }
            function toggleDevMode() {
                window._devMode = !window._devMode;
                localStorage.setItem('deskview-devmode', window._devMode ? '1' : '0');
                applyDevMode();
            }
            document.addEventListener('DOMContentLoaded', applyDevMode);
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
                var statusEl = document.getElementById('trmnlSleepStatus_' + roomId);
                var form = document.getElementById('trmnlSleepForm_' + roomId);
                if (statusEl) { statusEl.style.display = 'block'; statusEl.textContent = 'Speichere...'; statusEl.style.color = ''; }
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
                    var ok = !data.error && (data.status === 200 || data.status === 204);
                    if (statusEl) {
                        statusEl.textContent = ok ? '✅ Sleep Schedule gespeichert' : '❌ Fehler: ' + (data.error || data);
                        statusEl.style.color = ok ? '#059669' : '#dc2626';
                    }
                    if (window._devMode && resultEl) {
                        resultEl.style.display = 'block';
                        resultEl.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
                    }
                } catch(e) {
                    if (statusEl) { statusEl.textContent = '❌ Fehler: ' + e.message; statusEl.style.color = '#dc2626'; }
                }
            }

            async function loadDeviceStatus(roomId) {
                var statusEl = document.getElementById('trmnlDeviceStatus_' + roomId);
                var form = document.getElementById('trmnlStatusForm_' + roomId);
                statusEl.style.display = 'block';
                statusEl.innerHTML = 'Lade Gerätestatus...';
                try {
                    var fd = new FormData(form);
                    var r = await fetch('/admin/device-status', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams(fd).toString()
                    });
                    var data;
                    try { data = JSON.parse(await r.text()); } catch(e) { statusEl.innerHTML = 'Fehler beim Parsen'; return; }
                    if (data.error) { statusEl.innerHTML = '❌ ' + data.error; return; }
                    var d = data.device;
                    var battPct = d.percent_charged != null ? Math.round(d.percent_charged) + '%' : '–';
                    var battV   = d.battery_voltage != null ? d.battery_voltage.toFixed(2) + ' V' : '–';
                    var rssi    = d.rssi != null ? d.rssi + ' dBm' : '–';
                    var wifi    = d.wifi_strength != null ? d.wifi_strength + '%' : '–';
                    var sleep   = d.sleep_mode_enabled ? '✅ An' : '❌ Aus';
                    var sleepT  = d.sleep_mode_enabled ? (minutesToTime(d.sleep_start_time) + ' – ' + minutesToTime(d.sleep_end_time)) : '–';
                    statusEl.innerHTML =
                        '<b>🔋 Akku:</b> ' + battPct + ' (' + battV + ')<br>' +
                        '<b>📶 WLAN:</b> ' + wifi + ' (RSSI: ' + rssi + ')<br>' +
                        '<b>😴 Schlafmodus:</b> ' + sleep + ' ' + sleepT;
                } catch(e) {
                    statusEl.innerHTML = 'Fehler: ' + e.message;
                }
            }

            function minutesToTime(min) {
                if (min == null) return '–';
                var h = String(Math.floor(min / 60)).padStart(2, '0');
                var m = String(min % 60).padStart(2, '0');
                return h + ':' + m;
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
    if (!room.terminalId) return;
    const terminal = getTerminal(room.terminalId);
    if (!terminal || terminal.trmnlMode !== 'webhook' || !terminal.trmnlWebhookUrl) return;

    const payload = renderRoomApiJson(room);
    try {
        await fetch(terminal.trmnlWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ merge_variables: payload })
        });
    } catch (err) {
        console.error(`TRMNL Webhook Push Fehler (${room.id}):`, err.message);
    }
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
    const store = FileStore
        ? new FileStore({ path: path.join(DATA_DIR, 'sessions'), ttl: 86400, retries: 0, logFn: function(){} })
        : undefined;
    return session({
        store,
        secret: String(appConfig.sessionSecret || '').trim() || bootstrapSessionSecret,
        resave: false,
        saveUninitialized: false,
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
    const currentAdmin  = getCurrentAdmin(req);
    const roomList      = Object.values(rooms);
    const totalSeats    = roomList.reduce((s, r) => s + r.seats.length, 0);
    const occupiedSeats = roomList.reduce((s, r) => s + r.seats.filter(seat => seat.name && seat.name !== 'Frei').length, 0);
    const freeSeats     = totalSeats - occupiedSeats;
    const terminalList  = Object.values(terminals);

    const auslastungPct = totalSeats ? Math.round(occupiedSeats / totalSeats * 100) : 0;

    // --- Statistiken (volle Breite, Hero) ---
    const statsHtml = `
        <div class="card db-hero">
            <div class="db-hero-label">📊 Übersicht</div>
            <div class="db-stat-grid">
                <div class="db-stat-tile">
                    <div class="db-stat-num">${roomList.length}</div>
                    <div class="db-stat-sub">Räume</div>
                </div>
                <div class="db-stat-tile db-stat-tile--red">
                    <div class="db-stat-num" style="color:#dc2626;">${occupiedSeats}</div>
                    <div class="db-stat-sub">Belegt</div>
                </div>
                <div class="db-stat-tile db-stat-tile--green">
                    <div class="db-stat-num" style="color:#059669;">${freeSeats}</div>
                    <div class="db-stat-sub">Frei</div>
                </div>
                <div class="db-stat-tile">
                    <div class="db-stat-num">${terminalList.length}</div>
                    <div class="db-stat-sub">Terminals</div>
                </div>
            </div>
            <div style="margin-top:20px;">
                <div style="display:flex;justify-content:space-between;font-size:13px;opacity:.6;margin-bottom:6px;">
                    <span>Auslastung</span><span>${auslastungPct}%</span>
                </div>
                <div style="background:var(--border);border-radius:999px;height:8px;overflow:hidden;">
                    <div style="height:100%;width:${auslastungPct}%;background:${auslastungPct > 80 ? '#dc2626' : auslastungPct > 50 ? '#f59e0b' : '#059669'};border-radius:999px;transition:width .4s;"></div>
                </div>
            </div>
        </div>`;

    // --- Raumauslastung ---
    const roomOccHtml = hasPermission(req, 'rooms.view') ? `
        <div class="card">
            <div class="db-card-title">🏢 Raumauslastung</div>
            ${roomList.length === 0 ? '<p class="db-empty">Keine Räume.</p>' :
                roomList.map(r => {
                    const tot = r.seats.length, occ = r.seats.filter(s => s.name && s.name !== 'Frei').length;
                    const pct = tot ? Math.round(occ / tot * 100) : 0;
                    const c   = pct === 100 ? '#dc2626' : pct > 50 ? '#f59e0b' : '#059669';
                    return `<div class="db-room-row">
                        <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px;">
                            <span class="db-room-name">${escapeHtml(r.abteilung)} <span class="db-room-num">${escapeHtml(r.roomnumber)}</span></span>
                            <span style="font-weight:700;color:${c};font-size:14px;">${occ}<span style="font-weight:400;opacity:.5;">/${tot}</span></span>
                        </div>
                        <div style="background:var(--border);border-radius:999px;height:6px;overflow:hidden;">
                            <div style="height:100%;width:${pct}%;background:${c};border-radius:999px;"></div>
                        </div>
                    </div>`;
                }).join('')}
        </div>` : '';

    // --- Terminals ---
    const terminalsHtml = hasPermission(req, 'terminals.view') ? `
        <div class="card">
            <div class="db-card-title">🖥️ Terminals</div>
            ${terminalList.length === 0
                ? '<p class="db-empty">Keine Terminals. <a href="/admin/terminals" style="color:var(--primary);">Anlegen →</a></p>'
                : terminalList.map(t => {
                    const asgn = roomList.find(r => r.terminalId === t.id);
                    const mc   = t.trmnlMode === 'webhook' ? '#059669' : t.trmnlMode === 'polling' ? '#2563eb' : '#6b7280';
                    const hasStatus = !!(t.trmnlDeviceApiKey && t.trmnlDeviceMac);
                    return `<div class="term-live-row db-term-row" data-tid="${escapeHtml(t.id)}" data-interval="${t.statusRefreshInterval || 30}">
                        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
                            <div style="min-width:0;">
                                <div style="font-weight:600;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(t.name)}</div>
                                <div style="font-size:12px;opacity:.45;margin-top:2px;">${asgn ? escapeHtml(asgn.abteilung) : 'nicht zugewiesen'}</div>
                            </div>
                            <span style="flex-shrink:0;font-size:11px;padding:3px 9px;border-radius:999px;background:${mc}22;color:${mc};font-weight:700;letter-spacing:.02em;">${escapeHtml(t.trmnlMode || 'none')}</span>
                        </div>
                        ${hasStatus ? '<div class="ts-status db-ts-status"><span class="ts-batt">🔋 –</span><span class="ts-wifi">📶 –</span><span class="ts-sleep"></span></div>' : ''}
                    </div>`;
                }).join('')}
        </div>` : '';

    // --- Schnellaktionen ---
    const quickLinks = [
        hasPermission(req, 'rooms.create')    ? `<a href="/admin/rooms"     class="db-btn">＋ Raum</a>`     : '',
        hasPermission(req, 'terminals.create')? `<a href="/admin/terminals" class="db-btn">＋ Terminal</a>` : '',
        hasPermission(req, 'admins.create')   ? `<a href="/admin/admins"    class="db-btn">＋ Admin</a>`    : '',
        hasPermission(req, 'links.view')      ? `<a href="/admin/links"     class="db-btn">🔗 Raumlinks</a>` : '',
    ].filter(Boolean);
    const quickActionsHtml = quickLinks.length ? `
        <div class="card">
            <div class="db-card-title">⚡ Schnellaktionen</div>
            <div style="display:flex;flex-wrap:wrap;gap:10px;">${quickLinks.join('')}</div>
        </div>` : '';

    // --- Meine Rechte ---
    const myPermsHtml = `
        <div class="card">
            <div class="db-card-title">👤 Meine Rechte</div>
            ${formatAdminPermissions(currentAdmin)}
        </div>`;

    // --- Microsoft ---
    const microsoftHtml = hasPermission(req, 'microsoft.view') ? (() => {
        const cfg = microsoftConfig, en = appConfig.microsoftLoginEnabled;
        const ok  = !!(cfg.clientID && cfg.tenantID && cfg.clientSecret && cfg.callbackURL);
        return `<div class="card">
            <div class="db-card-title">🔷 Microsoft / Entra ID</div>
            <div style="display:flex;flex-direction:column;gap:8px;">
                <div class="db-info-row">
                    <span>Login aktiviert</span><span style="font-weight:700;color:${en ? '#059669' : '#6b7280'};">${en ? '✅ Ja' : '❌ Nein'}</span>
                </div>
                <div class="db-info-row">
                    <span>Konfiguriert</span><span style="font-weight:700;color:${ok ? '#059669' : '#f59e0b'};">${ok ? '✅ Vollständig' : '⚠️ Unvollständig'}</span>
                </div>
            </div>
        </div>`;
    })() : '';

    // --- Admins ---
    const adminsHtml = hasPermission(req, 'admins.view') ? `
        <div class="card">
            <div class="db-card-title">👥 Admins</div>
            <div style="display:flex;flex-direction:column;gap:8px;">
                ${admins.map(a => `
                <div class="db-info-row">
                    <span style="font-weight:500;">${escapeHtml(a.displayName || a.username)}${a.master ? ' <span class="badge badge-master" style="font-size:10px;vertical-align:middle;">MASTER</span>' : ''}</span>
                    <span style="opacity:.4;font-size:13px;">${a.microsoft ? 'Microsoft' : 'Lokal'}</span>
                </div>`).join('')}
            </div>
        </div>` : '';

    // --- Server-Status ---
    const serverHtml = hasPermission(req, 'server.view') ? `
        <div class="card db-hero" style="grid-column:1/-1;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:10px;">
                <div class="db-card-title" style="margin:0;">⚙️ DeskView Server</div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;" data-csrf="${getCsrfToken(req)}">
                    <button onclick="srvFetchStatus()" style="padding:6px 14px;border:1.5px solid var(--border);border-radius:8px;background:transparent;color:var(--text);font-size:12px;font-weight:600;cursor:pointer;">📋 systemctl status</button>
                    ${hasPermission(req, 'server.restart') ? `<button onclick="srvConfirmRestart('deskview')" style="padding:6px 14px;border:1.5px solid #f59e0b;border-radius:8px;background:transparent;color:#f59e0b;font-size:12px;font-weight:600;cursor:pointer;">↺ DeskView neu starten</button>` : ''}
                    ${hasPermission(req, 'server.reboot') ? `<button onclick="srvConfirmRestart('linux')" style="padding:6px 14px;border:1.5px solid #dc2626;border-radius:8px;background:transparent;color:#dc2626;font-size:12px;font-weight:600;cursor:pointer;">⏻ Linux neu starten</button>` : ''}
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;">
                <div>
                    <div style="font-size:12px;font-weight:600;opacity:.45;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;">CPU &amp; RAM</div>
                    <div style="display:flex;flex-direction:column;gap:7px;">
                        <div class="db-info-row"><span>CPU (<span id="srv-cpu-cores">–</span> Kerne)</span>
                            <span style="display:flex;align-items:center;gap:8px;">
                                <span style="width:70px;height:6px;background:var(--border);border-radius:999px;overflow:hidden;display:inline-block;">
                                    <span id="srv-cpu-bar" style="display:block;height:100%;width:0%;background:#2563eb;border-radius:999px;transition:width .5s;"></span>
                                </span>
                                <span id="srv-cpu" style="font-weight:700;min-width:36px;text-align:right;">–</span>
                            </span>
                        </div>
                        <div class="db-info-row"><span>Load avg</span><span id="srv-load" style="font-weight:600;font-size:12px;opacity:.8;">–</span></div>
                        <div class="db-info-row"><span>RAM</span>
                            <span style="display:flex;align-items:center;gap:8px;">
                                <span style="width:70px;height:6px;background:var(--border);border-radius:999px;overflow:hidden;display:inline-block;">
                                    <span id="srv-ram-bar" style="display:block;height:100%;width:0%;background:#059669;border-radius:999px;transition:width .5s;"></span>
                                </span>
                                <span id="srv-ram" style="font-weight:700;min-width:36px;text-align:right;">–</span>
                            </span>
                        </div>
                        <div class="db-info-row"><span>RAM gesamt</span><span id="srv-ram-detail" style="font-weight:600;opacity:.7;">–</span></div>
                    </div>
                </div>
                <div>
                    <div style="font-size:12px;font-weight:600;opacity:.45;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;">System</div>
                    <div style="display:flex;flex-direction:column;gap:7px;">
                        <div class="db-info-row"><span>Hostname</span><span id="srv-host" style="font-weight:600;font-size:12px;">–</span></div>
                        <div class="db-info-row"><span>IP-Adresse(n)</span><span id="srv-ip" style="font-weight:600;font-size:12px;">–</span></div>
                        <div class="db-info-row"><span>Plattform</span><span id="srv-platform" style="font-weight:600;font-size:12px;opacity:.7;">–</span></div>
                        <div class="db-info-row"><span>System-Uptime</span><span id="srv-sys-uptime" style="font-weight:600;">–</span></div>
                    </div>
                </div>
                <div>
                    <div style="font-size:12px;font-weight:600;opacity:.45;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;">DeskView Prozess</div>
                    <div style="display:flex;flex-direction:column;gap:7px;">
                        <div class="db-info-row"><span>Laufzeit</span><span id="srv-uptime" style="font-weight:600;">–</span></div>
                        <div class="db-info-row"><span>Node.js</span><span id="srv-node" style="font-weight:600;opacity:.7;font-size:12px;">–</span></div>
                        <div class="db-info-row"><span>Heap</span><span id="srv-heap" style="font-weight:600;">–</span></div>
                        <div class="db-info-row"><span>RSS</span><span id="srv-rss" style="font-weight:600;">–</span></div>
                    </div>
                </div>
                <div style="grid-column:1/-1;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <div style="font-size:12px;font-weight:600;opacity:.45;text-transform:uppercase;letter-spacing:.06em;">Server-Log</div>
                        <span id="srv-log-age" style="font-size:11px;opacity:.3;"></span>
                    </div>
                    <div id="srv-log" style="background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:10px 14px;height:200px;overflow-y:auto;font-family:monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;"></div>
                    <div id="srv-systemctl-wrap" style="display:none;margin-top:12px;">
                        <div style="font-size:12px;font-weight:600;opacity:.45;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;">systemctl status komvera-deskview</div>
                        <div id="srv-systemctl" style="background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:10px 14px;max-height:220px;overflow-y:auto;font-family:monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;"></div>
                    </div>
                </div>
            </div>
        </div>` : '';

    const content = `
        <style>
        .db-hero { grid-column: 1 / -1; }
        .db-hero-label { font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;opacity:.45;margin-bottom:16px; }
        .db-stat-grid { display:grid;grid-template-columns:repeat(2,1fr);gap:12px; }
        @media(min-width:500px){ .db-stat-grid{grid-template-columns:repeat(4,1fr);} }
        .db-stat-tile { text-align:center;padding:18px 10px;border:1px solid var(--border);border-radius:12px;background:var(--bg); }
        .db-stat-num { font-size:clamp(28px,3.5vw,52px);font-weight:800;line-height:1; }
        .db-stat-sub { font-size:13px;opacity:.5;margin-top:6px; }
        .db-card-title { font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;opacity:.45;margin-bottom:18px; }
        .db-empty { opacity:.45;font-size:14px;margin:0; }
        .db-room-row { margin-bottom:14px; }
        .db-room-row:last-child { margin-bottom:0; }
        .db-room-name { font-weight:600;font-size:15px; }
        .db-room-num { font-weight:400;opacity:.45;font-size:13px;margin-left:5px; }
        .db-term-row { padding:12px 14px;border:1px solid var(--border);border-radius:10px;margin-bottom:8px; }
        .db-term-row:last-child { margin-bottom:0; }
        .db-ts-status { margin-top:8px;font-size:13px;opacity:.55;display:flex;gap:14px; }
        .db-btn { display:inline-block;padding:10px 18px;border:1.5px solid var(--border);border-radius:10px;text-decoration:none;font-size:14px;font-weight:500;color:var(--text);transition:border-color .15s,background .15s; }
        .db-btn:hover { border-color:var(--primary);color:var(--primary); }
        .db-info-row { display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:14px; }
        .db-grid { display:grid;grid-template-columns:1fr;gap:16px;align-items:start; }
        @media(min-width:600px){ .db-grid{grid-template-columns:repeat(2,1fr);gap:20px;} }
        @media(min-width:1100px){ .db-grid{grid-template-columns:repeat(3,1fr);gap:24px;} }
        @media(min-width:1500px){ .db-grid{grid-template-columns:repeat(4,1fr);gap:28px;} }
        .card { border-radius:16px;padding:clamp(16px,2.5vw,28px); }
        </style>
        <div class="topbar">
            <div>
                <h1 class="page-title">Dashboard</h1>
                <div class="muted">Angemeldet als ${escapeHtml(currentAdmin?.displayName || currentAdmin?.username || 'Admin')} ${currentAdmin?.master ? '<span class="badge badge-master">MASTER</span>' : ''}</div>
            </div>
        </div>
        <div class="db-grid">
            ${statsHtml}
            ${roomOccHtml}
            ${terminalsHtml}
            ${quickActionsHtml}
            ${myPermsHtml}
            ${microsoftHtml}
            ${adminsHtml}
            ${serverHtml}
        </div>
        <style>
        .srv-modal-bg { position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9000;display:flex;align-items:center;justify-content:center;padding:16px;backdrop-filter:blur(3px); }
        .srv-modal { background:var(--card-bg);border:1px solid var(--border);border-radius:20px;padding:32px;max-width:420px;width:100%;box-shadow:0 24px 60px rgba(0,0,0,.25);animation:srvModalIn .18s ease; }
        @keyframes srvModalIn { from{opacity:0;transform:scale(.95)} to{opacity:1;transform:scale(1)} }
        .srv-modal-icon { font-size:40px;text-align:center;margin-bottom:14px; }
        .srv-modal-title { font-size:20px;font-weight:700;text-align:center;margin-bottom:8px; }
        .srv-modal-desc { font-size:14px;opacity:.6;text-align:center;margin-bottom:22px;line-height:1.5; }
        .srv-modal-check { display:flex;align-items:center;gap:10px;padding:12px 16px;border:1.5px solid var(--border);border-radius:12px;cursor:pointer;margin-bottom:20px;transition:border-color .15s; }
        .srv-modal-check:hover { border-color:var(--primary); }
        .srv-modal-check input { width:18px;height:18px;cursor:pointer;accent-color:var(--primary);flex-shrink:0; }
        .srv-modal-check span { font-size:14px;font-weight:500; }
        .srv-modal-btns { display:flex;gap:10px; }
        .srv-modal-btns button { flex:1;padding:12px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;border:none;transition:opacity .15s; }
        .srv-modal-cancel { background:var(--border);color:var(--text); }
        .srv-modal-confirm { color:#fff; }
        .srv-modal-confirm:disabled { opacity:.35;cursor:not-allowed; }
        .srv-overlay { position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px); }
        .srv-overlay-box { background:var(--card-bg);border-radius:20px;padding:36px 40px;max-width:380px;width:100%;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,.3); }
        .srv-spinner { width:48px;height:48px;border:4px solid var(--border);border-top-color:var(--primary);border-radius:50%;animation:srvSpin .8s linear infinite;margin:0 auto 20px; }
        @keyframes srvSpin { to{transform:rotate(360deg)} }
        .srv-step { display:flex;align-items:center;gap:10px;font-size:14px;padding:8px 0;border-bottom:1px solid var(--border); }
        .srv-step:last-child { border-bottom:none; }
        .srv-step-icon { width:22px;text-align:center;flex-shrink:0; }
        </style>
        <script>
        // ---- Terminal-Status ----
        var _tsTimers = {};
        function fetchTerminalStatus(tid, row) {
            fetch('/admin/terminals/status/' + encodeURIComponent(tid))
                .then(function(r){ return r.json(); })
                .then(function(data) {
                    if (data.error || !data.device) return;
                    var d = data.device;
                    var battEl  = row.querySelector('.ts-batt');
                    var wifiEl  = row.querySelector('.ts-wifi');
                    var sleepEl = row.querySelector('.ts-sleep');
                    if (battEl) battEl.textContent = '🔋 ' + (d.percent_charged != null ? Math.round(d.percent_charged) + '%' : '–');
                    if (wifiEl)  wifiEl.textContent = '📶 ' + (d.wifi_strength   != null ? d.wifi_strength + '%' : '–');
                    if (sleepEl) sleepEl.textContent = d.sleep_mode_enabled ? '😴 An' : '';
                })
                .catch(function(){});
        }

        // ---- Server-Stats ----
        function fmtUptime(s) {
            var d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60), sc = s%60;
            if (d>0) return d+'d '+h+'h '+m+'m';
            if (h>0) return h+'h '+m+'m '+sc+'s';
            return m+'m '+sc+'s';
        }
        function srvFetchStatus() {
            var wrap = document.getElementById('srv-systemctl-wrap');
            var el   = document.getElementById('srv-systemctl');
            if (!el) return;
            if (wrap) wrap.style.display = 'block';
            el.textContent = 'Wird geladen\u2026';
            fetch('/admin/server/systemctl-status')
                .then(function(r){ return r.json(); })
                .then(function(d){ el.textContent = d.output || '(keine Ausgabe)'; })
                .catch(function(){ el.textContent = 'Fehler beim Laden.'; });
        }

        // ---- Restart Modal ----
        function getCsrf() {
            var el = document.querySelector('[data-csrf]');
            return el ? el.getAttribute('data-csrf') : '';
        }
        function srvConfirmRestart(type) {
            var isDeskview = type === 'deskview';
            var modal = document.createElement('div');
            modal.className = 'srv-modal-bg';
            modal.innerHTML =
                '<div class="srv-modal">' +
                    '<div class="srv-modal-icon">' + (isDeskview ? '\u21BA' : '\u23FB') + '</div>' +
                    '<div class="srv-modal-title">' + (isDeskview ? 'DeskView neu starten?' : 'Linux neu starten?') + '</div>' +
                    '<div class="srv-modal-desc">' + (isDeskview
                        ? 'Der DeskView-Dienst wird neu gestartet.<br>Du wirst automatisch weitergeleitet sobald er wieder l\u00e4uft.'
                        : 'Der gesamte Linux-Server wird neu gestartet.<br>Alle Verbindungen werden getrennt. Dies dauert einige Minuten.') +
                    '</div>' +
                    '<label class="srv-modal-check">' +
                        '<input type="checkbox" id="srv-confirm-cb">' +
                        '<span>' + (isDeskview ? 'Ja, DeskView jetzt neu starten' : 'Ja, Linux-Server jetzt neu starten') + '</span>' +
                    '</label>' +
                    '<div class="srv-modal-btns">' +
                        '<button class="srv-modal-cancel">Abbrechen</button>' +
                        '<button class="srv-modal-confirm" id="srv-confirm-btn" disabled style="background:' + (isDeskview ? '#f59e0b' : '#dc2626') + ';">Neu starten</button>' +
                    '</div>' +
                '</div>';
            document.body.appendChild(modal);
            var cb  = modal.querySelector('#srv-confirm-cb');
            var btn = modal.querySelector('#srv-confirm-btn');
            cb.addEventListener('change', function() { btn.disabled = !cb.checked; });
            modal.querySelector('.srv-modal-cancel').addEventListener('click', function() { modal.remove(); });
            modal.addEventListener('click', function(e) { if (e.target === modal) modal.remove(); });
            btn.addEventListener('click', function() {
                modal.remove();
                isDeskview ? srvDoRestart() : srvDoReboot();
            });
        }

        function srvDoRestart() {
            var overlay = srvShowOverlay('DeskView wird neu gestartet\u2026', [
                { id:'s1', text:'Neustart-Befehl senden\u2026' },
                { id:'s2', text:'Server startet neu\u2026' },
                { id:'s3', text:'Warte bis DeskView wieder l\u00e4uft\u2026' },
                { id:'s4', text:'Weiterleitung\u2026' }
            ]);
            fetch('/admin/server/restart', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'_csrf='+encodeURIComponent(getCsrf()) })
                .then(function(r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    srvStepDone(overlay, 's1');
                    srvStepActive(overlay, 's2');
                    // 4 Sekunden warten damit systemctl Zeit hat den Prozess zu stoppen
                    setTimeout(function() {
                        srvStepDone(overlay, 's2');
                        srvStepActive(overlay, 's3');
                        var tries = 0;
                        function poll() {
                            fetch('/admin/server/stats', { cache: 'no-store' })
                                .then(function(r) {
                                    if (r.ok) {
                                        srvStepDone(overlay, 's3');
                                        srvStepActive(overlay, 's4');
                                        setTimeout(function() { window.location.href = '/admin'; }, 1000);
                                    } else {
                                        if (++tries < 60) setTimeout(poll, 2000);
                                    }
                                })
                                .catch(function() {
                                    if (++tries < 60) setTimeout(poll, 2000);
                                });
                        }
                        poll();
                    }, 4000);
                })
                .catch(function() {
                    overlay.querySelector('.srv-overlay-box').innerHTML += '<p style="color:#dc2626;margin-top:16px;font-size:13px;">Fehler beim Senden des Befehls.</p>';
                });
        }

        function srvDoReboot() {
            var overlay = srvShowOverlay('Linux-Server wird neu gestartet\u2026', [
                { id:'r1', text:'Neustart-Befehl wird gesendet\u2026' },
                { id:'r2', text:'Server f\u00e4hrt herunter\u2026' },
                { id:'r3', text:'Bitte warte \u2014 dauert ca. 1\u20132 Minuten' }
            ]);
            fetch('/admin/server/reboot', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'_csrf='+encodeURIComponent(getCsrf()) })
                .then(function() {
                    srvStepDone(overlay, 'r1');
                    srvStepActive(overlay, 'r2');
                    setTimeout(function() { srvStepDone(overlay, 'r2'); srvStepActive(overlay, 'r3'); }, 3000);
                })
                .catch(function() {
                    overlay.querySelector('.srv-overlay-box').innerHTML += '<p style="color:#dc2626;margin-top:16px;font-size:13px;">Fehler beim Senden des Befehls.</p>';
                });
        }

        function srvShowOverlay(title, steps) {
            var overlay = document.createElement('div');
            overlay.className = 'srv-overlay';
            var stepsHtml = steps.map(function(s) {
                return '<div class="srv-step" id="ovl-'+s.id+'"><span class="srv-step-icon">⏳</span><span>'+s.text+'</span></div>';
            }).join('');
            overlay.innerHTML =
                '<div class="srv-overlay-box">' +
                    '<div class="srv-spinner"></div>' +
                    '<div style="font-size:17px;font-weight:700;margin-bottom:20px;">'+title+'</div>' +
                    '<div style="text-align:left;">'+stepsHtml+'</div>' +
                '</div>';
            document.body.appendChild(overlay);
            // Ersten Schritt sofort aktiv
            srvStepActive(overlay, steps[0].id);
            return overlay;
        }
        function srvStepDone(overlay, id) {
            var el = overlay.querySelector('#ovl-'+id+' .srv-step-icon');
            if (el) el.textContent = '✅';
        }
        function srvStepActive(overlay, id) {
            var el = overlay.querySelector('#ovl-'+id+' .srv-step-icon');
            if (el) el.textContent = '⏳';
        }

        function srvApply(d) {
            function el(id) { return document.getElementById(id); }
            function set(id, val) { var e = el(id); if (e) e.textContent = val; }
            var cpuBar = el('srv-cpu-bar'), ramBar = el('srv-ram-bar');
            set('srv-cpu',       d.cpu + '%');
            set('srv-cpu-cores', d.cpuCores);
            set('srv-load',      d.load1 + ' / ' + d.load5 + ' / ' + d.load15 + ' (1/5/15 min)');
            set('srv-ram',       d.ramPct + '%');
            set('srv-ram-detail',d.ramUsed + ' MB / ' + d.ramTotal + ' MB');
            set('srv-uptime',    fmtUptime(d.uptime));
            set('srv-sys-uptime',fmtUptime(d.sysUptime));
            set('srv-heap',      d.heapUsed + ' / ' + d.heapTotal + ' MB');
            set('srv-rss',       d.rss + ' MB');
            set('srv-node',      d.nodeVer);
            set('srv-host',      d.hostname);
            set('srv-platform',  d.platform);
            set('srv-ip',        (d.ips && d.ips.length) ? d.ips.join(', ') : '–');
            if (cpuBar) { cpuBar.style.width = d.cpu+'%'; cpuBar.style.background = d.cpu>80?'#dc2626':d.cpu>50?'#f59e0b':'#2563eb'; }
            if (ramBar) { ramBar.style.width = d.ramPct+'%'; ramBar.style.background = d.ramPct>85?'#dc2626':d.ramPct>60?'#f59e0b':'#059669'; }
            var logEl = el('srv-log');
            if (logEl && d.logs) {
                var atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 10;
                logEl.textContent = d.logs.map(function(l){
                    return '['+new Date(l.t).toLocaleTimeString('de-DE')+'] ['+l.level.toUpperCase()+'] '+l.msg;
                }).join('\n');
                if (atBottom) logEl.scrollTop = logEl.scrollHeight;
            }
            var ageEl = el('srv-log-age');
            if (ageEl) ageEl.textContent = new Date().toLocaleTimeString('de-DE');
        }
        var _srvTimer = null;
        function srvFetch() {
            fetch('/admin/server/stats', { cache: 'no-store' })
                .then(function(r) {
                    if (r.ok) return r.json();
                    return Promise.reject('HTTP ' + r.status + (r.redirected ? ' (redirect \u2013 Sitzung abgelaufen?)' : ''));
                })
                .then(function(d) {
                    var logEl = document.getElementById('srv-log');
                    if (logEl) logEl.style.color = '';
                    srvApply(d);
                })
                .catch(function(reason) {
                    var logEl = document.getElementById('srv-log');
                    if (!logEl) return;
                    var msg = (typeof reason === 'string') ? reason : (reason && reason.message ? reason.message : String(reason));
                    logEl.textContent = 'Fehler beim Laden der Statistiken: ' + msg;
                    logEl.style.color = '#dc2626';
                });
        }
        function srvStartPolling() {
            if (_srvTimer) return;
            srvFetch();
            _srvTimer = setInterval(srvFetch, 10000);
        }
        function srvStopPolling() {
            if (_srvTimer) { clearInterval(_srvTimer); _srvTimer = null; }
        }

        (function() {
            document.querySelectorAll('.term-live-row').forEach(function(row) {
                var tid = row.getAttribute('data-tid');
                if (!tid) return;
                fetchTerminalStatus(tid, row);
                var ms = parseInt(row.getAttribute('data-interval') || '30', 10) * 60 * 1000;
                if (_tsTimers[tid]) clearInterval(_tsTimers[tid]);
                _tsTimers[tid] = setInterval(function() { fetchTerminalStatus(tid, row); }, ms);
            });
            var logEl = document.getElementById('srv-log');
            if (logEl) { logEl.textContent = 'Laden\u2026'; logEl.style.color = ''; }
            srvStartPolling();
        })();

        document.addEventListener('visibilitychange', function() {
            if (document.hidden) { srvStopPolling(); } else { srvStartPolling(); }
        });
        </script>
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

                            <label>TRMNL Terminal <span style="font-weight:400;opacity:.6;">(optional)</span></label>
                            <select name="terminalId">
                                <option value="">– Kein Terminal –</option>
                                ${Object.values(terminals).map(t => `<option value="${escapeHtml(t.id)}" ${room.terminalId === t.id ? 'selected' : ''}>${escapeHtml(t.name)}</option>`).join('')}
                            </select>

                            <button type="submit">Raum speichern</button>
                        </form>
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
        const tid = String(req.body.terminalId || '').trim();
        room.terminalId = tid && terminals[tid] ? tid : null;


        saveRooms();
        return res.redirect('/admin/rooms');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Raum konnte nicht aktualisiert werden');
    }
});

app.post('/admin/test-trmnl-push', requireAdmin, requirePermission('terminals.edit'), requireCsrf, async (req, res) => {
    const terminalId = String(req.body.terminalId || '').trim();
    const terminal = getTerminal(terminalId);
    if (!terminal) return res.status(404).json({ error: 'Terminal nicht gefunden' });
    if (terminal.trmnlMode !== 'webhook' || !terminal.trmnlWebhookUrl) return res.json({ error: 'Kein Webhook konfiguriert' });

    const assignedRoom = Object.values(rooms).find(r => r.terminalId === terminalId);
    const payload = assignedRoom ? renderRoomApiJson(assignedRoom) : { abteilung: 'Test', roomnumber: '-', seats: [] };

    try {
        const r = await fetch(terminal.trmnlWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ merge_variables: payload })
        });
        const text = await r.text();
        return res.json({ results: [{ type: 'Webhook', status: r.status, body: text.slice(0, 300) }], payload });
    } catch (err) {
        return res.json({ results: [{ type: 'Webhook', error: err.message }], payload });
    }
});

app.post('/admin/device-status', requireAdmin, requirePermission('terminals.view'), requireCsrf, async (req, res) => {
    const terminalId = String(req.body.terminalId || '').trim();
    const terminal = getTerminal(terminalId);
    if (!terminal) return res.status(404).json({ error: 'Terminal nicht gefunden' });
    if (!terminal.trmnlDeviceApiKey || !terminal.trmnlDeviceMac) return res.status(400).json({ error: 'Account API Key und MAC-Adresse fehlen' });

    try {
        const headers = { 'Authorization': `Bearer ${decryptValue(terminal.trmnlDeviceApiKey)}`, 'Content-Type': 'application/json' };
        const listRes = await fetch('https://usetrmnl.com/api/devices', { headers });
        if (!listRes.ok) return res.json({ error: `TRMNL Fehler: ${listRes.status}` });

        const list = await listRes.json();
        const devices = list.data || list.devices || list;
        const device = Array.isArray(devices)
            ? devices.find(d => (d.mac_address || '').toUpperCase() === terminal.trmnlDeviceMac.toUpperCase())
            : null;

        if (!device) return res.json({ error: `Gerät mit MAC ${terminal.trmnlDeviceMac} nicht gefunden` });
        return res.json({ device });
    } catch (err) {
        return res.json({ error: err.message });
    }
});

// GET endpoint for live status — used by dashboard widget + terminals page auto-refresh
app.get('/admin/terminals/status/:terminalId', requireAdmin, requirePermission('terminals.view'), async (req, res) => {
    const terminalId = String(req.params.terminalId || '').trim();
    const terminal = getTerminal(terminalId);
    if (!terminal) return res.status(404).json({ error: 'Terminal nicht gefunden' });
    if (!terminal.trmnlDeviceApiKey || !terminal.trmnlDeviceMac) return res.status(400).json({ error: 'Kein API Key / MAC konfiguriert' });
    try {
        const headers = { 'Authorization': `Bearer ${decryptValue(terminal.trmnlDeviceApiKey)}`, 'Content-Type': 'application/json' };
        const listRes = await fetch('https://usetrmnl.com/api/devices', { headers });
        if (!listRes.ok) return res.json({ error: `TRMNL Fehler: ${listRes.status}` });
        const list = await listRes.json();
        const devices = list.data || list.devices || list;
        const device = Array.isArray(devices)
            ? devices.find(d => (d.mac_address || '').toUpperCase() === terminal.trmnlDeviceMac.toUpperCase())
            : null;
        if (!device) return res.json({ error: 'Gerät nicht gefunden' });
        return res.json({ device });
    } catch (err) {
        return res.json({ error: err.message });
    }
});

app.get('/admin/server/stats', requireAdmin, requirePermission('server.view'), (req, res) => {
    res.json({
        ...getServerStats(),
        logs: _logBuffer.slice(-80).reverse()
    });
});


app.get('/admin/server/systemctl-status', requireAdmin, requirePermission('server.view'), (req, res) => {
    exec('sudo systemctl status komvera-deskview --no-pager -l', { timeout: 5000 }, (err, stdout, stderr) => {
        res.json({ output: (stdout || '') + (stderr || '') });
    });
});

app.post('/admin/server/restart', requireAdmin, requirePermission('server.restart'), requireCsrf, (req, res) => {
    const admin = getCurrentAdmin(req);
    console.log(`[Server] DeskView-Neustart angefordert von Admin: ${admin?.username || '?'}`);
    res.json({ ok: true });
    exec('sudo systemctl restart komvera-deskview', (err) => {
        if (err) {
            console.warn('[Server] systemctl restart fehlgeschlagen, fallback process.exit');
            setTimeout(() => process.exit(0), 200);
        }
    });
});

app.post('/admin/server/reboot', requireAdmin, requirePermission('server.reboot'), requireCsrf, (req, res) => {
    const admin = getCurrentAdmin(req);
    console.log(`[Server] Linux-Reboot angefordert von Admin: ${admin?.username || '?'}`);
    res.json({ ok: true });
    setTimeout(() => exec('sudo reboot'), 500);
});

app.post('/admin/save-sleep-schedule', requireAdmin, requirePermission('terminals.edit'), requireCsrf, async (req, res) => {
    const terminalId = String(req.body.terminalId || '').trim();
    const terminal = getTerminal(terminalId);
    if (!terminal) return res.status(404).json({ error: 'Terminal nicht gefunden' });
    if (!terminal.trmnlDeviceApiKey || !terminal.trmnlDeviceMac) return res.status(400).json({ error: 'Account API Key und MAC-Adresse fehlen' });

    try {
        const headers = {
            'Authorization': `Bearer ${decryptValue(terminal.trmnlDeviceApiKey)}`,
            'Content-Type': 'application/json'
        };

        const listRes = await fetch('https://usetrmnl.com/api/devices', { headers });
        if (!listRes.ok) {
            const errText = await listRes.text();
            return res.json({ error: `TRMNL Fehler: ${listRes.status}`, body: errText.slice(0, 200) });
        }

        const list = await listRes.json();
        const devices = list.data || list.devices || list;
        const device = Array.isArray(devices)
            ? devices.find(d => (d.mac_address || '').toUpperCase() === terminal.trmnlDeviceMac.toUpperCase())
            : null;

        if (!device) return res.json({ error: `Gerät mit MAC ${terminal.trmnlDeviceMac} nicht gefunden`, all_devices: Array.isArray(devices) ? devices.map(d => d.mac_address) : devices });

        // Zeiten direkt aus Request lesen und in Terminal speichern
        const toMinutes = t => { const [h, m] = (t || '00:00').split(':').map(Number); return h * 60 + m; };
        const sleepStart = String(req.body.trmnlSleepStart || terminal.trmnlSleepStart || '19:00').trim();
        const sleepEnd   = String(req.body.trmnlSleepEnd   || terminal.trmnlSleepEnd   || '07:00').trim();
        terminal.trmnlSleepStart = sleepStart;
        terminal.trmnlSleepEnd   = sleepEnd;
        saveTerminals();

        const patchBody = {
            device: {
                sleep_mode_enabled: true,
                sleep_start_time: toMinutes(sleepStart),
                sleep_end_time:   toMinutes(sleepEnd)
            }
        };

        const patchRes = await fetch(`https://usetrmnl.com/api/devices/${device.id}`, {
            method: 'PATCH',
            headers,
            body: JSON.stringify(patchBody)
        });

        const text = await patchRes.text();
        let body;
        try { body = JSON.parse(text); } catch(e) { body = text; }
        return res.json({ status: patchRes.status, body, device_id: device.id, sent: patchBody.device });
    } catch (err) {
        return res.json({ error: err.message });
    }
});

/*
==================================================
TERMINALS ADMIN
==================================================
*/
app.get('/admin/terminals', requireAdmin, requirePermission('terminals.view'), (req, res) => {
    const terminalList = Object.values(terminals);

    const cards = terminalList.map(t => {
        const assignedRooms = Object.values(rooms).filter(r => r.terminalId === t.id);
        const assignedText = assignedRooms.length > 0
            ? 'Zugewiesen: ' + assignedRooms.map(r => escapeHtml(r.abteilung)).join(', ')
            : 'Keinem Raum zugewiesen';

        const modeColor = t.trmnlMode === 'webhook' ? '#059669' : t.trmnlMode === 'polling' ? '#6366f1' : '#6b7280';

        return `
        <div class="card" style="margin-bottom:12px;padding:0;overflow:hidden;">
            <div onclick="toggleTerminal('${escapeHtml(t.id)}')" style="display:flex;justify-content:space-between;align-items:center;padding:14px 18px;cursor:pointer;user-select:none;">
                <div style="display:flex;align-items:center;gap:12px;">
                    <span id="termArrow_${escapeHtml(t.id)}" style="font-size:12px;opacity:.5;transition:transform .2s;">▶</span>
                    <div>
                        <div style="font-size:15px;font-weight:600;">${escapeHtml(t.name)}</div>
                        <div style="font-size:12px;opacity:.5;margin-top:2px;">${assignedText}</div>
                        ${(t.trmnlDeviceApiKey && t.trmnlDeviceMac) ? `<div id="termHeaderStatus_${escapeHtml(t.id)}" style="font-size:11px;opacity:.55;margin-top:3px;"></div>` : ''}
                    </div>
                </div>
                <span style="font-size:11px;padding:3px 10px;border-radius:999px;background:${modeColor}20;color:${modeColor};font-weight:600;">${escapeHtml(t.trmnlMode || 'none')}</span>
            </div>
            <div id="termBody_${escapeHtml(t.id)}" style="display:none;padding:0 18px 18px 18px;border-top:1px solid var(--border);">

            ${hasPermission(req, 'terminals.edit') ? `
            <form method="POST" action="/admin/terminals/update">
                ${csrfField(req)}
                <input type="hidden" name="terminalId" value="${escapeHtml(t.id)}">

                <label>Name</label>
                <input type="text" name="name" value="${escapeHtml(t.name)}" required>

                <label>Modus</label>
                <select name="trmnlMode" id="trmnlMode_${escapeHtml(t.id)}" onchange="trmnlModeChange('${escapeHtml(t.id)}')">
                    <option value="none"    ${(t.trmnlMode||'none')==='none'    ? 'selected' : ''}>Kein TRMNL</option>
                    <option value="polling" ${(t.trmnlMode||'none')==='polling' ? 'selected' : ''}>Polling (TRMNL zieht Daten selbst)</option>
                    <option value="webhook" ${(t.trmnlMode||'none')==='webhook' ? 'selected' : ''}>Webhook / Push</option>
                </select>

                <div id="trmnl_polling_${escapeHtml(t.id)}" style="display:${(t.trmnlMode||'none')==='polling' ? 'block' : 'none'}">
                    <p style="font-size:13px;opacity:.7;margin-bottom:8px;">TRMNL fragt die Daten selbst ab. Kein Push von DeskView nötig — Intervall direkt in TRMNL einstellen.</p>
                </div>

                <div id="trmnl_webhook_${escapeHtml(t.id)}" style="display:${(t.trmnlMode||'none')==='webhook' ? 'block' : 'none'}">
                    <p style="font-size:13px;opacity:.7;margin-bottom:8px;">Bei jeder Änderung werden die Daten an TRMNL gesendet. Das Gerät zeigt die Änderung beim nächsten Poll-Zyklus an.</p>
                    <label>Webhook URL <span style="font-weight:400;opacity:.6;">(aus TRMNL Plugin → Webhook-Strategie)</span></label>
                    <input type="text" name="trmnlWebhookUrl" value="${escapeHtml(t.trmnlWebhookUrl || '')}" placeholder="https://usetrmnl.com/api/custom_plugins/...">
                </div>

                <hr style="margin:20px 0;border:none;border-top:1px solid var(--border);">
                <h3 style="font-size:15px;margin:0 0 10px 0;">Gerät <span style="font-weight:400;opacity:.6;font-size:13px;">(für Sleep Schedule &amp; Status)</span></h3>

                <label>TRMNL Account API Key <span style="font-weight:400;opacity:.6;">(Account → Settings → API Key)</span></label>
                <div class="field-wrap">
                    <input type="password" id="trmnlApiKey_${escapeHtml(t.id)}" name="trmnlDeviceApiKey" value="${escapeHtml(decryptValue(t.trmnlDeviceApiKey) || '')}" placeholder="Account API Key" autocomplete="off">
                    <button type="button" class="eye-btn" data-eye="trmnlApiKey_${escapeHtml(t.id)}" onclick="toggleVis('trmnlApiKey_${escapeHtml(t.id)}')">&#128065;</button>
                </div>

                <label>Device MAC-Adresse</label>
                <div class="field-wrap">
                    <input type="password" id="trmnlMac_${escapeHtml(t.id)}" name="trmnlDeviceMac" value="${escapeHtml(t.trmnlDeviceMac || '')}" placeholder="z. B. 08:92:72:65:F8:9C" autocomplete="off">
                    <button type="button" class="eye-btn" data-eye="trmnlMac_${escapeHtml(t.id)}" onclick="toggleVis('trmnlMac_${escapeHtml(t.id)}')">&#128065;</button>
                </div>

                <label>Status Aktualisierungsintervall</label>
                <select name="statusRefreshInterval">
                    ${[15,30,45,60,120,240,480].map(v=>`<option value="${v}" ${(t.statusRefreshInterval||30)===v?'selected':''}>${v<60?v+' Min':v/60+(v/60===1?' Std':' Std')}</option>`).join('')}
                </select>

                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px;">
                    <button type="submit">Terminal speichern</button>
                    <button type="button" onclick="syncTerminalName('${escapeHtml(t.id)}')" style="background:#6366f1;">↻ Name aus TRMNL</button>
                </div>
            </form>

            <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
                <form id="trmnlTestForm_${escapeHtml(t.id)}" class="dev-only" style="margin:0;">
                    <input type="hidden" name="_csrf" value="${getCsrfToken(req)}">
                    <input type="hidden" name="terminalId" value="${escapeHtml(t.id)}">
                    <button type="button" onclick="testTrmnlPushT('${escapeHtml(t.id)}')" style="background:#6b7280;">Push testen</button>
                </form>
                <form id="trmnlStatusForm_${escapeHtml(t.id)}" style="margin:0;">
                    <input type="hidden" name="_csrf" value="${getCsrfToken(req)}">
                    <input type="hidden" name="terminalId" value="${escapeHtml(t.id)}">
                    <button type="button" onclick="loadDeviceStatusT('${escapeHtml(t.id)}')" style="background:#6366f1;">Gerätestatus</button>
                </form>
            </div>
            <div id="trmnlDeviceStatus_${escapeHtml(t.id)}" style="display:none;margin-top:10px;background:#1e1e2e;color:#cdd6f4;padding:12px;border-radius:8px;font-size:13px;line-height:1.8;"></div>
            <pre id="trmnlTestResult_${escapeHtml(t.id)}" class="dev-only" style="display:none;margin-top:8px;background:#111;color:#0f0;padding:10px;border-radius:6px;font-size:12px;overflow:auto;max-height:200px;"></pre>

            <div style="margin-top:16px;padding:14px;border:1px solid var(--border);border-radius:8px;">
                <h4 style="margin:0 0 10px 0;font-size:14px;">😴 Sleep Schedule</h4>
                <form id="trmnlSleepForm_${escapeHtml(t.id)}" style="margin:0;">
                    <input type="hidden" name="_csrf" value="${getCsrfToken(req)}">
                    <input type="hidden" name="terminalId" value="${escapeHtml(t.id)}">
                    <div style="display:flex;gap:16px;margin-bottom:10px;">
                        <div style="flex:1;">
                            <label style="font-size:13px;">Aktiv ab (Morgens)</label>
                            <input type="time" name="trmnlSleepEnd" value="${escapeHtml(t.trmnlSleepEnd || '07:00')}">
                        </div>
                        <div style="flex:1;">
                            <label style="font-size:13px;">Schlafen ab (Abends)</label>
                            <input type="time" name="trmnlSleepStart" value="${escapeHtml(t.trmnlSleepStart || '19:00')}">
                        </div>
                    </div>
                    <button type="button" onclick="saveSleepScheduleT('${escapeHtml(t.id)}')" style="background:#059669;">Sleep Schedule speichern</button>
                    <span id="trmnlSleepStatus_${escapeHtml(t.id)}" style="display:none;font-size:13px;margin-left:10px;"></span>
                </form>
            </div>
            ` : ''}

            ${hasPermission(req, 'terminals.delete') ? `
            <form method="POST" action="/admin/terminals/delete" style="margin-top:16px;" onsubmit="return confirm('Terminal wirklich löschen?')">
                ${csrfField(req)}
                <input type="hidden" name="terminalId" value="${escapeHtml(t.id)}">
                <button type="submit" class="btn-danger">Terminal löschen</button>
            </form>
            ` : ''}
            </div><!-- /termBody -->
        </div>`;
    }).join('');

    const createForm = hasPermission(req, 'terminals.create') ? `
    <div class="card" style="margin-bottom:20px;">
        <h2 style="margin:0 0 16px 0;font-size:16px;">Neues Terminal anlegen</h2>
        <form method="POST" action="/admin/terminals/create">
            ${csrfField(req)}
            <label>Name <span style="font-weight:400;opacity:.6;">(z. B. "Demo 1" oder "Raum 201")</span></label>
            <input type="text" name="name" required placeholder="Terminal Name">
            <button type="submit">Terminal erstellen</button>
        </form>
    </div>` : '';

    const content = `
    <div class="topbar"><h1>Terminals</h1></div>
    ${createForm}
    ${cards || '<div class="card"><p style="opacity:.6;">Noch keine Terminals vorhanden.</p></div>'}
    <script>
        function toggleTerminal(tid) {
            var body  = document.getElementById('termBody_' + tid);
            var arrow = document.getElementById('termArrow_' + tid);
            if (!body) return;
            var open = body.style.display === 'none' || body.style.display === '';
            body.style.display  = open ? 'block' : 'none';
            if (arrow) arrow.style.transform = open ? 'rotate(90deg)' : '';
        }
        function trmnlModeChange(tid) {
            var sel = document.getElementById('trmnlMode_' + tid);
            if (!sel) return;
            var mode = sel.value;
            var pollingEl = document.getElementById('trmnl_polling_' + tid);
            var webhookEl = document.getElementById('trmnl_webhook_' + tid);
            if (pollingEl) pollingEl.style.display = mode === 'polling' ? 'block' : 'none';
            if (webhookEl) webhookEl.style.display = mode === 'webhook' ? 'block' : 'none';
        }
        async function syncTerminalName(tid) {
            var formEl = document.querySelector('input[value="' + tid + '"][name="terminalId"]');
            if (!formEl) return;
            var card = formEl.closest('.card');
            var nameEl = card ? card.querySelector('input[name="name"]') : null;
            var csrf = card ? card.querySelector('input[name="_csrf"]') : null;
            if (!nameEl) { alert('Bitte erst API Key und MAC speichern.'); return; }
            var fd = new FormData();
            fd.append('_csrf', csrf ? csrf.value : '');
            fd.append('terminalId', tid);
            var r = await fetch('/admin/terminals/sync-name', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(fd).toString() });
            var data; try { data = JSON.parse(await r.text()); } catch(e) { alert('Fehler'); return; }
            if (data.error) { alert('Fehler: ' + data.error); return; }
            if (data.name) { nameEl.value = data.name; alert('Name synchronisiert: ' + data.name); }
        }
        async function saveSleepScheduleT(tid) {
            var statusEl = document.getElementById('trmnlSleepStatus_' + tid);
            var form = document.getElementById('trmnlSleepForm_' + tid);
            if (statusEl) { statusEl.style.display='block'; statusEl.textContent='Speichere...'; statusEl.style.color=''; }
            try {
                var r = await fetch('/admin/save-sleep-schedule', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(new FormData(form)).toString() });
                var data; try { data = JSON.parse(await r.text()); } catch(e) { data = {}; }
                var ok = !data.error && (data.status === 200 || data.status === 204);
                if (statusEl) { statusEl.textContent = ok ? '✅ Gespeichert' : '❌ ' + (data.error||'Fehler'); statusEl.style.color = ok ? '#059669' : '#dc2626'; }
                if (window._devMode) { var pre = document.getElementById('trmnlTestResult_'+tid); if(pre){pre.style.display='block';pre.textContent=JSON.stringify(data,null,2);} }
            } catch(e) { if(statusEl){statusEl.textContent='❌ '+e.message;statusEl.style.color='#dc2626';} }
        }
        async function testTrmnlPushT(tid) {
            var resultEl = document.getElementById('trmnlTestResult_' + tid);
            var form = document.getElementById('trmnlTestForm_' + tid);
            if (resultEl) { resultEl.style.display='block'; resultEl.textContent='Teste Push...'; }
            try {
                var r = await fetch('/admin/test-trmnl-push', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(new FormData(form)).toString() });
                var data; try { data = JSON.parse(await r.text()); } catch(e) { data = await r.text(); }
                if (resultEl) resultEl.textContent = typeof data==='string' ? data : JSON.stringify(data,null,2);
            } catch(e) { if(resultEl) resultEl.textContent='Fehler: '+e.message; }
        }
        async function loadDeviceStatusT(tid) {
            var statusEl = document.getElementById('trmnlDeviceStatus_' + tid);
            var form = document.getElementById('trmnlStatusForm_' + tid);
            statusEl.style.display='block'; statusEl.innerHTML='Lade...';
            try {
                var r = await fetch('/admin/device-status', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(new FormData(form)).toString() });
                var data; try { data = JSON.parse(await r.text()); } catch(e) { statusEl.innerHTML='Fehler'; return; }
                if (data.error) { statusEl.innerHTML='❌ '+data.error; return; }
                var d = data.device;
                var battPct = d.percent_charged!=null ? Math.round(d.percent_charged)+'%' : '–';
                var battV   = d.battery_voltage!=null ? d.battery_voltage.toFixed(2)+' V' : '–';
                var rssi    = d.rssi!=null ? d.rssi+' dBm' : '–';
                var wifi    = d.wifi_strength!=null ? d.wifi_strength+'%' : '–';
                var sleep   = d.sleep_mode_enabled ? '✅ An' : '❌ Aus';
                var sleepT  = d.sleep_mode_enabled ? (mtt(d.sleep_start_time)+' – '+mtt(d.sleep_end_time)) : '–';
                statusEl.innerHTML = '<b>🔋 Akku:</b> '+battPct+' ('+battV+')<br><b>📶 WLAN:</b> '+wifi+' (RSSI: '+rssi+')<br><b>😴 Schlafmodus:</b> '+sleep+' '+sleepT;
            } catch(e) { statusEl.innerHTML='Fehler: '+e.message; }
        }
        function mtt(min) { if(min==null)return'–'; return String(Math.floor(min/60)).padStart(2,'0')+':'+String(min%60).padStart(2,'0'); }

        // --- Auto-Status für Terminal-Header ---
        var _pageStatusTimers = {};
        async function loadHeaderStatus(tid) {
            var el = document.getElementById('termHeaderStatus_' + tid);
            if (!el) return;
            try {
                var r = await fetch('/admin/terminals/status/' + encodeURIComponent(tid));
                var data = await r.json();
                if (data.error || !data.device) { el.textContent = ''; return; }
                var d = data.device;
                var parts = [];
                if (d.percent_charged != null) parts.push('🔋 ' + Math.round(d.percent_charged) + '%');
                if (d.wifi_strength != null)    parts.push('📶 ' + d.wifi_strength + '%');
                if (d.sleep_mode_enabled)       parts.push('😴 An');
                el.textContent = parts.join('  ');
            } catch(e) { el.textContent = ''; }
        }
        function setupTerminalAutoRefresh(tid, intervalMin) {
            loadHeaderStatus(tid);
            if (_pageStatusTimers[tid]) clearInterval(_pageStatusTimers[tid]);
            _pageStatusTimers[tid] = setInterval(function(){ loadHeaderStatus(tid); }, intervalMin * 60 * 1000);
        }
        document.addEventListener('DOMContentLoaded', function() {
            ${Object.values(terminals).filter(t => t.trmnlDeviceApiKey && t.trmnlDeviceMac).map(t =>
                `setupTerminalAutoRefresh('${escapeHtml(t.id)}', ${t.statusRefreshInterval || 30});`
            ).join('\n            ')}
        });
    </script>`;

    res.send(renderAdminLayout(req, 'Terminals', content));
});

app.post('/admin/terminals/create', requireAdmin, requirePermission('terminals.create'), requireCsrf, (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        if (!name) return res.status(400).send('Name fehlt');
        const id = 'terminal_' + Date.now();
        terminals[id] = { id, name, trmnlMode: 'none', trmnlWebhookUrl: '', trmnlDeviceApiKey: '', trmnlDeviceMac: '', trmnlSleepStart: '19:00', trmnlSleepEnd: '07:00', statusRefreshInterval: 30 };
        saveTerminals();
        return res.redirect('/admin/terminals');
    } catch (err) {
        return res.status(500).send('Fehler beim Erstellen');
    }
});

app.post('/admin/terminals/update', requireAdmin, requirePermission('terminals.edit'), requireCsrf, (req, res) => {
    try {
        const terminalId = String(req.body.terminalId || '').trim();
        const terminal = getTerminal(terminalId);
        if (!terminal) return res.status(404).send('Terminal nicht gefunden');
        terminal.name = String(req.body.name || '').trim() || terminal.name;
        terminal.trmnlMode = ['none','polling','webhook'].includes(req.body.trmnlMode) ? req.body.trmnlMode : 'none';
        terminal.trmnlWebhookUrl = String(req.body.trmnlWebhookUrl || '').trim();
        const rawApiKey = String(req.body.trmnlDeviceApiKey || '').trim();
        terminal.trmnlDeviceApiKey = rawApiKey ? encryptValue(rawApiKey) : (terminal.trmnlDeviceApiKey || '');
        terminal.trmnlDeviceMac = String(req.body.trmnlDeviceMac || '').trim();
        const ivl = parseInt(req.body.statusRefreshInterval, 10);
        terminal.statusRefreshInterval = [15, 30, 45, 60, 120, 240, 480].includes(ivl) ? ivl : 30;
        saveTerminals();
        return res.redirect('/admin/terminals');
    } catch (err) {
        return res.status(500).send('Fehler beim Speichern');
    }
});

app.post('/admin/terminals/delete', requireAdmin, requirePermission('terminals.delete'), requireCsrf, (req, res) => {
    try {
        const terminalId = String(req.body.terminalId || '').trim();
        if (!terminals[terminalId]) return res.status(404).send('Terminal nicht gefunden');
        delete terminals[terminalId];
        Object.values(rooms).forEach(r => { if (r.terminalId === terminalId) r.terminalId = null; });
        saveTerminals();
        saveRooms();
        return res.redirect('/admin/terminals');
    } catch (err) {
        return res.status(500).send('Fehler beim Löschen');
    }
});

app.post('/admin/terminals/sync-name', requireAdmin, requirePermission('terminals.edit'), requireCsrf, async (req, res) => {
    const terminalId = String(req.body.terminalId || '').trim();
    const terminal = getTerminal(terminalId);
    if (!terminal) return res.status(404).json({ error: 'Terminal nicht gefunden' });
    if (!terminal.trmnlDeviceApiKey || !terminal.trmnlDeviceMac) return res.status(400).json({ error: 'API Key und MAC fehlen' });
    try {
        const headers = { 'Authorization': `Bearer ${decryptValue(terminal.trmnlDeviceApiKey)}`, 'Content-Type': 'application/json' };
        const listRes = await fetch('https://usetrmnl.com/api/devices', { headers });
        if (!listRes.ok) return res.json({ error: `TRMNL Fehler: ${listRes.status}` });
        const list = await listRes.json();
        const devices = list.data || list.devices || list;
        const device = Array.isArray(devices)
            ? devices.find(d => (d.mac_address || '').toUpperCase() === terminal.trmnlDeviceMac.toUpperCase())
            : null;
        if (!device) return res.json({ error: 'Gerät nicht gefunden' });
        if (device.name) { terminal.name = device.name; saveTerminals(); }
        return res.json({ name: terminal.name });
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
        ${req.query.error ? `<div class="notice" style="border-color:#dc2626;color:#dc2626;margin-bottom:16px;">❌ ${escapeHtml(String(req.query.error))}</div>` : ''}

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

        ${(() => {
            const me = getCurrentAdmin(req);
            if (!me || !me.master) return '';
            const others = admins.filter(a => !a.master);
            if (others.length === 0) return '';
            return `
            <div class="card" style="border:2px solid #f59e0b;">
                <h2 style="color:#92400e;">⚠️ Master übertragen</h2>
                <p style="font-size:13px;opacity:.7;margin-bottom:16px;">
                    Überträgt den Master-Status an einen anderen Admin. Du wirst danach ein normaler Admin ohne Master-Rechte.
                    Diese Aktion kann nicht rückgängig gemacht werden.
                </p>
                <form method="POST" action="/admin/admins/transfer-master" onsubmit="return confirm('Master-Status wirklich übertragen? Du verlierst danach alle Master-Rechte.')">
                    ${csrfField(req)}
                    <label>Neuer Master</label>
                    <select name="targetUsername" required>
                        <option value="">– Admin auswählen –</option>
                        ${others.map(a => `<option value="${escapeHtml(a.username)}">${escapeHtml(a.displayName || a.username)} (@${escapeHtml(a.username)})</option>`).join('')}
                    </select>
                    <label>Dein Passwort zur Bestätigung</label>
                    <div class="field-wrap">
                        <input type="password" id="transfer_pw" name="password" required autocomplete="off">
                        <button type="button" class="eye-btn" data-eye="transfer_pw" onclick="toggleVis('transfer_pw')">&#128065;</button>
                    </div>
                    <button type="submit" style="background:#f59e0b;color:#000;">Master übertragen</button>
                </form>
            </div>`;
        })()}
    `;

    res.send(renderAdminLayout(req, 'Admins', content));
});

app.post('/admin/admins/transfer-master', requireAdmin, requireCsrf, async (req, res) => {
    try {
        const me = getCurrentAdmin(req);
        if (!me || !me.master) return res.status(403).send('Nur der Master kann den Master-Status übertragen.');

        const targetUsername = String(req.body.targetUsername || '').trim();
        const password = String(req.body.password || '');

        if (!targetUsername) return res.redirect('/admin/admins?error=Kein+Admin+ausgewählt');

        const passwordMatch = await bcrypt.compare(password, me.passwordHash);
        if (!passwordMatch) return res.redirect('/admin/admins?error=Falsches+Passwort');

        const target = admins.find(a => a.username === targetUsername);
        if (!target || target.master) return res.redirect('/admin/admins?error=Admin+nicht+gefunden');

        // Transfer
        me.master = false;
        target.master = true;
        target.permissions = [...AVAILABLE_PERMISSIONS]; // alle Rechte

        saveAdmins();
        return res.redirect('/admin/admins');
    } catch (err) {
        console.error(err);
        return res.status(500).send('Fehler beim Übertragen');
    }
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