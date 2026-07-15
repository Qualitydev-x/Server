const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

const PORT = process.env.PORT || 3000;
const BOT_SECRET = process.env.BOT_SECRET || "rainx-bot-secret";
const DATA_FILE = path.join(__dirname, "data.json");

// ====== IN-MEMORY STORE ======
let data = {
    keys: {}, // { keyId: { tier, active, expired, createdAt, expiresAt, usedBy, hwid, ip, lastHwidReset } }
    scripts: { NORMAL: "", ADMIN: "", ALLMAP: "" }
};

function loadData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
        }
        data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    } catch (e) {
        console.log("Data file error, using defaults");
    }
}

function saveData() {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

loadData();
setInterval(saveData, 10000);

// ====== HELPERS ======
function nowSec() { return Math.floor(Date.now() / 1000); }

function isExpired(key) {
    if (key.expiresAt === -1) return false;
    if (key.expired) return true;
    if (!key.expiresAt) return false;
    return nowSec() >= key.expiresAt;
}

function botAuth(req, res, next) {
    if (req.headers["x-bot-secret"] !== BOT_SECRET)
        return res.status(403).json({ ok: false, error: "forbidden" });
    next();
}

// ====== KEY ENDPOINTS ======
app.post("/key/generate", botAuth, (req, res) => {
    const { tier, days } = req.body;
    if (!["NORMAL", "ADMIN", "ALLMAP"].includes(tier)) return res.status(400).json({ ok: false });
    
    const keyId = crypto.randomBytes(16).toString("hex");
    const expiresAt = days === 0 ? -1 : nowSec() + (days * 86400);
    
    data.keys[keyId] = {
        tier, active: false, expired: false, createdAt: nowSec(),
        expiresAt, usedBy: null, hwid: "", ip: "", lastHwidReset: 0
    };
    saveData();
    
    res.json({ ok: true, key: keyId, tier, expiresAt });
});

app.get("/key/:keyId", botAuth, (req, res) => {
    const key = data.keys[req.params.keyId];
    if (!key) return res.status(404).json({ ok: false });
    res.json({ ok: true, key: req.params.keyId, ...key, expired: isExpired(key) });
});

app.delete("/key/:keyId", botAuth, (req, res) => {
    if (!data.keys[req.params.keyId]) return res.status(404).json({ ok: false });
    delete data.keys[req.params.keyId];
    saveData();
    res.json({ ok: true });
});

app.get("/keys", botAuth, (req, res) => {
    const keys = {};
    for (const [id, key] of Object.entries(data.keys)) {
        keys[id] = { ...key, expired: isExpired(key) };
    }
    res.json({ ok: true, keys });
});

// ====== CLIENT VERIFY ======
app.post("/verify", (req, res) => {
    const { key, hwid, ip, discordUserId } = req.body;
    if (!key || !hwid || !ip) return res.json({ ok: false, reason: "bad_request" });
    
    const keyData = data.keys[key];
    if (!keyData) return res.json({ ok: false, reason: "invalid_key" });
    if (isExpired(keyData)) return res.json({ ok: false, reason: "expired" });
    
    // First activation
    if (!keyData.usedBy) {
        keyData.usedBy = discordUserId || ("user_" + crypto.randomBytes(8).toString("hex"));
        keyData.hwid = hwid;
        keyData.ip = ip;
        keyData.active = true;
        saveData();
        return res.json({ ok: true, tier: keyData.tier });
    }
    
    // Check HWID+IP mismatch
    if (keyData.hwid !== hwid || keyData.ip !== ip) {
        return res.json({ ok: false, reason: "hwid_ip_mismatch" });
    }
    
    res.json({ ok: true, tier: keyData.tier });
});

// ====== GET KEY BY DISCORD USER ID ======
app.get("/key/user/:userId", botAuth, (req, res) => {
    const userId = req.params.userId;
    for (const [keyId, keyData] of Object.entries(data.keys)) {
        if (keyData.usedBy === userId) {
            return res.json({ ok: true, key: keyId, ...keyData, expired: isExpired(keyData) });
        }
    }
    res.status(404).json({ ok: false, error: "no_key_found" });
});

// ====== RESET IP ======
app.post("/reset-ip", (req, res) => {
    const { key, newIp } = req.body;
    if (!key || !newIp) return res.json({ ok: false });
    
    const keyData = data.keys[key];
    if (!keyData) return res.json({ ok: false });
    
    keyData.ip = newIp;
    saveData();
    res.json({ ok: true });
});

// ====== RESET HWID ======
app.post("/reset-hwid", (req, res) => {
    const { key, newHwid } = req.body;
    if (!key || !newHwid) return res.json({ ok: false });
    
    const keyData = data.keys[key];
    if (!keyData) return res.json({ ok: false });
    
    keyData.hwid = newHwid;
    keyData.lastHwidReset = nowSec();
    saveData();
    res.json({ ok: true });
});

// ====== SCRIPT ENDPOINTS ======
app.post("/script/update", botAuth, (req, res) => {
    const { tier, content } = req.body;
    if (!["NORMAL", "ADMIN", "ALLMAP"].includes(tier) || !content) return res.status(400).json({ ok: false });
    
    data.scripts[tier] = content;
    saveData();
    res.json({ ok: true, tier });
});

app.get("/script/:tier", (req, res) => {
    const { tier } = req.params;
    if (!["NORMAL", "ADMIN", "ALLMAP"].includes(tier)) return res.status(400).json({ ok: false });
    
    // tier hierarchy: ALLMAP >= ADMIN >= NORMAL
    const tierOrder = { NORMAL: 1, ADMIN: 2, ALLMAP: 3 };
    const tierLevel = tierOrder[tier];
    
    let script = "";
    // Return scripts at same level or below
    if (tier === "ALLMAP" && data.scripts.ALLMAP) script = data.scripts.ALLMAP;
    else if (tier === "ADMIN" && data.scripts.ADMIN) script = data.scripts.ADMIN;
    else if (data.scripts.NORMAL) script = data.scripts.NORMAL;
    
    if (!script) return res.status(404).json({ ok: false, error: "no_script" });
    
    res.setHeader("Content-Type", "text/plain");
    res.send(script);
});

app.get("/scripts", botAuth, (req, res) => {
    res.json({ ok: true, scripts: { NORMAL: !!data.scripts.NORMAL, ADMIN: !!data.scripts.ADMIN, ALLMAP: !!data.scripts.ALLMAP } });
});

app.get("/ping", (req, res) => res.send("pong"));
app.listen(PORT, () => console.log(`✅ Server V3 running on port ${PORT}`));
