// --- DOM Elements ---
const loginView = document.getElementById('login-view');
const configView = document.getElementById('config-view');
const successView = document.getElementById('success-view');

const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginBtn = document.getElementById('login-btn');
const loginError = document.getElementById('login-error');

const logoutBtn = document.getElementById('logout-btn');
const regionSelect = document.getElementById('region-select');
const dnsPreset = document.getElementById('dns-preset');
const customDnsGroup = document.getElementById('custom-dns-group');
const customDnsInput = document.getElementById('custom-dns');
const generateBtn = document.getElementById('generate-btn');
const genError = document.getElementById('gen-error');

const saveBtn = document.getElementById('save-btn');
const createAnotherBtn = document.getElementById('create-another-btn');
const saveStatus = document.getElementById('save-status');

// --- Global State ---
let authToken = null;
let currentRegions = [];
let generatedConfig = null;
let generatedRegionId = null;

// Initialize Neutralino
Neutralino.init();
Neutralino.events.on("windowClose", () => {
    Neutralino.app.exit();
});

// Load saved state on startup
Neutralino.events.on("ready", async () => {
    try {
        const savedUser = await Neutralino.storage.getData('username');
        if (savedUser) usernameInput.value = savedUser;
    } catch (e) { } // Ignore if keys don't exist yet

    try {
        const savedToken = await Neutralino.storage.getData('authToken');
        if (savedToken) {
            authToken = savedToken;
            switchView(configView);
            await loadRegions();

            // Load saved preferences
            try {
                const savedRegionIndex = await Neutralino.storage.getData('selectedRegionIndex');
                if (savedRegionIndex && regionSelect.options.length > savedRegionIndex) {
                    regionSelect.value = savedRegionIndex;
                    generateBtn.disabled = false;
                }
            } catch (e) { }

            try {
                const savedDnsPreset = await Neutralino.storage.getData('dnsPreset');
                if (savedDnsPreset) {
                    dnsPreset.value = savedDnsPreset;
                    if (savedDnsPreset === 'custom') {
                        customDnsGroup.classList.remove('hidden');
                        const savedCustomDns = await Neutralino.storage.getData('customDns');
                        if (savedCustomDns) customDnsInput.value = savedCustomDns;
                    }
                }
            } catch (e) { }
        }
    } catch (e) { }
});

// --- Utility Functions ---

// We use curl via CLI because standard fetch() is subject to CORS blocks from PIA servers.
async function curlRequest(url, method = 'GET', data = null) {
    let cmd = `curl -s -X ${method}`;
    if (data) {
        // Windows escaping logic for JSON curl payload
        const escapedJson = JSON.stringify(data).replace(/"/g, '\\"');
        cmd += ` -H "Content-Type: application/json" -d "${escapedJson}"`;
    }
    cmd += ` "${url}"`;

    try {
        const res = await Neutralino.os.execCommand(cmd);
        if (res.exitCode !== 0) throw new Error(res.stdErr || res.stdOut);
        return res.stdOut;
    } catch (err) {
        throw new Error('Network request failed: ' + err.message);
    }
}

function generateWireGuardKeys() {
    const privateKeyBytes = new Uint8Array(32);
    window.crypto.getRandomValues(privateKeyBytes);

    // WireGuard clamping
    privateKeyBytes[0] &= 248;
    privateKeyBytes[31] &= 127;
    privateKeyBytes[31] |= 64;

    const keyPair = nacl.box.keyPair.fromSecretKey(privateKeyBytes);

    return {
        privateKey: encodeBase64(keyPair.secretKey),
        publicKey: encodeBase64(keyPair.publicKey)
    };
}

function encodeBase64(uint8Array) {
    let binary = '';
    for (let i = 0; i < uint8Array.byteLength; i++) {
        binary += String.fromCharCode(uint8Array[i]);
    }
    return window.btoa(binary);
}

// --- Event Listeners ---

// 1. Login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const user = usernameInput.value.trim();
    const pass = passwordInput.value;

    if (!user || !pass) return;

    setLoading(loginBtn, true);
    hideError(loginError);

    try {
        const responseStr = await curlRequest('https://www.privateinternetaccess.com/api/client/v2/token', 'POST', { username: user, password: pass });
        const result = JSON.parse(responseStr);

        if (result.token) {
            authToken = result.token;

            // Save Token and Username
            try {
                await Neutralino.storage.setData('authToken', authToken);
                await Neutralino.storage.setData('username', user);
            } catch (e) { console.error("Could not save to storage", e); }

            switchView(configView);
            await loadRegions();
        } else {
            showError(loginError, 'Authentication failed. Please check your credentials.');
        }
    } catch (err) {
        showError(loginError, 'Auth error: ' + err.message);
    } finally {
        setLoading(loginBtn, false);
    }
});

// 2. Load API Regions
async function loadRegions() {
    regionSelect.disabled = true;
    regionSelect.innerHTML = '<option value="">Loading regions...</option>';
    hideError(genError);

    try {
        const rawResponse = await curlRequest('https://serverlist.piaservers.net/vpninfo/servers/v6');

        let jsonString = rawResponse;
        const lastBraceIdx = jsonString.lastIndexOf('}');
        if (lastBraceIdx >= 0) {
            jsonString = jsonString.substring(0, lastBraceIdx + 1);
        }

        const data = JSON.parse(jsonString);

        if (data && data.regions) {
            currentRegions = data.regions.filter(r => r.servers && r.servers.wg).sort((a, b) => a.name.localeCompare(b.name));
            regionSelect.innerHTML = '<option value="" disabled selected>Select a region...</option>';
            currentRegions.forEach((region, index) => {
                const option = document.createElement('option');
                option.value = index;
                option.textContent = `${region.name} (${region.id})`;
                regionSelect.appendChild(option);
            });
            regionSelect.disabled = false;
        }
    } catch (err) {
        regionSelect.innerHTML = '<option value="">Error loading regions</option>';
        showError(genError, 'Failed to fetch servers: ' + err.message);
    }
}

// 3. DNS Dropdown Toggle
dnsPreset.addEventListener('change', async () => {
    if (dnsPreset.value === 'custom') {
        customDnsGroup.classList.remove('hidden');
    } else {
        customDnsGroup.classList.add('hidden');
    }
    try { await Neutralino.storage.setData('dnsPreset', dnsPreset.value); } catch (e) { }
});

customDnsInput.addEventListener('change', async () => {
    try { await Neutralino.storage.setData('customDns', customDnsInput.value); } catch (e) { }
});

regionSelect.addEventListener('change', async () => {
    generateBtn.disabled = !regionSelect.value;
    if (regionSelect.value) {
        try { await Neutralino.storage.setData('selectedRegionIndex', regionSelect.value); } catch (e) { }
    }
});

// 4. Generate keys & config
generateBtn.addEventListener('click', async () => {
    if (!regionSelect.value || !authToken) return;

    const selectedRegion = currentRegions[regionSelect.value];

    let userDns = dnsPreset.value;
    if (userDns === 'custom') {
        userDns = customDnsInput.value.trim();
        if (!userDns) userDns = '1.1.1.1';
    }

    setLoading(generateBtn, true);
    hideError(genError);
    regionSelect.disabled = true;

    try {
        // 1. Generate Keys locally
        const keys = generateWireGuardKeys();

        if (!selectedRegion.servers || !selectedRegion.servers.wg || selectedRegion.servers.wg.length === 0) {
            throw new Error('No WireGuard servers available in this region.');
        }

        const serverObj = selectedRegion.servers.wg[Math.floor(Math.random() * selectedRegion.servers.wg.length)];
        const wgIp = serverObj.ip;
        const wgPort = 1337;

        // 2. Register via curl (ignoring SSL warnings via -k)
        const encodedPubKey = encodeURIComponent(keys.publicKey);
        const registerUrl = `https://${wgIp}:${wgPort}/addKey?pt=${authToken}&pubkey=${encodedPubKey}`;

        // We add -k to ignore untrusted PIA internal SSL certs
        const cmd = `curl -s -k -X GET "${registerUrl}"`;
        const res = await Neutralino.os.execCommand(cmd);

        const data = JSON.parse(res.stdOut);

        if (data.status === 'OK') {
            generatedConfig = `[Interface]
Address = ${data.peer_ip}/32
PrivateKey = ${keys.privateKey}
DNS = ${userDns}

[Peer]
PublicKey = ${data.server_key}
Endpoint = ${data.server_ip}:${data.server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25`;

            generatedRegionId = selectedRegion.id;
            switchView(successView);
            hideElement(saveStatus);
        } else {
            throw new Error(data.message || 'Key registration failed.');
        }
    } catch (err) {
        showError(genError, 'Generation failed: ' + err.message);
    } finally {
        setLoading(generateBtn, false);
        regionSelect.disabled = false;
    }
});

// 5. Save Config using Neutralino OS File Dialog
saveBtn.addEventListener('click', async () => {
    if (!generatedConfig) return;

    try {
        const filename = `PIA-${generatedRegionId}.conf`;
        const selectedPath = await Neutralino.os.showSaveDialog('Save WireGuard Configuration', {
            defaultPath: filename,
            filters: [{ name: 'WireGuard Config', extensions: ['conf'] }]
        });

        if (selectedPath) {
            await Neutralino.filesystem.writeFile(selectedPath, generatedConfig);
            showStatus(saveStatus, `Saved to: ${selectedPath}`, 'success');
        }
    } catch (err) {
        showStatus(saveStatus, `Failed to save: ${err.message}`, 'error');
    }
});

// 6. Resets
logoutBtn.addEventListener('click', async () => {
    authToken = null;
    passwordInput.value = '';

    // Clear Token from storage
    try {
        await Neutralino.storage.setData('authToken', '');
    } catch (e) { }

    switchView(loginView);
});

createAnotherBtn.addEventListener('click', () => {
    generatedConfig = null;
    switchView(configView);
});

// --- UI Helpers ---
function switchView(viewElement) {
    document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
    viewElement.classList.add('active');
}

function setLoading(btnElement, isLoading) {
    const text = btnElement.querySelector('.btn-text');
    const spinner = btnElement.querySelector('.spinner');

    if (isLoading) {
        btnElement.disabled = true;
        text.classList.add('hidden');
        spinner.classList.remove('hidden');
    } else {
        btnElement.disabled = false;
        text.classList.remove('hidden');
        spinner.classList.add('hidden');
    }
}

function showError(el, msg) { el.textContent = msg; el.classList.remove('hidden'); }
function hideError(el) { el.classList.add('hidden'); }
function showStatus(el, msg, type) { el.textContent = msg; el.className = `status-msg ${type}`; }
function hideElement(el) { el.classList.add('hidden'); }
