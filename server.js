const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-fixed-secret-key';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// ==================== DATA DIRECTORIES ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending.json');
const ordersFile = path.join(dataDir, 'orders.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));
if (!fs.existsSync(ordersFile)) fs.writeFileSync(ordersFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }
function readOrders() { return JSON.parse(fs.readFileSync(ordersFile)); }
function writeOrders(orders) { fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Halal Trading Bot - Fixed Version' });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
        const users = readUsers();
        if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
        const pending = readPending();
        if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
        const hashedPassword = bcrypt.hashSync(password, 10);
        pending[email] = { email, password: hashedPassword, requestedAt: new Date().toISOString(), status: 'pending' };
        writePending(pending);
        res.json({ success: true, message: 'Registration request sent to owner.' });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    try {
        const { email, password } = req.body;
        const users = readUsers();
        const user = users[email];
        if (!user) {
            const pending = readPending();
            if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
        if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
        const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, isOwner: user.isOwner || false });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email,
        password: pending[email].password,
        isOwner: false,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

// ==================== BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function getServerTime(useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    try {
        const response = await axios.get(`${baseUrl}/api/v3/time`, { timeout: 10000 });
        return response.data.serverTime;
    } catch (error) {
        return Date.now();
    }
}

function generateSignature(queryString, secret) {
    return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const timestamp = await getServerTime(useDemo);
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const sortedKeys = Object.keys(allParams).sort();
    const queryString = sortedKeys.map(k => `${k}=${allParams[k]}`).join('&');
    const signature = generateSignature(queryString, secretKey);
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({ method, url, headers: { 'X-MBX-APIKEY': apiKey }, timeout: 15000 });
    return response.data;
}

async function getSpotBalance(apiKey, secretKey, useDemo = false) {
    try {
        const accountData = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtBalance?.free || 0);
    } catch (error) {
        return 0;
    }
}

async function getCurrentPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`, { timeout: 10000 });
    return parseFloat(response.data.price);
}

async function placeMarketOrder(apiKey, secretKey, symbol, side, quantity, useDemo = false) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        side,
        type: 'MARKET',
        quantity: quantity.toFixed(6)
    }, 'POST', useDemo);
}

// ==================== SIMPLE AI - NEVER HOLDS ====================
async function getSimpleSignal(symbol, useDemo = false) {
    try {
        const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
        const ticker = await axios.get(`${baseUrl}/api/v3/ticker/24hr?symbol=${symbol}`, { timeout: 10000 });
        const priceChange = parseFloat(ticker.data.priceChangePercent);
        // If price dropped in last 24h -> BUY (dip), else SELL (pump)
        const action = priceChange < 0 ? 'BUY' : 'SELL';
        const confidence = 0.7;
        console.log(`🤖 SIMPLE AI: ${symbol} -> ${action} (24h change: ${priceChange}%)`);
        return { action, confidence, current: parseFloat(ticker.data.lastPrice) };
    } catch (error) {
        console.error('Signal error:', error.message);
        return { action: 'BUY', confidence: 0.6, current: 50000 };
    }
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    try {
        let { apiKey, secretKey, accountType } = req.body;
        if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
        const cleanApi = cleanKey(apiKey);
        const cleanSecret = cleanKey(secretKey);
        const useDemo = (accountType === 'testnet');
        const spotBalance = await getSpotBalance(cleanApi, cleanSecret, useDemo);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        const mode = useDemo ? 'Demo Trading' : 'Real Binance';
        res.json({
            success: true,
            message: `${mode} API keys saved! Spot: ${spotBalance} USDT`,
            spotBalance: spotBalance
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid API keys: ' + (error.response?.data?.msg || error.message) });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        const mode = useDemo ? 'Demo Trading' : 'Real Binance';
        res.json({
            success: true,
            spotBalance: spotBalance,
            totalBalance: spotBalance,
            message: `Connected to ${mode}! Balance: ${spotBalance} USDT`
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed. Check your API keys.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No keys set' });
    res.json({
        success: true,
        apiKey: decrypt(user.apiKey),
        secretKey: decrypt(user.secretKey)
    });
});

// ==================== TRADING ENGINE ====================
const activeSessions = {};
const openPositions = {};

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs, accountType } = req.body;
        if (initialInvestment < 3) return res.status(400).json({ success: false, message: 'Minimum investment is $3' });
        if (targetProfit < 3) return res.status(400).json({ success: false, message: 'Target profit must be at least $3' });
        if (!timeLimit || timeLimit < 0.1) return res.status(400).json({ success: false, message: 'Time limit must be at least 0.1 hours' });

        const users = readUsers();
        const user = users[req.user.email];
        if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add API keys first' });

        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');

        const balance = await getSpotBalance(apiKey, secretKey, useDemo);
        if (balance < initialInvestment) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have ${balance} USDT, need ${initialInvestment}` });
        }

        const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
        activeSessions[sessionId] = {
            isActive: true,
            currentProfit: 0,
            trades: [],
            winStreak: 0,
            initialInvestment,
            targetProfit,
            timeLimit,
            riskLevel,
            tradingPairs,
            startedAt: Date.now(),
            userEmail: req.user.email,
            apiKey, secretKey, useDemo
        };

        // Start trading interval (every 2 minutes)
        const interval = setInterval(async () => {
            const session = activeSessions[sessionId];
            if (!session || !session.isActive) {
                clearInterval(interval);
                return;
            }

            // Check time limit
            const elapsedHours = (Date.now() - session.startedAt) / (1000 * 60 * 60);
            if (elapsedHours >= session.timeLimit) {
                session.isActive = false;
                clearInterval(interval);
                console.log(`⏰ Time limit reached for ${session.userEmail}`);
                return;
            }
            // Check profit target
            if (session.currentProfit >= session.targetProfit) {
                session.isActive = false;
                clearInterval(interval);
                console.log(`🎯 Target reached for ${session.userEmail}`);
                return;
            }

            // Get any open position for this session
            const userPositions = openPositions[session.userEmail] || [];
            const openPos = userPositions.find(p => p.sessionId === sessionId);

            if (openPos) {
                // Close existing position
                console.log(`📉 Closing ${openPos.symbol} for ${session.userEmail}`);
                try {
                    const closeSide = openPos.side === 'BUY' ? 'SELL' : 'BUY';
                    const order = await placeMarketOrder(session.apiKey, session.secretKey, openPos.symbol, closeSide, openPos.quantity, session.useDemo);
                    const fillPrice = parseFloat(order.fills?.[0]?.price || 0);
                    let profit = 0;
                    if (openPos.side === 'BUY') {
                        profit = (fillPrice - openPos.entryPrice) * openPos.quantity;
                    } else {
                        profit = (openPos.entryPrice - fillPrice) * openPos.quantity;
                    }
                    session.currentProfit += profit;
                    session.winStreak = profit > 0 ? session.winStreak + 1 : 0;
                    session.trades.unshift({
                        symbol: openPos.symbol,
                        side: `${openPos.side} CLOSED`,
                        profit: profit.toFixed(2),
                        timestamp: new Date().toISOString()
                    });
                    // Save trade to file
                    const tradeFile = path.join(tradesDir, session.userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let allTrades = [];
                    if (fs.existsSync(tradeFile)) allTrades = JSON.parse(fs.readFileSync(tradeFile));
                    allTrades.unshift({
                        symbol: openPos.symbol,
                        side: openPos.side,
                        profit: profit,
                        timestamp: new Date().toISOString()
                    });
                    fs.writeFileSync(tradeFile, JSON.stringify(allTrades, null, 2));
                    // Remove position
                    openPositions[session.userEmail] = userPositions.filter(p => p.sessionId !== sessionId);
                    console.log(`✅ Closed with profit: $${profit.toFixed(2)}. Total profit: $${session.currentProfit.toFixed(2)}`);
                } catch (err) {
                    console.error('Close error:', err.message);
                }
            } else {
                // Open new position
                const currentBalance = await getSpotBalance(session.apiKey, session.secretKey, session.useDemo);
                let basePercent = 0.15;
                if (session.riskLevel === 'low') basePercent = 0.10;
                if (session.riskLevel === 'high') basePercent = 0.20;
                let positionSize = currentBalance * basePercent;
                if (positionSize < 3) positionSize = 3;
                if (currentBalance < positionSize + 5) {
                    console.log(`⚠️ Insufficient balance: ${currentBalance} USDT, need ${positionSize + 5}`);
                    return;
                }
                const symbol = session.tradingPairs[Math.floor(Math.random() * session.tradingPairs.length)];
                console.log(`🔍 Getting signal for ${symbol}...`);
                const signal = await getSimpleSignal(symbol, session.useDemo);
                const price = signal.current || await getCurrentPrice(symbol, session.useDemo);
                const quantity = positionSize / price;
                try {
                    console.log(`🚀 Opening ${signal.action} for ${symbol} with $${positionSize.toFixed(2)}`);
                    const order = await placeMarketOrder(session.apiKey, session.secretKey, symbol, signal.action, quantity, session.useDemo);
                    const fillPrice = parseFloat(order.fills?.[0]?.price || 0);
                    const executedQty = parseFloat(order.executedQty);
                    if (!openPositions[session.userEmail]) openPositions[session.userEmail] = [];
                    openPositions[session.userEmail].push({
                        sessionId: sessionId,
                        symbol: symbol,
                        side: signal.action,
                        quantity: executedQty,
                        entryPrice: fillPrice,
                        openedAt: new Date().toISOString()
                    });
                    session.trades.unshift({
                        symbol: symbol,
                        side: `${signal.action} OPEN`,
                        entryPrice: fillPrice.toFixed(2),
                        timestamp: new Date().toISOString()
                    });
                    console.log(`✅ Opened ${signal.action} at $${fillPrice}`);
                } catch (err) {
                    console.error('Open error:', err.message);
                }
            }
        }, 120000); // 2 minutes

        activeSessions[sessionId].interval = interval;
        const mode = useDemo ? 'DEMO' : 'REAL';
        console.log(`🎯 Trading started for ${req.user.email} | $${initialInvestment} -> $${targetProfit} | ${timeLimit}h`);
        res.json({
            success: true,
            sessionId,
            message: `🕋 HALAL TRADING STARTED! Investment: $${initialInvestment} | Target: $${targetProfit} | Time: ${timeLimit}h | Will trade every 2 minutes.`
        });
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeSessions[sessionId]) {
        if (activeSessions[sessionId].interval) clearInterval(activeSessions[sessionId].interval);
        activeSessions[sessionId].isActive = false;
        delete activeSessions[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    try {
        const { sessionId } = req.body;
        const session = activeSessions[sessionId];
        if (!session) return res.json({ success: true, currentProfit: 0, newTrades: [], isActive: false });
        const elapsedHours = (Date.now() - session.startedAt) / (1000 * 60 * 60);
        const timeRemaining = Math.max(0, session.timeLimit - elapsedHours);
        const progressPercent = session.targetProfit > 0 ? (session.currentProfit / session.targetProfit) * 100 : 0;
        res.json({
            success: true,
            currentProfit: session.currentProfit,
            targetProfit: session.targetProfit,
            newTrades: session.trades.slice(0, 10),
            winStreak: session.winStreak || 0,
            timeRemaining: timeRemaining,
            progressPercent: progressPercent,
            isActive: session.isActive
        });
    } catch (error) {
        res.json({ success: true, currentProfit: 0, newTrades: [] });
    }
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        if (!user || !user.apiKey) return res.json({ success: false, balance: 0 });
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        res.json({ success: true, spotBalance: spotBalance, total: spotBalance });
    } catch (error) {
        res.json({ success: false, balance: 0 });
    }
});

// ==================== ADMIN DATA ROUTES ====================
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email,
        hasApiKeys: !!users[email].apiKey,
        isOwner: users[email].isOwner,
        isApproved: users[email].isApproved,
        isBlocked: users[email].isBlocked
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const balances = {};
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.apiKey) {
            balances[email] = { spot: 0, total: 0 };
            continue;
        }
        try {
            const apiKey = decrypt(userData.apiKey);
            const secretKey = decrypt(userData.secretKey);
            const spotBalance = await getSpotBalance(apiKey, secretKey, false);
            balances[email] = { spot: spotBalance, total: spotBalance };
        } catch (error) {
            balances[email] = { spot: 0, total: 0, error: true };
        }
    }
    res.json({ success: true, balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) {
        return res.status(401).json({ success: false, message: 'Current password incorrect' });
    }
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed!' });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL TRADING BOT - FIXED VERSION`);
    console.log(`✅ Server: http://localhost:${PORT}`);
    console.log(`✅ Minimum Investment: $3 | Default Time: 1 hour`);
    console.log(`✅ Trades every 2 minutes (NEVER HOLDS)`);
    console.log(`✅ Login: mujtabahatif@gmail.com / Mujtabah@2598\n`);
});
