const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

// --- Basic Setup ---
const app = express();
app.use(cors());
app.use(express.json());

// --- THIS IS THE KEY FIX ---
// Serve all static files (like index.html) from the 'public' directory.
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// --- Hardcoded Constants ---
const MONGO_URI = "mongodb+srv://GlobalConnection:iNA6MVaimtgyr2rV@ghostsgambling.41ahktw.mongodb.net/?retryWrites=true&w=majority&appName=GhostsGambling";
const JWT_SECRET = "9dkslfn2_DJ83sldf@!dkaP83";
const PORT = process.env.PORT || 3000; // Vercel provides the PORT environment variable

// --- Database Connection ---
mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully."))
    .catch(err => console.error("MongoDB connection error:", err));

// --- Mongoose Schemas ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    coins: { type: Number, default: 10000 },
    bio: { type: String, default: "No bio set." },
    pfp: { type: String, default: "https://i.imgur.com/8bzvETr.png" },
    online: { type: Boolean, default: false }
});

const messageSchema = new mongoose.Schema({
    username: String,
    message: String,
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// --- In-Memory Game State ---
const blackjackGames = new Map();
const minesGames = new Map();

// --- Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- API ROUTES ---
// The '/api' prefix is crucial to separate backend from frontend routes.

// --- API: Authentication ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Username and password are required." });
        if (password.length < 4) return res.status(400).json({ message: "Password must be at least 4 characters." });
        if (await User.findOne({ username: username.toLowerCase() })) return res.status(400).json({ message: "Username already taken." });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username: username.toLowerCase(), password: hashedPassword, coins: 10000 });
        await newUser.save();
        res.status(201).json({ message: "User registered successfully." });
    } catch (error) {
        res.status(500).json({ message: "Server error during registration." });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user || !await bcrypt.compare(password, user.password)) return res.status(400).json({ message: "Invalid credentials." });
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: "Server error during login." });
    }
});

// --- API: Profile ---
app.get('/api/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
});

app.post('/api/profile/update', authenticateToken, async (req, res) => {
    const { bio, pfp } = req.body;
    const updatedUser = await User.findByIdAndUpdate(req.user.id, { bio, pfp }, { new: true }).select('-password');
    res.json(updatedUser);
});

app.get('/api/user/:username', async (req, res) => {
    const user = await User.findOne({ username: req.params.username.toLowerCase() }).select('username bio pfp');
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json(user);
});

// --- Game Logic (Stateful) ---
const getCardValue = (c) => { if (['J', 'Q', 'K'].includes(c.value)) return 10; if (c.value === 'A') return 11; return parseInt(c.value); };
const getHandValue = (h) => { let v = h.reduce((s, c) => s + getCardValue(c), 0); let a = h.filter(c => c.value === 'A').length; while (v > 21 && a > 0) { v -= 10; a--; } return v; };

app.post('/api/blackjack/start', authenticateToken, async (req, res) => {
    const { bet } = req.body; const user = await User.findById(req.user.id);
    if (blackjackGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current game." });
    if (!bet || bet <= 0 || user.coins < bet) return res.status(400).json({ message: "Invalid bet." });
    user.coins -= bet; await user.save(); broadcastOnlineUsers();
    const deck = ['H', 'D', 'C', 'S'].flatMap(s => ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'].map(v => ({ suit: s, value: v }))).sort(() => .5 - Math.random());
    const pHand = [deck.pop(), deck.pop()], dHand = [deck.pop(), deck.pop()];
    const gState = { deck, playerHand: pHand, dealerHand: dHand, bet, status: 'playing' };
    blackjackGames.set(req.user.id, gState);
    if (getHandValue(pHand) === 21) { const w = bet * 2.5; user.coins += w; await user.save(); blackjackGames.delete(req.user.id); broadcastOnlineUsers(); return res.json({ status: `Blackjack! Win ${w}`, playerHand: pHand, dealerHand: dHand, playerValue: 21, dealerValue: getHandValue(dHand), newBalance: user.coins }); }
    res.json({ status: 'playing', playerHand: pHand, dealerHand: [dHand[0], { suit: '?', value: '?' }], playerValue: getHandValue(pHand), newBalance: user.coins });
});
app.post('/api/blackjack/action', authenticateToken, async (req, res) => {
    const { action } = req.body; const game = blackjackGames.get(req.user.id); if (!game) return res.status(404).json({ message: "No active game." });
    const user = await User.findById(req.user.id); let pVal = getHandValue(game.playerHand);
    if (action === 'hit') { game.playerHand.push(game.deck.pop()); pVal = getHandValue(game.playerHand); if (pVal > 21) { game.status = 'bust'; blackjackGames.delete(req.user.id); broadcastOnlineUsers(); return res.json({ status: `Bust! Lost ${game.bet}`, playerHand: game.playerHand, dealerHand: game.dealerHand, playerValue: pVal, newBalance: user.coins }); } blackjackGames.set(req.user.id, game); return res.json({ status: 'playing', playerHand: game.playerHand, playerValue: pVal }); }
    if (action === 'stand') { while (getHandValue(game.dealerHand) < 17) game.dealerHand.push(game.deck.pop()); const dVal = getHandValue(game.dealerHand); pVal = getHandValue(game.playerHand); let msg = ''; let w = 0; if (dVal > 21 || pVal > dVal) { w = game.bet * 2; msg = `You win ${w}`; user.coins += w; } else if (pVal < dVal) { msg = `Dealer wins. Lost ${game.bet}`; } else { w = game.bet; msg = `Push. Bet of ${w} returned`; user.coins += w; } await user.save(); blackjackGames.delete(req.user.id); broadcastOnlineUsers(); return res.json({ status: msg, playerHand: game.playerHand, dealerHand: game.dealerHand, playerValue: pVal, dealerValue: dVal, newBalance: user.coins }); }
    res.status(400).json({ message: "Invalid action." });
});
app.post('/api/mines/start', authenticateToken, async (req, res) => {
    const { bet, minesCount } = req.body; const user = await User.findById(req.user.id);
    if (minesGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current game." });
    if (!bet || bet <= 0 || user.coins < bet) return res.status(400).json({ message: "Invalid bet." });
    if (![3, 5, 8, 10].includes(minesCount)) return res.status(400).json({ message: "Invalid mine count." });
    user.coins -= bet; await user.save(); broadcastOnlineUsers();
    const mines = new Set(); while (mines.size < minesCount) mines.add(Math.floor(Math.random() * 25));
    minesGames.set(req.user.id, { bet, mines: Array.from(mines), clicks: 0, mult: { 3: 1.15, 5: 1.3, 8: 1.5, 10: 1.8 }[minesCount] });
    res.json({ message: "Game started", newBalance: user.coins });
});
app.post('/api/mines/click', authenticateToken, async (req, res) => {
    const { index } = req.body; const game = minesGames.get(req.user.id); if (!game) return res.status(404).json({ message: "No active game." });
    if (game.mines.includes(index)) { minesGames.delete(req.user.id); return res.json({ gameOver: true, message: `Boom! You lost ${game.bet}`, minePositions: game.mines }); }
    game.clicks++; const profit = game.bet * Math.pow(game.mult, game.clicks) - game.bet; minesGames.set(req.user.id, game);
    res.json({ gameOver: false, revealedIndex: index, profit: Math.floor(profit), nextMultiplier: Math.pow(game.mult, game.clicks + 1) });
});
app.post('/api/mines/cashout', authenticateToken, async (req, res) => {
    const game = minesGames.get(req.user.id); if (!game || game.clicks === 0) return res.status(400).json({ message: "No game or clicks to cashout." });
    const winnings = Math.floor(game.bet * Math.pow(game.mult, game.clicks)); const user = await User.findById(req.user.id);
    user.coins += winnings; await user.save(); minesGames.delete(req.user.id); broadcastOnlineUsers();
    res.json({ message: `Cashed out ${winnings} coins!`, newBalance: user.coins });
});

// --- Websockets for Chat & Online Users ---
io.on('connection', (socket) => {
    socket.on('authenticate', async (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            await User.findByIdAndUpdate(decoded.id, { online: true });
            socket.userId = decoded.id;
            socket.username = decoded.username;
            broadcastOnlineUsers();
            const lastMessages = await Message.find().sort({ timestamp: -1 }).limit(50);
            socket.emit('chat_history', lastMessages.reverse());
        } catch (err) { socket.disconnect(); }
    });

    socket.on('chat_message', async (msg) => {
        if (socket.username && msg) {
            const newMessage = new Message({ username: socket.username, message: msg });
            await newMessage.save();
            io.emit('chat_message', newMessage);
        }
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            await User.findByIdAndUpdate(socket.userId, { online: false });
            broadcastOnlineUsers();
            blackjackGames.delete(socket.userId);
            minesGames.delete(socket.userId);
        }
    });
});
async function broadcastOnlineUsers() {
    const onlineUsers = await User.find({ online: true }).select('username coins');
    io.emit('online_users', onlineUsers);
}
setInterval(broadcastOnlineUsers, 5000);

// --- SERVER START ---
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

// Export the app for serverless environments like Vercel
module.exports = app;