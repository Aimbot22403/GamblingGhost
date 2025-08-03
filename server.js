const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

// --- SETUP ---
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// --- CONFIGURATION ---
// Using the port Vercel provides. Falls back to 3000 for local testing.
const PORT = process.env.PORT || 3000;
// Hardcoded connection strings as requested. For production, use Environment Variables.
const MONGO_URI = "mongodb+srv://GlobalConnection:Balls123@ghostsgambling.41ahktw.mongodb.net/?retryWrites=true&w=majority&appName=GhostsGambling";
const JWT_SECRET = "9dkslfn2_DJ83sldf@!dkaP83";

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
// This line is CRITICAL: It serves all static files (like index.html) from the 'public' directory.
app.use(express.static(path.join(__dirname, 'public')));

// --- DATABASE CONNECTION ---
mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB connected successfully."))
    .catch(err => console.error("MongoDB connection error:", err));

// --- SCHEMAS ---
// Mongoose will automatically create these collections in the DB when you first register a user.
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

// --- IN-MEMORY GAME STATE ---
const blackjackGames = new Map();
const minesGames = new Map();

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Access denied.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};

// --- API ROUTES ---
// All API routes are prefixed with `/api` to avoid conflicts with frontend files.

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Username and password are required." });
        if (await User.findOne({ username: username.toLowerCase() })) return res.status(400).json({ message: "Username already taken." });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username: username.toLowerCase(), password: hashedPassword });
        await user.save(); // This will create the 'users' collection if it doesn't exist
        res.status(201).json({ message: "User registered successfully." });
    } catch (error) {
        res.status(500).json({ message: "Server error during registration." });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: "Server error during login." });
    }
});

app.get('/api/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
});

app.post('/api/profile/update', authenticateToken, async (req, res) => {
    await User.findByIdAndUpdate(req.user.id, { bio: req.body.bio, pfp: req.body.pfp });
    res.json({ message: 'Profile updated' });
});

app.get('/api/user/:username', async (req, res) => {
    const user = await User.findOne({ username: req.params.username.toLowerCase() }).select('username bio pfp');
    res.json(user || { message: 'User not found' });
});

// --- GAME API ROUTES ---
const getCardValue = c => { if (['J', 'Q', 'K'].includes(c.value)) return 10; if (c.value === 'A') return 11; return parseInt(c.value); };
const getHandValue = h => { let v = h.reduce((s, c) => s + getCardValue(c), 0); let a = h.filter(c => c.value === 'A').length; while (v > 21 && a > 0) { v -= 10; a--; } return v; };

app.post('/api/blackjack/start', authenticateToken, async (req, res) => {
    const { bet } = req.body;
    const user = await User.findById(req.user.id);
    if (blackjackGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current game." });
    if (!bet || bet <= 0 || user.coins < bet) return res.status(400).json({ message: "Invalid bet." });
    user.coins -= bet; await user.save(); broadcastOnlineUsers();
    const deck = ['H', 'D', 'C', 'S'].flatMap(s => ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'].map(v => ({ suit: s, value: v }))).sort(() => .5 - Math.random());
    const playerHand = [deck.pop(), deck.pop()], dealerHand = [deck.pop(), deck.pop()];
    const gameState = { deck, playerHand, dealerHand, bet, status: 'playing' };
    blackjackGames.set(req.user.id, gameState);
    if (getHandValue(playerHand) === 21) { const winnings = bet * 2.5; user.coins += winnings; await user.save(); blackjackGames.delete(req.user.id); broadcastOnlineUsers(); return res.json({ status: `Blackjack! You win ${winnings}`, playerHand, dealerHand, playerValue: 21, dealerValue: getHandValue(dealerHand), newBalance: user.coins }); }
    res.json({ status: 'playing', playerHand, dealerHand: [dealerHand[0], { suit: '?', value: '?' }], playerValue: getHandValue(playerHand), newBalance: user.coins });
});

app.post('/api/blackjack/action', authenticateToken, async (req, res) => {
    const { action } = req.body;
    const game = blackjackGames.get(req.user.id); if (!game) return res.status(404).json({ message: "No active game." });
    const user = await User.findById(req.user.id);
    let playerValue = getHandValue(game.playerHand);
    if (action === 'hit') {
        game.playerHand.push(game.deck.pop()); playerValue = getHandValue(game.playerHand);
        if (playerValue > 21) { blackjackGames.delete(req.user.id); broadcastOnlineUsers(); return res.json({ status: `Bust! You lost ${game.bet}`, playerHand: game.playerHand, dealerHand: game.dealerHand, playerValue, dealerValue: getHandValue(game.dealerHand), newBalance: user.coins });}
        blackjackGames.set(req.user.id, game); return res.json({ status: 'playing', playerHand: game.playerHand, dealerHand: [game.dealerHand[0], { suit: '?', value: '?' }], playerValue });
    }
    if (action === 'stand') {
        while (getHandValue(game.dealerHand) < 17) game.dealerHand.push(game.deck.pop());
        const dealerValue = getHandValue(game.dealerHand); playerValue = getHandValue(game.playerHand);
        let msg = '', winnings = 0;
        if (dealerValue > 21 || playerValue > dealerValue) { winnings = game.bet * 2; msg = `You win ${winnings} coins!`; user.coins += winnings; }
        else if (playerValue < dealerValue) { msg = `Dealer wins. You lost ${game.bet} coins.`; }
        else { winnings = game.bet; msg = `Push. Your bet of ${winnings} coins was returned.`; user.coins += winnings; }
        await user.save(); blackjackGames.delete(req.user.id); broadcastOnlineUsers();
        return res.json({ status: msg, playerHand: game.playerHand, dealerHand: game.dealerHand, playerValue, dealerValue, newBalance: user.coins });
    }
});

app.post('/api/mines/start', authenticateToken, async (req, res) => {
    const { bet, minesCount } = req.body;
    const user = await User.findById(req.user.id);
    if (minesGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current game." });
    if (!bet || bet <= 0 || user.coins < bet) return res.status(400).json({ message: "Invalid bet." });
    if (![3, 5, 8, 10].includes(minesCount)) return res.status(400).json({ message: "Invalid mine count." });
    user.coins -= bet; await user.save(); broadcastOnlineUsers();
    const mines = new Set(); while (mines.size < minesCount) mines.add(Math.floor(Math.random() * 25));
    minesGames.set(req.user.id, { bet, mines: Array.from(mines), clicks: 0, mult: { 3: 1.15, 5: 1.3, 8: 1.5, 10: 1.8 }[minesCount] });
    res.json({ newBalance: user.coins });
});

app.post('/api/mines/click', authenticateToken, async (req, res) => {
    const { index } = req.body;
    const game = minesGames.get(req.user.id); if (!game) return res.status(404).json({ message: "No active game." });
    if (game.mines.includes(index)) { minesGames.delete(req.user.id); return res.json({ gameOver: true, message: `Boom! You lost ${game.bet} coins.`, minePositions: game.mines }); }
    game.clicks++;
    const profit = game.bet * Math.pow(game.mult, game.clicks) - game.bet;
    minesGames.set(req.user.id, game);
    res.json({ gameOver: false, profit: Math.floor(profit), nextMultiplier: Math.pow(game.mult, game.clicks + 1) });
});

app.post('/api/mines/cashout', authenticateToken, async (req, res) => {
    const game = minesGames.get(req.user.id); if (!game || game.clicks === 0) return res.status(400).json({ message: "No game or clicks to cashout." });
    const winnings = Math.floor(game.bet * Math.pow(game.mult, game.clicks));
    const user = await User.findById(req.user.id);
    user.coins += winnings; await user.save(); minesGames.delete(req.user.id); broadcastOnlineUsers();
    res.json({ message: `Cashed out ${winnings} coins!`, newBalance: user.coins });
});

// --- WEBSOCKET LOGIC ---
io.on('connection', (socket) => {
    socket.on('authenticate', async (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await User.findById(decoded.id); if (!user) throw new Error("User not found");
            await User.findByIdAndUpdate(user._id, { online: true });
            socket.userId = user._id.toString(); socket.username = user.username;
            broadcastOnlineUsers();
            const lastMessages = await Message.find().sort({ timestamp: -1 }).limit(50);
            socket.emit('chat_history', lastMessages.reverse());
        } catch (err) { socket.disconnect(); }
    });
    socket.on('chat_message', async (msg) => {
        if (socket.username && msg) {
            const newMessage = new Message({ username: socket.username, message: msg });
            await newMessage.save(); io.emit('chat_message', newMessage);
        }
    });
    socket.on('disconnect', async () => {
        if (socket.userId) {
            await User.findByIdAndUpdate(socket.userId, { online: false });
            broadcastOnlineUsers();
            blackjackGames.delete(socket.userId); minesGames.delete(socket.userId);
        }
    });
});
async function broadcastOnlineUsers() {
    const onlineUsers = await User.find({ online: true }).select('username coins');
    io.emit('online_users', onlineUsers);
}
setInterval(broadcastOnlineUsers, 5000);


// --- SERVER LISTEN ---
server.listen(PORT, () => {
    console.log(`Ghosts Gambling server running on http://localhost:${PORT}`);
});