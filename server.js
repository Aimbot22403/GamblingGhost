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

// --- ENVIRONMENT VARIABLES & SECRETS ---
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// --- VALIDATE ENVIRONMENT VARIABLES ---
if (!MONGO_URI || !JWT_SECRET) {
    console.error("FATAL ERROR: MONGODB_URI and JWT_SECRET must be defined in environment variables.");
    // process.exit(1); // Optional: falls du den Server komplett stoppen willst
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- DATABASE CONNECTION ---
if (MONGO_URI) {
    mongoose.connect(MONGO_URI)
        .then(() => console.log("MongoDB connected successfully."))
        .catch(err => console.error("MongoDB connection error:", err));
}

// --- SCHEMAS ---
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
    const authHeader = req.header('Authorization');
    if (!authHeader) return res.status(401).json({ message: 'Access denied. No token provided.' });

    const token = authHeader.replace('Bearer ', '');
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token.' });
    }
};

// --- API ROUTES ---

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Username and password are required." });
        if (password.length < 4) return res.status(400).json({ message: "Password must be at least 4 characters." });

        const existingUser = await User.findOne({ username: username.toLowerCase() });
        if (existingUser) return res.status(400).json({ message: "Username already taken." });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username: username.toLowerCase(), password: hashedPassword });
        await user.save();

        res.status(201).json({ message: "User registered successfully." });
    } catch (error) {
        console.error("Register error:", error);
        res.status(500).json({ message: "Server error during registration." });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Username and password are required." });

        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(401).json({ message: 'Invalid credentials.' });

        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Server error during login." });
    }
});

// Get own profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -__v');
        if (!user) return res.status(404).json({ message: "User not found." });
        res.json(user);
    } catch (error) {
        console.error("Profile fetch error:", error);
        res.status(500).json({ message: "Error fetching profile." });
    }
});

// Update profile (bio + pfp)
app.post('/api/profile/update', authenticateToken, async (req, res) => {
    try {
        const { bio, pfp } = req.body;
        await User.findByIdAndUpdate(req.user.id, { bio, pfp });
        res.json({ message: 'Profile updated successfully.' });
    } catch (error) {
        console.error("Profile update error:", error);
        res.status(500).json({ message: "Error updating profile." });
    }
});

// Get any user profile by username (public)
app.get('/api/user/:username', async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();
        const user = await User.findOne({ username }).select('username bio pfp');
        if (!user) return res.status(404).json({ message: "User not found." });
        res.json(user);
    } catch (error) {
        console.error("User fetch error:", error);
        res.status(500).json({ message: "Error fetching user." });
    }
});

// --- GAME LOGIC ---

// Hilfsfunktionen für Blackjack
const getCardValue = c => {
    if (['J', 'Q', 'K'].includes(c.value)) return 10;
    if (c.value === 'A') return 11;
    return parseInt(c.value);
};
const getHandValue = h => {
    let total = h.reduce((sum, c) => sum + getCardValue(c), 0);
    let aces = h.filter(c => c.value === 'A').length;
    while (total > 21 && aces > 0) {
        total -= 10;
        aces--;
    }
    return total;
};

// Blackjack starten
app.post('/api/blackjack/start', authenticateToken, async (req, res) => {
    try {
        const { bet } = req.body;
        if (!bet || bet <= 0) return res.status(400).json({ message: "Invalid bet." });

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });
        if (blackjackGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current game first." });
        if (user.coins < bet) return res.status(400).json({ message: "Insufficient coins." });

        user.coins -= bet;
        await user.save();
        broadcastOnlineUsers();

        const suits = ['H', 'D', 'C', 'S'];
        const values = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];
        let deck = [];
        for (const s of suits) {
            for (const v of values) {
                deck.push({ suit: s, value: v });
            }
        }
        deck = deck.sort(() => 0.5 - Math.random());

        const playerHand = [deck.pop(), deck.pop()];
        const dealerHand = [deck.pop(), deck.pop()];
        const gameState = { deck, playerHand, dealerHand, bet, status: 'playing' };
        blackjackGames.set(req.user.id, gameState);

        const playerVal = getHandValue(playerHand);
        if (playerVal === 21) {
            // Blackjack sofort Gewinn
            const winnings = bet * 2.5;
            user.coins += winnings;
            await user.save();
            blackjackGames.delete(req.user.id);
            broadcastOnlineUsers();
            return res.json({
                status: `Blackjack! You win ${winnings} coins!`,
                playerHand,
                dealerHand,
                playerValue: playerVal,
                dealerValue: getHandValue(dealerHand),
                newBalance: user.coins
            });
        }

        res.json({
            status: 'playing',
            playerHand,
            dealerHand: [dealerHand[0], { suit: '?', value: '?' }],
            playerValue: playerVal,
            newBalance: user.coins
        });
    } catch (error) {
        console.error("Blackjack start error:", error);
        res.status(500).json({ message: "Error starting Blackjack." });
    }
});

// Blackjack Aktionen (hit, stand)
app.post('/api/blackjack/action', authenticateToken, async (req, res) => {
    try {
        const { action } = req.body;
        if (!action) return res.status(400).json({ message: "Action required." });

        const game = blackjackGames.get(req.user.id);
        if (!game) return res.status(404).json({ message: "No active Blackjack game." });

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        if (action === 'hit') {
            game.playerHand.push(game.deck.pop());
            const playerValue = getHandValue(game.playerHand);
            if (playerValue > 21) {
                game.status = 'bust';
                blackjackGames.delete(req.user.id);
                broadcastOnlineUsers();
                return res.json({
                    status: `Bust! You lost ${game.bet} coins.`,
                    playerHand: game.playerHand,
                    dealerHand: game.dealerHand,
                    playerValue,
                    dealerValue: getHandValue(game.dealerHand),
                    newBalance: user.coins
                });
            }
            blackjackGames.set(req.user.id, game);
            return res.json({
                status: 'playing',
                playerHand: game.playerHand,
                dealerHand: [game.dealerHand[0], { suit: '?', value: '?' }],
                playerValue
            });
        }

        if (action === 'stand') {
            while (getHandValue(game.dealerHand) < 17) {
                game.dealerHand.push(game.deck.pop());
            }
            const dealerValue = getHandValue(game.dealerHand);
            const playerValue = getHandValue(game.playerHand);
            let msg = '';
            let winnings = 0;

            if (dealerValue > 21 || playerValue > dealerValue) {
                winnings = game.bet * 2;
                msg = `You win ${winnings} coins!`;
                user.coins += winnings;
            } else if (playerValue < dealerValue) {
                msg = `Dealer wins. You lost ${game.bet} coins.`;
            } else {
                winnings = game.bet;
                msg = `Push. Your bet of ${winnings} coins was returned.`;
                user.coins += winnings;
            }
            await user.save();
            blackjackGames.delete(req.user.id);
            broadcastOnlineUsers();
            return res.json({
                status: msg,
                playerHand: game.playerHand,
                dealerHand: game.dealerHand,
                playerValue,
                dealerValue,
                newBalance: user.coins
            });
        }

        res.status(400).json({ message: "Invalid action." });
    } catch (error) {
        console.error("Blackjack action error:", error);
        res.status(500).json({ message: "Error during Blackjack action." });
    }
});

// Mines starten
app.post('/api/mines/start', authenticateToken, async (req, res) => {
    try {
        const { bet, minesCount } = req.body;
        if (!bet || bet <= 0) return res.status(400).json({ message: "Invalid bet." });
        if (![3, 5, 8, 10].includes(minesCount)) return res.status(400).json({ message: "Invalid mine count." });

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });
        if (minesGames.has(req.user.id)) return res.status(400).json({ message: "Finish your current Mines game." });
        if (user.coins < bet) return res.status(400).json({ message: "Insufficient coins." });

        user.coins -= bet;
        await user.save();
        broadcastOnlineUsers();

        const mines = new Set();
        while (mines.size < minesCount) {
            mines.add(Math.floor(Math.random() * 25)); // 25 Felder
        }

        minesGames.set(req.user.id, {
            bet,
            mines: Array.from(mines),
            clicks: 0,
            mult: { 3: 1.15, 5: 1.3, 8: 1.5, 10: 1.8 }[minesCount]
        });

        res.json({ message: "Game started", newBalance: user.coins });
    } catch (error) {
        console.error("Mines start error:", error);
        res.status(500).json({ message: "Error starting Mines game." });
    }
});

// Mines Feld klicken
app.post('/api/mines/click', authenticateToken, async (req, res) => {
    try {
        const { index } = req.body;
        const game = minesGames.get(req.user.id);
        if (!game) return res.status(404).json({ message: "No active Mines game." });

        if (game.mines.includes(index)) {
            minesGames.delete(req.user.id);
            return res.json({
                gameOver: true,
                message: `Boom! You hit a mine and lost ${game.bet} coins.`,
                minePositions: game.mines
            });
        }

        game.clicks++;
        const profit = game.bet * Math.pow(game.mult, game.clicks) - game.bet;
        minesGames.set(req.user.id, game);
        return res.json({
            gameOver: false,
            revealedIndex: index,
            profit: Math.floor(profit),
            nextMultiplier: Math.pow(game.mult, game.clicks + 1)
        });
    } catch (error) {
        console.error("Mines click error:", error);
        res.status(500).json({ message: "Error during Mines click." });
    }
});

// Mines auscashen
app.post('/api/mines/cashout', authenticateToken, async (req, res) => {
    try {
        const game = minesGames.get(req.user.id);
        if (!game || game.clicks === 0) return res.status(400).json({ message: "No game or clicks to cash out." });

        const winnings = Math.floor(game.bet * Math.pow(game.mult, game.clicks));
        const user = await User.findById(req.user.id);
        user.coins += winnings;
        await user.save();

        minesGames.delete(req.user.id);
        broadcastOnlineUsers();

        res.json({ message: `Cashed out ${winnings} coins!`, newBalance: user.coins });
    } catch (error) {
        console.error("Mines cashout error:", error);
        res.status(500).json({ message: "Error during Mines cashout." });
    }
});

// --- CATCH-ALL ROUTE ---
// Serve Frontend (React / Vue oder statische index.html)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- WEBSOCKET LOGIC ---
io.on('connection', (socket) => {
    socket.on('authenticate', async (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await User.findById(decoded.id);
            if (!user) throw new Error("User not found");
            await User.findByIdAndUpdate(user._id, { online: true });
            socket.userId = user._id.toString();
            socket.username = user.username;
            broadcastOnlineUsers();
            const lastMessages = await Message.find().sort({ timestamp: -1 }).limit(50);
            socket.emit('chat_history', lastMessages.reverse());
        } catch (err) {
            socket.disconnect();
        }
    });

    socket.on('chat_message', async (msg) => {
        if (socket.username && msg) {
            try {
                const newMessage = new Message({ username: socket.username, message: msg });
                await newMessage.save();
                io.emit('chat_message', newMessage);
            } catch (e) {
                console.error("Error saving chat message:", e);
            }
        }
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            try {
                await User.findByIdAndUpdate(socket.userId, { online: false });
                broadcastOnlineUsers();
                blackjackGames.delete(socket.userId);
                minesGames.delete(socket.userId);
            } catch (e) {
                console.error("Error during socket disconnect cleanup:", e);
            }
        }
    });
});

// Broadcast online users an alle Clients
async function broadcastOnlineUsers() {
    try {
        const onlineUsers = await User.find({ online: true }).select('username coins');
        io.emit('online_users', onlineUsers);
    } catch (e) {
        console.error("Error broadcasting online users:", e);
    }
}
setInterval(broadcastOnlineUsers, 5000);

// --- SERVER START ---
server.listen(PORT, () => {
    console.log(`Ghosts Gambling server running on port ${PORT}`);
});
