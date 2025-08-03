import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Hardcoded config
const JWT_SECRET = "9dkslfn2_DJ83sldf@!dkaP83";
const MONGO_URI =
  "mongodb+srv://GlobalConnection:iNA6MVaimtgyr2rV@ghostsgambling.41ahktw.mongodb.net/?retryWrites=true&w=majority&appName=GhostsGambling";
const DB_NAME = "GhostsGambling";

// Middleware
app.use(express.json({ limit: "10mb" })); // parse JSON bodies, allow big for profile pics
app.use(cors());

// Serve frontend file
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Connect to MongoDB
const client = new MongoClient(MONGO_URI, {
  useUnifiedTopology: true,
});
await client.connect();
const db = client.db(DB_NAME);
const Users = db.collection("users");
const Messages = db.collection("messages");
const Sessions = new Map(); // token => userId (in-memory)

// Helper: auth middleware
async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  const token = auth.split(" ")[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    const user = await Users.findOne({ _id: new ObjectId(data.id) });
    if (!user) return res.status(401).json({ error: "User not found" });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });
    const exists = await Users.findOne({ username: username.toLowerCase() });
    if (exists) return res.status(400).json({ error: "Username taken" });
    const hash = await bcrypt.hash(password, 10);
    const userDoc = {
      username: username.toLowerCase(),
      passwordHash: hash,
      coins: 10000,
      bio: "",
      profilePic: "", // base64 string
      online: false,
      lastOnline: new Date(),
    };
    const result = await Users.insertOne(userDoc);
    // create JWT
    const token = jwt.sign({ id: result.insertedId.toString() }, JWT_SECRET);
    Sessions.set(token, result.insertedId.toString());
    res.json({ token, username: userDoc.username, coins: userDoc.coins });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });
    const user = await Users.findOne({ username: username.toLowerCase() });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });
    // mark online
    await Users.updateOne({ _id: user._id }, { $set: { online: true, lastOnline: new Date() } });
    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET);
    Sessions.set(token, user._id.toString());
    res.json({ token, username: user.username, coins: user.coins });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// Logout (client just forgets token, but mark offline server-side optionally)
app.post("/api/logout", authMiddleware, async (req, res) => {
  try {
    await Users.updateOne({ _id: req.user._id }, { $set: { online: false, lastOnline: new Date() } });
    // Remove token from sessions map
    for (const [token, uid] of Sessions.entries()) {
      if (uid === req.user._id.toString()) Sessions.delete(token);
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Get current user info
app.get("/api/me", authMiddleware, async (req, res) => {
  const u = req.user;
  res.json({
    username: u.username,
    coins: u.coins,
    bio: u.bio,
    profilePic: u.profilePic,
  });
});

// Update profile (bio + profilePic)
app.post("/api/me/profile", authMiddleware, async (req, res) => {
  try {
    let { bio, profilePic } = req.body;
    if (typeof bio !== "string" || typeof profilePic !== "string") {
      return res.status(400).json({ error: "Invalid input" });
    }
    if (bio.length > 200) bio = bio.slice(0, 200);
    await Users.updateOne({ _id: req.user._id }, { $set: { bio, profilePic } });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Get profile by username (for chat clicks)
app.get("/api/user/:username", async (req, res) => {
  try {
    const username = req.params.username.toLowerCase();
    const user = await Users.findOne({ username });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({
      username: user.username,
      bio: user.bio,
      profilePic: user.profilePic,
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Get online users list (username + coins)
app.get("/api/online-users", async (req, res) => {
  try {
    const onlineUsers = await Users.find({ online: true }).project({ username: 1, coins: 1 }).toArray();
    res.json(onlineUsers);
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// --- CHAT ---

// Post a chat message
app.post("/api/chat", authMiddleware, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || text.length > 500) return res.status(400).json({ error: "Invalid message" });
    const message = {
      userId: req.user._id,
      username: req.user.username,
      text: text.trim(),
      timestamp: new Date(),
    };
    await Messages.insertOne(message);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Get last 100 messages
app.get("/api/chat", async (req, res) => {
  try {
    const msgs = await Messages.find({})
      .sort({ timestamp: -1 })
      .limit(100)
      .toArray();
    // reverse for oldest first
    res.json(msgs.reverse());
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// --- GAMES ---

// Blackjack game states are ephemeral - stored per user in memory (reset on server restart)
const blackjackGames = new Map();

// Helper for cards
const suits = ["♠", "♥", "♦", "♣"];
const values = [
  "A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K",
];

function createDeck() {
  const deck = [];
  for (const s of suits) {
    for (const v of values) deck.push({ suit: s, value: v });
  }
  return deck.sort(() => Math.random() - 0.5); // shuffle
}
function cardValue(card) {
  if (card.value === "A") return 11;
  if (["J", "Q", "K"].includes(card.value)) return 10;
  return Number(card.value);
}
function handValue(hand) {
  let val = 0, aces = 0;
  for (const c of hand) {
    val += cardValue(c);
    if (c.value === "A") aces++;
  }
  while (val > 21 && aces > 0) {
    val -= 10;
    aces--;
  }
  return val;
}

// Start blackjack
app.post("/api/blackjack/start", authMiddleware, async (req, res) => {
  try {
    let { bet } = req.body;
    bet = Number(bet);
    if (!bet || bet < 10 || bet > req.user.coins) return res.status(400).json({ error: "Invalid bet" });

    // Create deck and hands
    const deck = createDeck();
    const playerHand = [deck.pop(), deck.pop()];
    const dealerHand = [deck.pop(), deck.pop()];
    const playerVal = handValue(playerHand);
    const dealerVal = handValue(dealerHand);

    // Save game state
    blackjackGames.set(req.user._id.toString(), {
      deck,
      playerHand,
      dealerHand,
      bet,
      done: false,
      playerStood: false,
    });

    res.json({
      playerHand,
      dealerHand: [dealerHand[0], { suit: "?", value: "?" }],
      playerVal,
      bet,
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Player hits
app.post("/api/blackjack/hit", authMiddleware, async (req, res) => {
  try {
    const game = blackjackGames.get(req.user._id.toString());
    if (!game || game.done) return res.status(400).json({ error: "No active game" });

    game.playerHand.push(game.deck.pop());
    const playerVal = handValue(game.playerHand);
    if (playerVal > 21) {
      // Player busts - lose bet
      game.done = true;
      await Users.updateOne({ _id: req.user._id }, { $inc: { coins: -game.bet } });
      blackjackGames.delete(req.user._id.toString());
      return res.json({ status: "bust", playerHand: game.playerHand, playerVal, bet: game.bet, coins: req.user.coins - game.bet });
    }
    res.json({ status: "playing", playerHand: game.playerHand, playerVal });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Player stands, dealer plays
app.post("/api/blackjack/stand", authMiddleware, async (req, res) => {
  try {
    const game = blackjackGames.get(req.user._id.toString());
    if (!game || game.done) return res.status(400).json({ error: "No active game" });

    game.playerStood = true;

    // Dealer reveals cards and draws until 17+
    while (handValue(game.dealerHand) < 17) {
      game.dealerHand.push(game.deck.pop());
    }
    const playerVal = handValue(game.playerHand);
    const dealerVal = handValue(game.dealerHand);

    let result = "lose";
    let coinsChange = -game.bet;
    if (playerVal > 21) {
      result = "lose";
    } else if (dealerVal > 21 || playerVal > dealerVal) {
      result = "win";
      coinsChange = game.bet;
    } else if (playerVal === dealerVal) {
      result = "draw";
      coinsChange = 0;
    }
    // Update coins if not draw
    if (coinsChange !== 0) {
      await Users.updateOne({ _id: req.user._id }, { $inc: { coins: coinsChange } });
    }
    // Remove game state
    blackjackGames.delete(req.user._id.toString());
    const userAfter = await Users.findOne({ _id: req.user._id });

    res.json({
      result,
      playerHand: game.playerHand,
      dealerHand: game.dealerHand,
      playerVal,
      dealerVal,
      coins: userAfter.coins,
      bet: game.bet,
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// --- MINES ---

// Mines games ephemeral storage per user
const minesGames = new Map();

// Get multiplier by mines count
function getMultiplier(mines) {
  switch (mines) {
    case 3: return 1.3;
    case 5: return 1.8;
    case 8: return 3.5;
    case 10: return 5.5;
    default: return 1;
  }
}

// Start mines
app.post("/api/mines/start", authMiddleware, async (req, res) => {
  try {
    let { bet, mines } = req.body;
    bet = Number(bet);
    mines = Number(mines);
    if (!bet || bet < 10 || bet > req.user.coins) return res.status(400).json({ error: "Invalid bet" });
    if (![3, 5, 8, 10].includes(mines)) return res.status(400).json({ error: "Invalid mines count" });

    const gridSize = 25; // 5x5 grid
    const minePositions = new Set();
    while (minePositions.size < mines) {
      minePositions.add(Math.floor(Math.random() * gridSize));
    }
    minesGames.set(req.user._id.toString(), {
      bet,
      mines,
      minePositions,
      revealed: new Set(),
      finished: false,
      multiplier: getMultiplier(mines),
    });
    res.json({ ok: true, gridSize, mines });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Reveal a cell
app.post("/api/mines/reveal", authMiddleware, async (req, res) => {
  try {
    const { index } = req.body;
    if (typeof index !== "number") return res.status(400).json({ error: "Invalid index" });
    const game = minesGames.get(req.user._id.toString());
    if (!game || game.finished) return res.status(400).json({ error: "No active game" });
    if (game.revealed.has(index)) return res.status(400).json({ error: "Cell already revealed" });
    game.revealed.add(index);
    if (game.minePositions.has(index)) {
      // Player hit a mine - lose bet
      game.finished = true;
      await Users.updateOne({ _id: req.user._id }, { $inc: { coins: -game.bet } });
      minesGames.delete(req.user._id.toString());
      const userAfter = await Users.findOne({ _id: req.user._id });
      return res.json({ status: "lose", coins: userAfter.coins, hitMine: true });
    }
    // Player safe
    // Calculate current win coins: bet * multiplier * (safeCellsRevealed / total safe cells)
    const safeCells = 25 - game.mines;
    const safeRevealed = game.revealed.size;
    const partialMultiplier = 1 + ((game.multiplier - 1) * safeRevealed) / safeCells;

    res.json({ status: "safe", partialMultiplier, revealedCount: safeRevealed });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Cash out mines game (player takes current multiplier * bet)
app.post("/api/mines/cashout", authMiddleware, async (req, res) => {
  try {
    const game = minesGames.get(req.user._id.toString());
    if (!game || game.finished) return res.status(400).json({ error: "No active game" });

    const safeCells = 25 - game.mines;
    const safeRevealed = game.revealed.size;
    if (safeRevealed === 0) return res.status(400).json({ error: "No cells revealed yet" });

    const finalMultiplier = 1 + ((game.multiplier - 1) * safeRevealed) / safeCells;
    const winAmount = Math.floor(game.bet * finalMultiplier);

    // Add coins won
    await Users.updateOne({ _id: req.user._id }, { $inc: { coins: winAmount } });
    game.finished = true;
    minesGames.delete(req.user._id.toString());
    const userAfter = await Users.findOne({ _id: req.user._id });
    res.json({ status: "win", coins: userAfter.coins, winAmount, finalMultiplier });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Static files fallback - serve index.html for all other routes (SPA)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Start server
app.listen(PORT, () => {
  console.log(`Ghosts Gambling server listening on port ${PORT}`);
});
