// server.js
// Full-featured Nyx backend (text-only)
// Features: JSON responses, commands, memory, JWT auth, MongoDB storage (optional), rate limiting, personality, Gemini AI

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { GoogleGenAI } = require('@google/genai');

// -------------------
// Config / env checks
// -------------------
const PORT = process.env.PORT || 3000;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || null;
const MONGO_URI = process.env.MONGO_URI || null;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret'; // change in production

if (!GEMINI_API_KEY) {
  console.warn('WARNING: GEMINI_API_KEY not set. AI calls will fail until you set it in .env.');
}

// -------------------
// MongoDB and Models Setup
// -------------------
const useMongo = !!MONGO_URI;
let inMemoryUsers = {}; // Fallback storage for users if MongoDB is disabled

if (useMongo) {
    mongoose.connect(MONGO_URI)
        .then(() => console.log('MongoDB connected successfully.'))
        .catch(err => console.error('MongoDB connection error:', err));
}

// Mongoose Models (only initialized if useMongo is true)
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});
const User = useMongo ? mongoose.model('User', UserSchema) : null;

const MessageSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    role: { type: String, enum: ['user', 'model'], required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Message = useMongo ? mongoose.model('Message', MessageSchema) : null;

const MemorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    key: { type: String, required: true },
    value: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
const Memory = useMongo ? mongoose.model('Memory', MemorySchema) : null;



let ai = null;
try {
  if (GEMINI_API_KEY) {
    ai = new GoogleGenAI(GEMINI_API_KEY);
  }
} catch (err) {
  console.error('Failed to init GoogleGenAI client:', err && err.message);
  ai = null;
}


let personality = {};
let commands = {};
let responses = {};

function loadJsonFiles() {
    try {
        if (fs.existsSync('personality.json')) {
            personality = JSON.parse(fs.readFileSync('personality.json', 'utf8'));
        }
        if (fs.existsSync('commands.json')) {
            commands = JSON.parse(fs.readFileSync('commands.json', 'utf8'));
        }
        if (fs.existsSync('responses.json')) {
            responses = JSON.parse(fs.readFileSync('responses.json', 'utf8'));
        }
    } catch (e) {
        console.error("Error loading JSON files:", e.message);
    }
}
loadJsonFiles();


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public')); 


const rateLimiter = (req, res, next) => {

    next();
};


const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Authorization header missing.' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { id: userId, email: userEmail }
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};




function formatHistory(history) {
    return history.map(msg => ({
        role: msg.role === 'bot' ? 'model' : 'user', // Ensure roles are 'user'/'model'
        parts: [{ text: msg.text }]
    }));
}

// Function to store message in DB (conditional on useMongo)
async function saveMessage(userId, role, text) {
    if (!useMongo || !Message) return;
    try {
        await Message.create({ userId, role, text });
    } catch (err) {
        console.error('Failed to save message to MongoDB:', err.message);
    }
}

// ----------------
// Routes: Auth
// ----------------

// Register Route
app.post('/api/auth/register', rateLimiter, async (req, res) => {
    const { email, password, username } = req.body;
    if (!email || !password || !username) return res.status(400).json({ error: 'Missing fields.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    
    if (useMongo && User) {
        // --- MONGODB REGISTRATION ---
        try {
            const user = await User.create({ email, username, password: hashedPassword });
            const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
            return res.json({ message: 'Registration successful.', token });
        } catch (err) {
            if (err.code === 11000) return res.status(409).json({ error: 'User already exists.' });
            return res.status(500).json({ error: 'Registration failed.' });
        }
    } else {
        // --- IN-MEMORY FALLBACK REGISTRATION ---
        if (inMemoryUsers[email]) return res.status(409).json({ error: 'User already exists (in-memory).' });

        // Use a UUID or timestamp as a pseudo-ID for in-memory user
        const pseudoId = 'guest_' + Date.now(); 
        inMemoryUsers[email] = {
            _id: pseudoId,
            email,
            username,
            password: hashedPassword
        };
        const token = jwt.sign({ id: pseudoId, email: email }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ message: 'Registration successful (in-memory).', token });
    }
});

// Login Route
app.post('/api/auth/login', rateLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password.' });

    let user = null;

    if (useMongo && User) {
        // --- MONGODB LOGIN ---
        try {
            user = await User.findOne({ email });
            if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
        } catch (err) {
            return res.status(500).json({ error: 'Login failed.' });
        }
    } else {
        // --- IN-MEMORY FALLBACK LOGIN ---
        user = inMemoryUsers[email];
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Shared password comparison logic
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials.' });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ message: 'Login successful.', token });
});

// ----------------
// Routes: AI Chat
// ----------------

const systemInstruction = personality.system_prompt || "You are a helpful, concise, and professional AI assistant. Respond warmly and directly.";
const model = 'gemini-2.5-flash';

// Main Chat Route
app.post('/api/chat', authMiddleware, rateLimiter, async (req, res) => {
  if (!ai) return res.status(500).json({ text: 'AI client not initialized.' });
  const user = req.user;
  const { prompt, history } = req.body;
  
  if (!prompt) return res.status(400).json({ text: 'Prompt is required.' });

  // History should already be in the correct format from the client
  const geminiHistory = formatHistory(history); 
  geminiHistory.push({ role: 'user', parts: [{ text: prompt }] });
  
  const fallback = 'Sorry, the AI is currently unavailable. Please try again later.';

  try {
    // Save user message to DB (conditional)
    await saveMessage(user.id, 'user', prompt);

    const response = await ai.models.generateContent({
        model,
        contents: geminiHistory,
        config: {
            systemInstruction: systemInstruction,
            temperature: 0.7,
        }
    });

    const botResponse = response.text;

    // Save model response to DB (conditional)
    await saveMessage(user.id, 'model', botResponse);
    
    return res.json({ text: botResponse });

  } catch (err) {
    console.error('Gemini Chat API Error:', err.message);
    return res.status(500).json({ text: fallback });
  }
});


// ----------------
// Routes: Gemini Tools
// ----------------

app.post('/api/tool/:toolType', authMiddleware, rateLimiter, async (req, res) => {
    if (!ai) return res.status(500).json({ error: 'AI client not initialized.' });
    const user = req.user;
    const { history } = req.body; 
    const toolType = req.params.toolType;

    // Filter out non-content messages (like welcome messages)
    const contentHistory = history.filter(m => m.role !== 'system' && m.text !== "Welcome back! What can I help you with today?"); 

    if (contentHistory.length < 2) {
        return res.status(400).json({ error: 'Not enough conversation history to analyze.' });
    }

    // Convert history to a single string for prompt injection
    const conversationText = contentHistory.map(m => `${m.role.toUpperCase()}: ${m.text}`).join('\n');

    let instruction = '';
    let responseText = '';
    
    switch (toolType) {
        case 'summarize':
            instruction = "You are a conversation summarization expert. Analyze the following chat history between USER and a BOT. Provide a concise, professional, single-paragraph summary of the main topics and conclusions discussed. Do not use bullet points or lists. Start the summary directly, without a greeting.";
            responseText = "Here is a quick summary of your chat:";
            break;
        case 'suggest':
            instruction = "You are a helpful assistant. Analyze the following chat history between USER and a BOT. Suggest exactly three distinct, interesting follow-up questions or actions the user could take next. Format your output as a numbered list (1., 2., 3.). Do not include any introductory or concluding text, just the list.";
            responseText = "Here are some ideas for next steps:";
            break;
        case 'tasks':
            instruction = "You are a task management AI. Analyze the following chat history between USER and a BOT, focusing on the last few turns. Identify any implied or explicit tasks, action items, or things to remember. Generate a concise, simple list of these items. Format your output as a markdown bulleted list using the '-' character. Do not include any introductory or concluding text, just the list.";
            responseText = "I've generated this action plan for you:";
            break;
        default:
            return res.status(404).json({ error: `Unknown tool type: ${toolType}` });
    }

    const fullPrompt = `CONVERSATION HISTORY:\n\n${conversationText}\n\n[END OF HISTORY]`;

    try {
        const response = await ai.models.generateContent({
            model,
            contents: [{ role: 'user', parts: [{ text: fullPrompt }] }],
            config: {
                systemInstruction: instruction,
                temperature: 0.3,
            }
        });

        const geminiOutput = response.text;
        
        const finalResponse = `${responseText}\n\n${geminiOutput}`;

        // Save the tool usage as a model message (conditional)
        await saveMessage(user.id, 'model', `[AI Tool: ${toolType}]\n${geminiOutput}`);

        return res.json({ text: finalResponse });

    } catch (err) {
        console.error(`Gemini Tool API Error (${toolType}):`, err.message);
        return res.status(500).json({ error: `Failed to execute AI tool ${toolType}.` });
    }
});


// ------------ Admin / utilities --------------

// Clear all memories for current user
app.post('/api/memory/clear', authMiddleware, rateLimiter, async (req, res) => {
  const user = req.user;
  if (!user) return res.status(401).json({ text: 'Authentication required' });
  if (!useMongo || !Memory) return res.status(500).json({ text: 'Memory not enabled.' });

  try {
    await Memory.deleteMany({ userId: user.id });
    return res.json({ text: 'All memories cleared.' });
  } catch (err) {
    console.error('Memory clear error:', err.message);
    return res.status(500).json({ text: 'Failed to clear memories.' });
  }
});

// Get last N messages (admin-ish)
app.get('/api/messages/recent', rateLimiter, async (req, res) => {
  if (!useMongo || !Message) return res.status(500).json({ text: 'Messages require MongoDB.' });
  const n = Math.min(100, Math.max(1, parseInt(req.query.n || '20', 10)));
  try {
    const msgs = await Message.find().sort({ createdAt: -1 }).limit(n).lean();
    return res.json({ messages: msgs });
  } catch (err) {
    console.error('Recent messages error:', err.message);
    return res.status(500).json({ text: 'Failed to read recent messages.' });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});