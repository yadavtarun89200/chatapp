const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Define allowed origins
const allowedOrigins = ['http://localhost:3000', 'https://textbytarun.vercel.app'];

const app = express();
app.use(cors({
    origin: allowedOrigins,
    methods: ["GET", "POST"]
}));
app.use(express.json());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST"]
    }
});

// Route for serving the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API routes for authentication
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if username already exists
        const { data: existingUsername } = await supabase
            .from('users')
            .select('username')
            .eq('username', username)
            .single();
            
        if (existingUsername) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Check if email already exists
        const { data: existingEmail } = await supabase
            .from('users')
            .select('email')
            .eq('email', email)
            .single();
            
        if (existingEmail) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log('Hashed Password:', hashedPassword); // Log the hashed password
        
        // Insert the new user
        const { data, error } = await supabase
            .from('users')
            .insert([
                { username, email, password: hashedPassword }
            ]);
            
        if (error) throw error;
        
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Signup failed' });
    }
});

// Connected users tracking
const connectedUsers = new Map();

io.on('connection', (socket) => {
    console.log('New client connected');

    // Auto-login handler (for session persistence)
    socket.on('auto-login', async (userData) => {
        const { username, userId } = userData;
        
        // Verify user exists in database
        const { data: user, error } = await supabase
            .from('users')
            .select('id')
            .eq('id', userId)
            .eq('username', username)
            .single();
            
        if (error || !user) {
            return socket.emit('auth-error', 'Session expired, please login again');
        }
        
        // Store user info with socket
        socket.username = username;
        socket.userId = userId;
        connectedUsers.set(socket.id, username);

        // Broadcast to other users
        socket.broadcast.emit('user-connected', username);

        // Send current online users
        io.emit('online-users', Array.from(connectedUsers.values()));
        
        // Load recent messages
        const { data: messages } = await supabase
            .from('messages')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(50);
            
        if (messages) {
            // Send recent messages to the newly connected user
            socket.emit('load-messages', messages.reverse());
        }
    });

    // Login handler
    socket.on('login', async (credentials) => {
        try {
            const { username, password } = credentials;
            
            // Get user from Supabase
            const { data: user, error } = await supabase
                .from('users')
                .select('*')
                .eq('username', username)
                .single();
                
            if (error || !user) {
                return socket.emit('login-error', 'Invalid credentials');
            }
            
            // Compare password with hashed password
            const passwordMatch = await bcrypt.compare(password, user.password);
            console.log('Password Match:', passwordMatch); // Log the result of the password comparison

            if (!passwordMatch) {
                return socket.emit('login-error', 'Invalid credentials');
            }
            
            // Store user info with socket
            socket.username = username;
            socket.userId = user.id;
            connectedUsers.set(socket.id, username);

            // Send login success
            socket.emit('login-success', { username, userId: user.id });

            // Broadcast to other users
            socket.broadcast.emit('user-connected', username);

            // Send current online users
            io.emit('online-users', Array.from(connectedUsers.values()));
            
            // Load recent messages
            const { data: messages } = await supabase
                .from('messages')
                .select('*')
                .order('created_at', { ascending: false })
                .limit(50);
                
            if (messages) {
                // Send recent messages to the newly connected user
                socket.emit('load-messages', messages.reverse());
            }
        } catch (error) {
            console.error('Login error:', error);
            socket.emit('login-error', 'An error occurred during login');
        }
    });

    // Message handler with confirmation
    socket.on('send-message', async (message) => {
        try {
            if (!socket.username || !socket.userId) return;
            
            // Store message in Supabase
            const timestamp = new Date().toISOString();
            const { data, error } = await supabase
                .from('messages')
                .insert([
                    { 
                        user_id: socket.userId,
                        username: socket.username,
                        message,
                        created_at: timestamp
                    }
                ])
                .select(); // Add select() to get the inserted data with IDs
                
            if (error) throw error;
            
            // Confirm to sender that message was stored
            socket.emit('message-stored', {
                id: data?.[0]?.id,
                timestamp
            });
            
            // Broadcast message to all connected clients except sender
            socket.broadcast.emit('chat-message', { 
                username: socket.username, 
                message,
                timestamp
            });
        } catch (error) {
            console.error('Message error:', error);
            socket.emit('message-error', 'Failed to send message');
        }
    });

    // Logout handler
    socket.on('logout', () => {
        if (socket.username) {
            // Broadcast user disconnection
            socket.broadcast.emit('user-disconnected', socket.username);
            
            // Remove user from connected users
            connectedUsers.delete(socket.id);
            
            // Update online users list
            io.emit('online-users', Array.from(connectedUsers.values()));
            
            // Clear socket user data
            socket.username = null;
            socket.userId = null;
            
            // Confirm logout
            socket.emit('logout-success');
        }
    });

    // Disconnect handler
    socket.on('disconnect', () => {
        if (socket.username) {
            // Remove user from connected users
            connectedUsers.delete(socket.id);

            // Broadcast user disconnection
            socket.broadcast.emit('user-disconnected', socket.username);

            // Update online users list
            io.emit('online-users', Array.from(connectedUsers.values()));
        }
    });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Chat server running on port ${PORT}`);
});
