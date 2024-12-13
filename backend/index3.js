const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const SESSION_SECRET = 'your-secret-key';

// Session middleware
app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }, // Use secure: true in production
    })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: 'YOUR_GOOGLE_CLIENT_ID',
            clientSecret: 'YOUR_GOOGLE_CLIENT_SECRET',
            callbackURL: 'http://localhost:3000/auth/google/callback',
        },
        (accessToken, refreshToken, profile, done) => {
            return done(null, profile);
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/'); // Redirect to home after login
    }
);

// Endpoint to check session
app.get('/session', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ authenticated: true, user: req.user });
    } else {
        res.json({ authenticated: false });
    }
});

// RSA key generation
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

app.get('/public-key', (req, res) => {
    res.send(publicKey.export({ type: 'pkcs1', format: 'pem' }));
});

// WebSocket handling
const clients = new Map();

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Authenticate clients via session ID
    socket.on('authenticate', (sessionId) => {
        // Validate session (you can integrate a database here)
        if (sessionId) {
            console.log(`Session ID received: ${sessionId}`);
            socket.authenticated = true;
        } else {
            socket.authenticated = false;
        }
    });

    // Handle encrypted messages
    socket.on('send-message', (encryptedMessage) => {
        if (!socket.authenticated) {
            console.log('Unauthenticated message attempt');
            return;
        }

        const decryptedMessage = crypto.privateDecrypt(
            privateKey,
            Buffer.from(encryptedMessage, 'base64')
        );
        console.log('Decrypted message:', decryptedMessage.toString());

        // Broadcast to authenticated clients
        clients.forEach((clientKey, clientId) => {
            if (clientId !== socket.id) {
                const encryptedForClient = crypto.publicEncrypt(
                    clientKey,
                    Buffer.from(decryptedMessage)
                );
                io.to(clientId).emit('receive-message', encryptedForClient.toString('base64'));
            }
        });
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        clients.delete(socket.id);
    });
});

server.listen(3000, () => {
    console.log('Server listening on port 3000');
});
