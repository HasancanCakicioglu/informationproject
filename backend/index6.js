// Node.js backend with Express and Socket.IO
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const clients = new Map(); // Map to store public keys of connected clients

// Load users from a JSON file
const users = JSON.parse(fs.readFileSync('users.json', 'utf8'));

// Generate RSA key pair for the server
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// Endpoint to fetch server's public key
app.get('/public-key', (req, res) => {
    res.send(publicKey.export({ type: 'pkcs1', format: 'pem' }));
});

// Endpoint to handle login
app.use(express.json({ limit: '10kb' }));
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minute
    max: 1000, 
    message: 'Too many requests, please try again later.'
});
app.use(limiter);
app.use(cors({
    methods: ['GET', 'POST'], // İzin verilen HTTP yöntemleri
    credentials: true 
}));

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(
        (u) => u.username === username && u.password === password
    );

    if (user) {
        res.status(200).send({ success: true, message: 'Login successful' });
    } else {
        res.status(401).send({ success: false, message: 'Invalid credentials' });
    }
});

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Register client's public key
    socket.on('register-key', (clientPublicKey) => {
        clients.set(socket.id, clientPublicKey);
        console.log(`Public key registered for client ${socket.id}`);
    });

    // Receive an encrypted message and broadcast it
    socket.on('send-message', (encryptedMessage) => {
        const decryptedMessage = crypto.privateDecrypt(
            privateKey,
            Buffer.from(encryptedMessage, 'base64')
        );

        clients.forEach((clientKey, clientId) => {
            if (clientId !== socket.id) {
                const encryptedForClient = crypto.publicEncrypt(
                    clientKey,
                    Buffer.from(decryptedMessage)
                );
                io.to(clientId).emit(
                    'receive-message',
                    encryptedForClient.toString('base64')
                );
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