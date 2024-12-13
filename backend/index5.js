const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// In-memory users data (replace with real database in production)
const users = JSON.parse(fs.readFileSync('users.json')); // Updated to match your structure

// Generate RSA key pair for the server
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// Endpoint to fetch server's public key
app.get('/public-key', (req, res) => {
    res.send(publicKey.export({ type: 'pkcs1', format: 'pem' }));
});

// Simple login system for verifying username and password
function verifyUser(username, encryptedPassword) {
    const user = users.find(u => u.username === username);
    if (user) {
        // Decrypt the password sent by client
        const decryptedPassword = crypto.privateDecrypt(
            privateKey,
            Buffer.from(encryptedPassword, 'base64')
        ).toString();

        // Verify password
        if (decryptedPassword === user.password) {
            return true;
        }
    }
    return false;
}

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    let isAuthenticated = false;

    // Handle user login with username and encrypted password
    socket.on('login', (data) => {
        const { username, encryptedPassword } = data;
        isAuthenticated = verifyUser(username, encryptedPassword);
        if (isAuthenticated) {
            socket.emit('login-success', 'Login successful');
            console.log(`${username} logged in successfully.`);
        } else {
            socket.emit('login-failure', 'Invalid username or password');
            console.log(`${username} failed to log in.`);
            socket.disconnect(); // Disconnect if login fails
        }
    });

    // Register client's public key
    socket.on('register-key', (clientPublicKey) => {
        if (isAuthenticated) {
            console.log(`Public key registered for client ${socket.id}`);
        }
    });

    // Receive an encrypted message and broadcast it
    socket.on('send-message', (encryptedMessage) => {
        if (!isAuthenticated) return;

        const decryptedMessage = crypto.privateDecrypt(
            privateKey,
            Buffer.from(encryptedMessage, 'base64')
        );

        // Broadcast encrypted message to all other clients
        io.emit('receive-message', encryptedMessage);
    });

    // Handle client disconnection
    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

server.listen(3000, () => {
    console.log('Server listening on port 3000');
});
