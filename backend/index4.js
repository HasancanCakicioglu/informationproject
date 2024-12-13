const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const clients = new Map(); // Map to store public keys of connected clients
const users = JSON.parse(fs.readFileSync('users.json')); // Users data in JSON file

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
    const user = users[username];
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
            clients.set(socket.id, clientPublicKey);
            console.log(`Public key registered for client ${socket.id}`);
        }
    });

    // Receive an encrypted message and broadcast it
    socket.on('send-message', (encryptedMessage) => {
        if (!isAuthenticated) return;

        console.log('1 Encrypted message:', encryptedMessage);
        const decryptedMessage = crypto.privateDecrypt(
            privateKey,
            Buffer.from(encryptedMessage, 'base64')
        );
        console.log('Decrypted message:', decryptedMessage.toString());

        // Broadcast encrypted message to all other clients
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

    // Handle client disconnection
    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        clients.delete(socket.id);
    });
});

server.listen(3000, () => {
    console.log('Server listening on port 3000');
});
