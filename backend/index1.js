const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const clients = new Map(); // Map to store public keys of connected clients

// Load users from users.json
const users = JSON.parse(fs.readFileSync('users.json'));
console.log('Users:', users);

// Generate RSA key pair for the server
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// Endpoint to fetch server's public key
app.get('/public-key', (req, res) => {
    res.send(publicKey.export({ type: 'pkcs1', format: 'pem' }));
});

// Handle login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);

    if (user) {
        res.send('Login successful');
        console.log(`User ${username} logged in successfully`);
    } else {
        res.status(401).send('Invalid username or password');
        console.log(`Login failed for user ${username}`);
    }
}
);

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Handle login
    socket.on('login', ({ username, password }) => {
        const user = users.find(u => u.username === username && u.password === password);
        console.log('User1:', user);

        if (user) {
            socket.emit('login-success', 'Login successful');
            console.log(`User ${username} logged in successfully`);
        } else {
            socket.emit('login-failure', 'Invalid username or password');
            console.log(`Login failed for user ${username}`);
            socket.disconnect();
        }
    });

    // Register client's public key
    socket.on('register-key', (clientPublicKey) => {
        clients.set(socket.id, clientPublicKey);
        console.log(`Public key registered for client ${socket.id}`);
    });

    // Receive an encrypted message and broadcast it
    socket.on('send-message', (encryptedMessage) => {
        console.log('1 Encrypted message:', encryptedMessage);
        const decryptedMessage = crypto.privateDecrypt(
            privateKey,
            Buffer.from(encryptedMessage, 'base64')
        );

        console.log('Decrypted message:', decryptedMessage.toString());

        // Broadcast encrypted message to all other clients
        console.log('Clients:', clients);
        clients.forEach((clientKey, clientId) => {
            console.log('2 Client key:', clientKey);
            if (clientId !== socket.id) {
                console.log('3 Client ID:', clientId);
                const encryptedForClient = crypto.publicEncrypt(
                    clientKey,
                    Buffer.from(decryptedMessage)
                );
                console.log('4 Encrypted for client:', encryptedForClient.toString('base64'));
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
