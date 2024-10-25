const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = crypto.randomBytes(32);
const IV_LENGTH = 16;

// In-memory storage (replace with a database in production)
let passwords = [];

// Middleware to verify authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Encrypt data
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
}

// Decrypt data
function decrypt(text) {
    const [ivHex, encryptedHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Login endpoint
app.post('/login', (req, res) => {
    const { pin, password } = req.body;

    // Validate credentials (replace with your desired PIN and password)
    if (pin === '290310' && password === 'OwenBailey26') {
        const token = jwt.sign({ userId: 1 }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Get all passwords
app.get('/passwords', authenticateToken, (req, res) => {
    const decryptedPasswords = passwords.map(p => ({
        ...p,
        password: decrypt(p.password)
    }));
    res.json(decryptedPasswords);
});

// Get single password
app.get('/passwords/:id', authenticateToken, (req, res) => {
    const password = passwords.find(p => p.id === parseInt(req.params.id));
    if (!password) return res.status(404).json({ error: 'Password not found' });
    
    const decryptedPassword = {
        ...password,
        password: decrypt(password.password)
    };
    res.json(decryptedPassword);
});

// Create password
app.post('/passwords', authenticateToken, (req, res) => {
    const { email, password, link, notes } = req.body;
    const newPassword = {
        id: Date.now(),
        email,
        password: encrypt(password),
        link,
        notes
    };
    passwords.push(newPassword);
    res.status(201).json(newPassword);
});

// Update password
app.put('/passwords/:id', authenticateToken, (req, res) => {
    const { email, password, link, notes } = req.body;
    const index = passwords.findIndex(p => p.id === parseInt(req.params.id));
    
    if (index === -1) return res.status(404).json({ error: 'Password not found' });

    passwords[index] = {
        ...passwords[index],
        email,
        password: encrypt(password),
        link,
        notes
    };

    res.json(passwords[index]);
});

// Delete password
app.delete('/passwords/:id', authenticateToken, (req, res) => {
    const index = passwords.findIndex(p => p.id === parseInt(req.params.id));
    
    if (index === -1) return res.status(404).json({ error: 'Password not found' });
    
    passwords.splice(index, 1);
    res.sendStatus(204);
});

// Serve static files (HTML, CSS, JS)
app.use(express.static('public'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Server started successfully. Access the password manager at http://localhost:${PORT}`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});