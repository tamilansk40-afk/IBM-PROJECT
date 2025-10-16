// USER AUTHENTICATION SYSTEM - ADVANCED VERSION
// Run commands:


const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');

dotenv.config();
const app = express();
app.use(bodyParser.json());

const SECRET = process.env.JWT_SECRET || 'secret_key';
const PORT = process.env.PORT || 5000;

// Initialize DB
const db = new sqlite3.Database('./auth_system.db');
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
)`);

// Register Route
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields required' });

  const hashed = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
    [name, email.toLowerCase(), hashed, role || 'user'],
    (err) => {
      if (err) return res.status(400).json({ error: 'Email already exists' });
      res.json({ message: 'User registered successfully' });
    }
  );
});

// Login Route
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  });
});

// Middleware: Authenticate Token
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Profile Route (Protected)
app.get('/profile', verifyToken, (req, res) => {
  db.get('SELECT id, name, email, role FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  });
});

// Admin Route
app.get('/admin/users', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  db.all('SELECT id, name, email, role FROM users', (err, users) => {
    res.json({ users });
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
