// index.js
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();

// ===== DATABASE =====
const connection = mysql.createConnection(process.env.DATABASE_URL);

// ===== JWT SECRET =====
const JWT_SECRET = process.env.JWT_SECRET || 'thailand_review_secret_2024';

// ===== MIDDLEWARE =====
app.use(express.json());

// ===== CORS =====
app.use(cors({
    origin: [
        'https://test-f6nu.onrender.com', // frontend deploy จริง
        'http://localhost:5500'           // dev local
    ],
    credentials: true
}));

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'กรุณาเข้าสู่ระบบก่อน' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
    }
}

// ===== ROUTES =====
app.get('/', (req, res) => res.send('Thailand Review API is running 🌺'));

// --- AUTH, PLACES, REVIEWS, COMMENTS, LIKES ---
// ใส่โค้ด route เดิมทั้งหมดเหมือนเดิม เช่น /auth/register, /places, /reviews, etc.

app.get('/places', (req, res) => {
    const { search, category } = req.query;
    let query = `
        SELECT p.*, 
        ROUND(AVG(r.rating),1) as avg_rating,
        COUNT(DISTINCT r.id) as review_count
        FROM places p
        LEFT JOIN reviews r ON r.place_id = p.id
        WHERE 1=1
    `;
    const params = [];
    if (search) {
        query += ' AND (p.name LIKE ? OR p.province LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }
    if (category && category !== 'ทั้งหมด') {
        query += ' AND p.category = ?';
        params.push(category);
    }
    query += ' GROUP BY p.id ORDER BY p.id DESC';
    connection.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: err.message });
        res.json(results);
    });
});

// ===== STATIC FILES =====
app.use(express.static(path.join(__dirname, 'public')));

// fallback SPA - อย่าให้ override API
app.get('/:catchAll(.*)', (req, res) => {
    // skip API routes
    if (req.path.startsWith('/auth') || req.path.startsWith('/places') ||
        req.path.startsWith('/reviews') || req.path.startsWith('/comments') ||
        req.path.startsWith('/likes')) {
        return res.status(404).json({ message: 'API not found' });
    }

    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

// ===== START SERVER =====
app.listen(process.env.PORT || 3000, () => console.log('✅ Server running on port 3000'));