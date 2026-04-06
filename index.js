// index.js
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();

// ===== CORS =====
// ต้องระบุ frontend domain จริง
app.use(cors({
    origin: [
        'https://test-f6nu.onrender.com', // frontend deploy
        'http://localhost:3000'           // dev local
    ],
    credentials: true
}));

// ===== JSON parser =====
app.use(express.json());

// ===== DATABASE =====
const connection = mysql.createConnection(process.env.DATABASE_URL);
connection.connect((err) => {
    if (err) console.error('❌ DB connection failed:', err.message);
    else console.log('✅ DB connected');
});

// ===== JWT SECRET =====
const JWT_SECRET = process.env.JWT_SECRET || 'thailand_review_secret_2024';

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

/* =========================
   AUTH ROUTES
========================= */
app.post('/auth/register', async (req, res) => {
    const { fname, lname, username, password } = req.body;
    if (!fname || !lname || !username || !password)
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });

    connection.query('SELECT id FROM users WHERE username = ?', [username], async (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length > 0) return res.status(400).json({ message: 'อีเมลนี้ถูกใช้งานแล้ว' });

        const hashed = await bcrypt.hash(password, 10);
        const avatar = `https://ui-avatars.com/api/?name=${fname}+${lname}&background=1A7A6E&color=fff`;

        connection.query(
            'INSERT INTO users (fname, lname, username, password, avatar) VALUES (?, ?, ?, ?, ?)',
            [fname, lname, username, hashed, avatar],
            (err, result) => {
                if (err) return res.status(500).json({ message: err.message });
                res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ', userId: result.insertId });
            }
        );
    });
});

app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    connection.query('SELECT * FROM users WHERE username = ?', [username], async (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length === 0) return res.status(401).json({ message: 'ไม่พบผู้ใช้งาน' });

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });

        const token = jwt.sign(
            { id: user.id, fname: user.fname, lname: user.lname, username: user.username, avatar: user.avatar, role: user.role || 'user' },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({
            message: 'เข้าสู่ระบบสำเร็จ',
            token,
            user: { id: user.id, fname: user.fname, lname: user.lname, username: user.username, avatar: user.avatar, role: user.role || 'user' }
        });
    });
});

app.get('/auth/me', authMiddleware, (req, res) => {
    connection.query('SELECT id, fname, lname, username, avatar, role FROM users WHERE id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        res.json(rows[0]);
    });
});

/* =========================
   PLACES ROUTES
========================= */
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

app.get('/places/:id', (req, res) => {
    connection.query(
        `SELECT p.*, 
            ROUND(AVG(r.rating),1) as avg_rating,
            COUNT(DISTINCT r.id) as review_count
        FROM places p
        LEFT JOIN reviews r ON r.place_id = p.id
        WHERE p.id = ?
        GROUP BY p.id`,
        [req.params.id],
        (err, results) => {
            if (err) return res.status(500).json({ message: err.message });
            if (!results[0]) return res.status(404).json({ message: 'ไม่พบสถานที่' });
            res.json(results[0]);
        }
    );
});

/* =========================
   REVIEWS ROUTES
========================= */
app.get('/reviews/place/:placeId', (req, res) => {
    connection.query(
        `SELECT r.*, u.fname, u.lname, u.avatar,
            COUNT(DISTINCT l.id) as like_count
        FROM reviews r
        JOIN users u ON u.id = r.user_id
        LEFT JOIN likes l ON l.review_id = r.id
        WHERE r.place_id = ?
        GROUP BY r.id
        ORDER BY r.created_at DESC`,
        [req.params.placeId],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json(rows);
        }
    );
});

/* =========================
   COMMENTS & LIKES ROUTES
========================= */
// ใส่เหมือนตัวก่อนหน้า...

/* =========================
   STATIC FILES + SPA FALLBACK
========================= */
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    // ถ้า request เป็น API ให้ next()
    if (req.path.startsWith('/auth') ||
        req.path.startsWith('/places') ||
        req.path.startsWith('/reviews') ||
        req.path.startsWith('/comments') ||
        req.path.startsWith('/likes')) {
        return next();
    }
    // ไม่ใช่ API → ส่งหน้า SPA
    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

module.exports = app;