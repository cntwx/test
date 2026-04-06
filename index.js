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

/* =========================
   AUTH
========================= */
// Register
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

// Login
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

// Get current user
app.get('/auth/me', authMiddleware, (req, res) => {
    connection.query('SELECT id, fname, lname, username, avatar, role FROM users WHERE id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        res.json(rows[0]);
    });
});

/* =========================
   PLACES
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

/* =========================
   REVIEWS
========================= */
app.get('/reviews/:placeId', (req, res) => {
    const { placeId } = req.params;
    connection.query(
        'SELECT r.*, u.fname, u.lname, u.avatar FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.place_id = ? ORDER BY r.id DESC',
        [placeId],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json(rows);
        }
    );
});

app.post('/reviews', authMiddleware, (req, res) => {
    const { place_id, rating, comment } = req.body;
    connection.query(
        'INSERT INTO reviews (place_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
        [place_id, req.user.id, rating, comment],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'รีวิวถูกบันทึกแล้ว', reviewId: result.insertId });
        }
    );
});

/* =========================
   COMMENTS
========================= */
app.get('/comments/:reviewId', (req, res) => {
    const { reviewId } = req.params;
    connection.query(
        'SELECT c.*, u.fname, u.lname, u.avatar FROM comments c JOIN users u ON c.user_id = u.id WHERE c.review_id = ? ORDER BY c.id ASC',
        [reviewId],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json(rows);
        }
    );
});

app.post('/comments', authMiddleware, (req, res) => {
    const { review_id, comment } = req.body;
    connection.query(
        'INSERT INTO comments (review_id, user_id, comment) VALUES (?, ?, ?)',
        [review_id, req.user.id, comment],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'คอมเมนต์ถูกบันทึกแล้ว', commentId: result.insertId });
        }
    );
});

/* =========================
   LIKES
========================= */
app.post('/likes', authMiddleware, (req, res) => {
    const { review_id } = req.body;
    connection.query(
        'INSERT INTO likes (review_id, user_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE id=id',
        [review_id, req.user.id],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ message: 'กดไลค์แล้ว' });
        }
    );
});

/* =========================
   STATIC FILES + SPA FALLBACK
========================= */
app.use(express.static(path.join(__dirname, 'public')));

// SPA fallback (ไม่ทำให้เกิด PathError)
app.get('*', (req, res) => {
    if (
        req.path.startsWith('/auth') ||
        req.path.startsWith('/places') ||
        req.path.startsWith('/reviews') ||
        req.path.startsWith('/comments') ||
        req.path.startsWith('/likes')
    ) {
        return res.status(404).json({ message: 'API not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

module.exports = app;