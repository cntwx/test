const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// ===== DATABASE =====
const connection = mysql.createConnection(process.env.DATABASE_URL);
connection.connect(err => {
    if (err) console.error('❌ DB connection failed:', err.message);
    else console.log('✅ DB connected');
});

const JWT_SECRET = process.env.JWT_SECRET || 'thailand_review_secret_2024';

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

/* ========================= AUTH ========================= */
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

/* ========================= PLACES ========================= */
app.get('/places', (req, res) => {
    const { search, category } = req.query;
    let query = `
        SELECT p.id, p.name, p.province, p.category, p.description, p.image, p.created_by,
            ROUND(AVG(r.rating), 1) as avg_rating,
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
    query += ' GROUP BY p.id, p.name, p.province, p.category, p.description, p.image, p.created_by ORDER BY p.id DESC';

    connection.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: err.message });
        res.json(results);
    });
});

app.get('/places/:id', (req, res) => {
    connection.query(
        `SELECT p.id, p.name, p.province, p.category, p.description, p.image, p.created_by,
            ROUND(AVG(r.rating), 1) as avg_rating,
            COUNT(DISTINCT r.id) as review_count
        FROM places p
        LEFT JOIN reviews r ON r.place_id = p.id
        WHERE p.id = ?
        GROUP BY p.id, p.name, p.province, p.category, p.description, p.image, p.created_by`,
        [req.params.id],
        (err, results) => {
            if (err) return res.status(500).json({ message: err.message });
            if (!results[0]) return res.status(404).json({ message: 'ไม่พบสถานที่' });
            res.json(results[0]);
        }
    );
});

app.post('/places', authMiddleware, (req, res) => {
    const { name, province, category, description, image } = req.body;
    if (!name || !province || !category || !description)
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });

    connection.query(
        'INSERT INTO places (name, province, category, description, image, created_by) VALUES (?, ?, ?, ?, ?, ?)',
        [name, province, category, description, image || '', req.user.id],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'เพิ่มสถานที่สำเร็จ', id: result.insertId });
        }
    );
});

app.put('/places/:id', authMiddleware, (req, res) => {
    const { name, province, category, description, image } = req.body;
    connection.query('SELECT created_by FROM places WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (!rows[0]) return res.status(404).json({ message: 'ไม่พบสถานที่' });
        if (req.user.role !== 'admin' && rows[0].created_by !== req.user.id)
            return res.status(403).json({ message: 'ไม่มีสิทธิ์แก้ไขสถานที่นี้' });

        connection.query(
            'UPDATE places SET name=?, province=?, category=?, description=?, image=? WHERE id=?',
            [name, province, category, description, image || '', req.params.id],
            (err) => {
                if (err) return res.status(500).json({ message: err.message });
                res.json({ message: 'แก้ไขสำเร็จ' });
            }
        );
    });
});

app.delete('/places/:id', authMiddleware, (req, res) => {
    connection.query('SELECT created_by FROM places WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (!rows[0]) return res.status(404).json({ message: 'ไม่พบสถานที่' });
        if (req.user.role !== 'admin' && rows[0].created_by !== req.user.id)
            return res.status(403).json({ message: 'ไม่มีสิทธิ์ลบสถานที่นี้' });

        connection.query('DELETE FROM places WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ message: 'ลบสำเร็จ' });
        });
    });
});

/* ========================= REVIEWS ========================= */
// ⚠️ /reviews/place/:placeId ต้องมาก่อน /reviews
app.get('/reviews/place/:placeId', (req, res) => {
    connection.query(
        `SELECT
            r.id, r.place_id, r.user_id, r.title, r.content, r.rating, r.created_at,
            u.fname, u.lname, u.avatar,
            COUNT(DISTINCT l.id) as like_count
        FROM reviews r
        JOIN users u ON u.id = r.user_id
        LEFT JOIN likes l ON l.review_id = r.id
        WHERE r.place_id = ?
        GROUP BY r.id, r.place_id, r.user_id, r.title, r.content, r.rating, r.created_at,
                 u.fname, u.lname, u.avatar
        ORDER BY r.created_at DESC`,
        [req.params.placeId],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json(rows);
        }
    );
});

app.get('/reviews', authMiddleware, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'ไม่มีสิทธิ์' });
    connection.query(
        `SELECT r.id, r.place_id, r.user_id, r.title, r.content, r.rating, r.created_at,
            u.fname, u.lname, p.name as place_name
        FROM reviews r
        JOIN users u ON u.id = r.user_id
        JOIN places p ON p.id = r.place_id
        ORDER BY r.created_at DESC`,
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json(rows);
        }
    );
});

app.post('/reviews', authMiddleware, (req, res) => {
    const { place_id, title, content, rating } = req.body;
    if (!place_id || !title || !content || !rating)
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });

    connection.query(
        'INSERT INTO reviews (place_id, user_id, title, content, rating) VALUES (?, ?, ?, ?, ?)',
        [place_id, req.user.id, title, content, rating],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'โพสรีวิวสำเร็จ', id: result.insertId });
        }
    );
});

app.delete('/reviews/:id', authMiddleware, (req, res) => {
    connection.query('SELECT * FROM reviews WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (!rows[0]) return res.status(404).json({ message: 'ไม่พบรีวิว' });
        if (rows[0].user_id !== req.user.id && req.user.role !== 'admin')
            return res.status(403).json({ message: 'ไม่มีสิทธิ์' });
        connection.query('DELETE FROM reviews WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ message: 'ลบสำเร็จ' });
        });
    });
});

/* ========================= COMMENTS ========================= */
app.get('/comments/review/:reviewId', (req, res) => {
    connection.query(
        `SELECT c.id, c.review_id, c.user_id, c.content, c.created_at,
            u.fname, u.lname, u.avatar
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.review_id = ?
        ORDER BY c.created_at ASC`,
        [req.params.reviewId],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json(rows);
        }
    );
});

app.post('/comments', authMiddleware, (req, res) => {
    const { review_id, content } = req.body;
    if (!review_id || !content)
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });
    connection.query(
        'INSERT INTO comments (review_id, user_id, content) VALUES (?, ?, ?)',
        [review_id, req.user.id, content],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'คอมเม้นสำเร็จ', id: result.insertId });
        }
    );
});

app.delete('/comments/:id', authMiddleware, (req, res) => {
    connection.query('SELECT * FROM comments WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (!rows[0]) return res.status(404).json({ message: 'ไม่พบคอมเม้น' });
        if (rows[0].user_id !== req.user.id && req.user.role !== 'admin')
            return res.status(403).json({ message: 'ไม่มีสิทธิ์' });
        connection.query('DELETE FROM comments WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ message: 'ลบสำเร็จ' });
        });
    });
});

/* ========================= LIKES ========================= */
app.post('/likes/:reviewId', authMiddleware, (req, res) => {
    const { reviewId } = req.params;
    const userId = req.user.id;
    connection.query('SELECT id FROM likes WHERE review_id = ? AND user_id = ?', [reviewId, userId], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length > 0) {
            connection.query('DELETE FROM likes WHERE review_id = ? AND user_id = ?', [reviewId, userId], (err) => {
                if (err) return res.status(500).json({ message: err.message });
                res.json({ liked: false });
            });
        } else {
            connection.query('INSERT INTO likes (review_id, user_id) VALUES (?, ?)', [reviewId, userId], (err) => {
                if (err) return res.status(500).json({ message: err.message });
                res.json({ liked: true });
            });
        }
    });
});

app.get('/likes/:reviewId/check', authMiddleware, (req, res) => {
    connection.query(
        'SELECT id FROM likes WHERE review_id = ? AND user_id = ?',
        [req.params.reviewId, req.user.id],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ liked: rows.length > 0 });
        }
    );
});

/* ========================= STATIC FILES ========================= */
app.use(express.static(path.join(__dirname, 'public')));

app.get('/{*path}', (req, res) => {
    const apiPaths = ['/auth', '/places', '/reviews', '/comments', '/likes'];
    if (apiPaths.some(p => req.path.startsWith(p))) {
        return res.status(404).json({ message: 'API not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

module.exports = app;