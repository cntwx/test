const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require("multer");
const fs = require("fs");
require('dotenv').config();

const app = express();

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

/* ========================= CREATE UPLOAD FOLDER ========================= */
const uploadPath = path.join(__dirname, "public/uploads");

if (!fs.existsSync(uploadPath)) {
    fs.mkdirSync(uploadPath, { recursive: true });
}

/* ========================= MULTER CONFIG ========================= */
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    }
});

const upload = multer({ storage });

/* ========================= DATABASE ========================= */
const connection = mysql.createConnection(process.env.DATABASE_URL);

connection.connect(err => {
    if (err) console.error('❌ DB connection failed:', err.message);
    else console.log('✅ DB connected');
});

const JWT_SECRET = process.env.JWT_SECRET || 'thailand_review_secret_2024';

/* ========================= MIDDLEWARE ========================= */
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

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'ไม่มีสิทธิ์' });
    next();
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
            'INSERT INTO users (fname,lname,username,password,avatar) VALUES (?,?,?,?,?)',
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
            message: 'เข้าสู่ระบบสำเร็จ', token,
            user: { id: user.id, fname: user.fname, lname: user.lname, username: user.username, avatar: user.avatar, role: user.role || 'user' }
        });
    });
});

app.get('/auth/me', authMiddleware, (req, res) => {
    connection.query('SELECT id,fname,lname,username,avatar,role FROM users WHERE id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        res.json(rows[0]);
    });
});

/* ========================= PLACES ========================= */

app.get('/places', (req, res) => {
    const { search, category } = req.query;
    let query = `
        SELECT p.*, 
        ROUND(AVG(r.rating),1) avg_rating,
        COUNT(r.id) review_count
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
        `SELECT p.*, ROUND(AVG(r.rating),1) AS avg_rating, COUNT(r.id) AS review_count
         FROM places p LEFT JOIN reviews r ON r.place_id = p.id
         WHERE p.id = ? GROUP BY p.id`,
        [req.params.id],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            if (rows.length === 0) return res.status(404).json({ message: 'ไม่พบสถานที่' });
            res.json(rows[0]);
        }
    );
});

/* POST /places — รองรับทั้ง upload ไฟล์และ URL */
app.post('/places', authMiddleware, upload.single("image"), (req, res) => {
    const { name, province, category, description, image: imageUrl } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : (imageUrl || "");

    if (!name || !province || !category || !description)
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });

    connection.query(
        'INSERT INTO places (name,province,category,description,image,created_by) VALUES (?,?,?,?,?,?)',
        [name, province, category, description, image, req.user.id],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'เพิ่มสถานที่สำเร็จ', id: result.insertId });
        }
    );
});

/* ★ PUT /places/:id — แก้ไขสถานที่ รองรับทั้ง upload ไฟล์และ URL */
app.put('/places/:id', authMiddleware, adminMiddleware, upload.single("image"), (req, res) => {
    const { id } = req.params;
    const { name, province, category, description, image: imageUrl } = req.body;

    if (!name || !province || !category || !description)
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });

    const image = req.file ? `/uploads/${req.file.filename}` : (imageUrl || null);

    const sql = image !== null
        ? 'UPDATE places SET name=?,province=?,category=?,description=?,image=? WHERE id=?'
        : 'UPDATE places SET name=?,province=?,category=?,description=? WHERE id=?';
    const params = image !== null
        ? [name, province, category, description, image, id]
        : [name, province, category, description, id];

    connection.query(sql, params, (err) => {
        if (err) return res.status(500).json({ message: err.message });
        res.json({ message: 'แก้ไขสถานที่สำเร็จ' });
    });
});

/* ★ DELETE /places/:id — ลบสถานที่ */
app.delete('/places/:id', authMiddleware, adminMiddleware, (req, res) => {
    connection.query('DELETE FROM places WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: err.message });
        res.json({ message: 'ลบสถานที่สำเร็จ' });
    });
});

/* ========================= REVIEWS ========================= */

/* ★ GET /reviews — admin ดูรีวิวทั้งหมด */
app.get('/reviews', authMiddleware, adminMiddleware, (req, res) => {
    connection.query(
        `SELECT rv.*, u.fname, u.lname, p.name AS place_name
         FROM reviews rv
         JOIN users u ON u.id = rv.user_id
         JOIN places p ON p.id = rv.place_id
         ORDER BY rv.created_at DESC`,
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json(rows);
        }
    );
});

app.get('/reviews/place/:placeId', (req, res) => {
    connection.query(
        `SELECT rv.*, u.fname, u.lname, u.avatar,
         (SELECT COUNT(*) FROM likes lk WHERE lk.review_id = rv.id) AS like_count
         FROM reviews rv
         JOIN users u ON u.id = rv.user_id
         WHERE rv.place_id = ?
         ORDER BY rv.created_at DESC`,
        [req.params.placeId],
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
        'INSERT INTO reviews (place_id, user_id, title, content, rating) VALUES (?,?,?,?,?)',
        [place_id, req.user.id, title, content, rating],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'เพิ่มรีวิวสำเร็จ', id: result.insertId });
        }
    );
});

app.delete('/reviews/:id', authMiddleware, (req, res) => {
    connection.query('SELECT * FROM reviews WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length === 0) return res.status(404).json({ message: 'ไม่พบรีวิว' });
        if (rows[0].user_id !== req.user.id && req.user.role !== 'admin')
            return res.status(403).json({ message: 'ไม่มีสิทธิ์ลบรีวิวนี้' });

        connection.query('DELETE FROM reviews WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ message: 'ลบรีวิวสำเร็จ' });
        });
    });
});

/* ========================= COMMENTS ========================= */

app.get('/comments/review/:reviewId', (req, res) => {
    connection.query(
        `SELECT c.*, u.fname, u.lname, u.avatar
         FROM comments c JOIN users u ON u.id = c.user_id
         WHERE c.review_id = ? ORDER BY c.created_at ASC`,
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
        'INSERT INTO comments (review_id, user_id, content) VALUES (?,?,?)',
        [review_id, req.user.id, content],
        (err, result) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ message: 'เพิ่มคอมเมนต์สำเร็จ', id: result.insertId });
        }
    );
});

app.delete('/comments/:id', authMiddleware, (req, res) => {
    connection.query('SELECT * FROM comments WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ message: err.message });
        if (rows.length === 0) return res.status(404).json({ message: 'ไม่พบคอมเมนต์' });
        if (rows[0].user_id !== req.user.id && req.user.role !== 'admin')
            return res.status(403).json({ message: 'ไม่มีสิทธิ์ลบคอมเมนต์นี้' });

        connection.query('DELETE FROM comments WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ message: 'ลบคอมเมนต์สำเร็จ' });
        });
    });
});

/* ========================= LIKES ========================= */

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

app.post('/likes/:reviewId', authMiddleware, (req, res) => {
    const { reviewId } = req.params;
    connection.query(
        'SELECT id FROM likes WHERE review_id = ? AND user_id = ?',
        [reviewId, req.user.id],
        (err, rows) => {
            if (err) return res.status(500).json({ message: err.message });
            if (rows.length > 0) {
                connection.query('DELETE FROM likes WHERE review_id = ? AND user_id = ?', [reviewId, req.user.id], (err) => {
                    if (err) return res.status(500).json({ message: err.message });
                    res.json({ liked: false });
                });
            } else {
                connection.query('INSERT INTO likes (review_id, user_id) VALUES (?,?)', [reviewId, req.user.id], (err) => {
                    if (err) return res.status(500).json({ message: err.message });
                    res.json({ liked: true });
                });
            }
        }
    );
});

/* ========================= STATIC FILES ========================= */

app.use(express.static(path.join(__dirname, 'public')));
app.use("/uploads", express.static(uploadPath));

/* ========================= SPA ROUTE (ต้องอยู่สุดท้ายเสมอ) ========================= */

app.get('/{*path}', (req, res) => {
    const apiPaths = ['/auth', '/places', '/reviews', '/comments', '/likes'];
    if (apiPaths.some(p => req.path.startsWith(p))) {
        return res.status(404).json({ message: 'API not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

/* ========================= SERVER ========================= */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
module.exports = app;