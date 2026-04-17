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

/* ========================= AUTH MIDDLEWARE ========================= */
function authMiddleware(req, res, next) {

    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'กรุณาเข้าสู่ระบบก่อน' });
    }

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

    if (!fname || !lname || !username || !password) {
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });
    }

    connection.query(
        'SELECT id FROM users WHERE username = ?',
        [username],
        async (err, rows) => {

            if (err) return res.status(500).json({ message: err.message });

            if (rows.length > 0) {
                return res.status(400).json({ message: 'อีเมลนี้ถูกใช้งานแล้ว' });
            }

            const hashed = await bcrypt.hash(password, 10);

            const avatar =
                `https://ui-avatars.com/api/?name=${fname}+${lname}&background=1A7A6E&color=fff`;

            connection.query(
                'INSERT INTO users (fname,lname,username,password,avatar) VALUES (?,?,?,?,?)',
                [fname, lname, username, hashed, avatar],
                (err, result) => {

                    if (err) return res.status(500).json({ message: err.message });

                    res.status(201).json({
                        message: 'สมัครสมาชิกสำเร็จ',
                        userId: result.insertId
                    });
                }
            );
        }
    );
});

app.post('/auth/login', (req, res) => {

    const { username, password } = req.body;

    connection.query(
        'SELECT * FROM users WHERE username = ?',
        [username],
        async (err, rows) => {

            if (err) return res.status(500).json({ message: err.message });

            if (rows.length === 0) {
                return res.status(401).json({ message: 'ไม่พบผู้ใช้งาน' });
            }

            const user = rows[0];

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    fname: user.fname,
                    lname: user.lname,
                    username: user.username,
                    avatar: user.avatar,
                    role: user.role || 'user'
                },
                JWT_SECRET,
                { expiresIn: '7d' }
            );

            res.json({
                message: 'เข้าสู่ระบบสำเร็จ',
                token,
                user: {
                    id: user.id,
                    fname: user.fname,
                    lname: user.lname,
                    username: user.username,
                    avatar: user.avatar,
                    role: user.role || 'user'
                }
            });
        }
    );
});

app.get('/auth/me', authMiddleware, (req, res) => {

    connection.query(
        'SELECT id,fname,lname,username,avatar,role FROM users WHERE id = ?',
        [req.user.id],
        (err, rows) => {

            if (err) return res.status(500).json({ message: err.message });

            if (rows.length === 0) {
                return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
            }

            res.json(rows[0]);
        }
    );
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

app.post('/places', authMiddleware, upload.single("image"), (req, res) => {

    const { name, province, category, description } = req.body;

    const image = req.file ? `/uploads/${req.file.filename}` : "";

    if (!name || !province || !category || !description) {
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });
    }

    connection.query(
        'INSERT INTO places (name,province,category,description,image,created_by) VALUES (?,?,?,?,?,?)',
        [name, province, category, description, image, req.user.id],
        (err, result) => {

            if (err) return res.status(500).json({ message: err.message });

            res.status(201).json({
                message: 'เพิ่มสถานที่สำเร็จ',
                id: result.insertId
            });
        }
    );
});

/* ========================= STATIC FILES ========================= */

app.use(express.static(path.join(__dirname, 'public')));

app.use("/uploads", express.static(uploadPath));

/* ========================= SPA ROUTE ========================= */

app.get('/{*path}', (req, res) => {

    const apiPaths = ['/auth', '/places', '/reviews', '/comments', '/likes'];

    if (apiPaths.some(p => req.path.startsWith(p))) {
        return res.status(404).json({ message: 'API not found' });
    }

    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

/* ========================= SERVER ========================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});

module.exports = app;