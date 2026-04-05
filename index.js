const express = require('express')
const cors = require('cors')
const mysql = require('mysql2')
require('dotenv').config()
const app = express()

app.use(cors())
app.use(express.json())

const connection = mysql.createConnection(process.env.DATABASE_URL)

// test route
app.get('/', (req, res) => {
    res.send('Places API is running')
})

/* =========================
   GET ALL PLACES
========================= */
app.get('/places', (req, res) => {
    connection.query(
        'SELECT * FROM places',
        (err, results) => {
            if (err) {
                console.error(err)
                return res.status(500).send(err)
            }
            res.json(results)
        }
    )
})

/* =========================
   GET PLACE BY ID
========================= */
app.get('/places/:id', (req, res) => {
    const id = req.params.id

    connection.query(
        'SELECT * FROM places WHERE id = ?',
        [id],
        (err, results) => {
            if (err) {
                console.error(err)
                return res.status(500).send(err)
            }
            res.json(results[0])
        }
    )
})

/* =========================
   CREATE PLACE
========================= */
app.post('/places', (req, res) => {

    const { name, province, category, description, image } = req.body

    connection.query(
        `INSERT INTO places 
        (name, province, category, description, image)
        VALUES (?, ?, ?, ?, ?)`,
        [name, province, category, description, image],
        (err, results) => {
            if (err) {
                console.error('POST ERROR:', err)
                return res.status(500).send(err)
            }
            res.json({
                message: "Place created",
                insertId: results.insertId
            })
        }
    )
})

/* =========================
   UPDATE PLACE
========================= */
app.put('/places/:id', (req, res) => {

    const id = req.params.id
    const { name, province, category, description, image } = req.body

    connection.query(
        `UPDATE places 
        SET name=?, province=?, category=?, description=?, image=? 
        WHERE id=?`,
        [name, province, category, description, image, id],
        (err, results) => {
            if (err) {
                console.error('PUT ERROR:', err)
                return res.status(500).send(err)
            }
            res.json({ message: "Place updated" })
        }
    )
})

/* =========================
   DELETE PLACE
========================= */
app.delete('/places/:id', (req, res) => {
    const id = req.params.id

    connection.query(
        'DELETE FROM places WHERE id=?',
        [id],
        (err, results) => {
            if (err) {
                console.error('DELETE ERROR:', err)
                return res.status(500).send(err)
            }
            res.json({ message: "Place deleted" })
        }
    )
})

app.listen(process.env.PORT || 3000, () => {
    console.log('Server running on port 3000')
})

module.exports = app;