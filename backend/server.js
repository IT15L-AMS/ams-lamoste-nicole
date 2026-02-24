const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
require('dotenv').config();
const { authenticateToken } = require('./middleware/authMiddleware');

const app = express();
app.use(cors());
app.use(express.json());


app.post('/auth/register', async (req, res) => {
    try {
        const { full_name, email, password, role_id } = req.body;

        if (!full_name || !email || !password || !role_id) {
            return res.status(400).json({ error: "All fields are required" });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const sql = "INSERT INTO users (full_name, email, password, role_id) VALUES (?, ?, ?, ?)";
        
        db.query(sql, [full_name, email, hashedPassword, role_id], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ error: "Email already exists" });
                }
                return res.status(500).json({ error: "Database error" });
            }
            res.status(201).json({ message: "User registered successfully!" });
        });

    } catch (error) {
        res.status(500).json({ error: "Server error during registration" });
    }
});


app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        
        if (results.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const user = results[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: user.id, role_id: user.role_id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '2h' } 
        );

        res.status(200).json({ 
            success: true,
            message: "Login successful!", 
            token: token 
        });
    });
});


app.get('/auth/profile', authenticateToken, (req, res) => {
    
    const sql = "SELECT id, full_name, email, role_id, created_at FROM users WHERE id = ?";
    
    db.query(sql, [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "User not found" });

        res.status(200).json({
            message: "Welcome to your protected profile!",
            user: results[0]
        });
    });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});