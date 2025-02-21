// Manage HTTP endpoints for APIs
const express = require('express');

// Encrypt password
const bcrypt = require('bcryptjs');

// Generate unique token
const jwt = require('jsonwebtoken');

// Send email
const { MailtrapClient } = require('mailtrap');
require('dotenv').config();



// Express.js
const client = express();
const port = process.env.EXPRESS_PORT;

client.use(express.json());

// PostgreSQL
const { Client } = require('pg');

const database = new Client({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    port: process.env.DB_PORT,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

database.connect().then(() => console.log(`Connected to database '${database.user}' on port '${database.port}'`));

// [TODO] Create database query manually without pgAdmin

// Mailtrap
const mail = new MailtrapClient({ token: process.env.MAILTRAP_API_KEY });
const sender = { name: "MessagingSystem", email: process.env.DEFAULT_EMAIL };



client.get('/', (req, res) => {
    res.send('Welcome to MessagingSystem. If you can read this message, that means our server is active and running with Status Code 200!');
});

client.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // const userExist = await database.query('SELECT * FROM "user" WHERE user_name = $1 OR user_email = $2', [username, email]);
        // if (userExist.rows.length > 0) return res.status(400).json({ error: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const verifyStatus = false;

        const query = 'INSERT INTO "user" (user_name, user_email, user_password, user_role, user_verified) VALUES ($1, $2, $3, $4, $5) RETURNING user_id';

        database.query(query, [username, email, hashedPassword, "Normal User", verifyStatus], (err, result) => {
            if (err) {
                console.error(err);
                res.status(500).json({ error: 'Error registering user' });
            } else {
                console.log(result);
                res.status(201).json({ message: 'User registered successfully' });

                const id = result.rows[0].user_id;
                const token = jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '15m' });

                const link = `http://localhost:${port}/verify?token=${token}`;

                mail.send({
                    from: sender,
                    to: [{ email: email }],
                    subject: "Verify Your Email",
                    html: `Welcome <b>${username}</b> to MessagingSystem! <br><br><br> Please click <a href="${link}">here</a> to verify your account <br><br><br> This is an auto-generated email. Please do not reply to this message. <br> If you have any questions, please contact our support team at support@demomailtrap.com.`
                })
                .then(console.log)
                .catch(console.error);
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

client.post('/verify', async (req, res) => {
    // [TODO] Add a response message UI in HTML when user clicks link
    const { token } = req.query;

    try {
        const { id } = jwt.verify(token, process.env.JWT_SECRET);

        const fetch = await database.query('SELECT * FROM "user" WHERE user_id = $1', [id]);
        const user = fetch.rows[0];

        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.user_verified) return res.status(400).json({ message: 'User already verified' });

        await database.query('UPDATE "user" SET user_verified = $1 WHERE user_id = $2', [true, id]);

        res.status(200).json({ message: 'Successfully verified email' });
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: 'Invalid or expired token' });
    }
});

client.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const fetch = await database.query('SELECT * FROM "user" WHERE user_name = $1', [username]);
 
        if (fetch.rows.length === 0) return res.status(401).json({ error: "Username is incorrect" });

        const validPassword = await bcrypt.compare(password, fetch.rows[0].user_password);
        if (!validPassword) return res.status(401).json({ error: "Invalid password" });

        const user = fetch.rows[0];
        if (!user.user_verified) return res.status(403).json({ error: "Email not verified" });

        const token = jwt.sign({ id: user.user_id, role: user.user_role, verified: user.user_verified }, process.env.JWT_SECRET);

        return res.status(200).header('Authorization', `Bearer ${token}`).json({ message: "Successfully logged in" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



client.listen(port, () => console.log(`Server started on port '${port}'`));
