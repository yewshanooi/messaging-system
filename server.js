// Manage HTTP endpoints for APIs
const express = require('express');

// Encrypt password
const bcrypt = require('bcryptjs');

// Generate unique tokens
const jwt = require('jsonwebtoken');

// Get path for HTML pages
const path = require("path");

require('dotenv').config();



// Express.js
const client = express();
const port = process.env.EXPRESS_PORT;

// Middleware to parse JSON request body
client.use(express.json());
// Middleware to parse URL-encoded request body (such as HTML forms)
client.use(express.urlencoded({ extended: false }));

// PostgreSQL
const { Client } = require('pg');





let database;

async function dbConfig() {
    const main_database = new Client({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD
    });
    
    await main_database.connect();


    // Check whether 'messagingsystem' database exist
    const dbExist = await main_database.query(`SELECT datname FROM pg_catalog.pg_database WHERE datname = '${process.env.DB_NAME}'`);

    if (dbExist.rowCount === 0) {
        console.log('[Database] No database found. Creating a new database');
        await main_database.query(`CREATE DATABASE "${process.env.DB_NAME}";`);
        console.log(`Created database '${process.env.DB_NAME}' ✅`);
    } else {
        console.log(`[Database] '${process.env.DB_NAME}' database exist`);
    }

    await main_database.end();



    database = new Client({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
    });
    
    await database.connect().then(() => console.log(`[Database] Connected to database '${database.database}'`));


    // Check whether 'user' table exist
    const tbExist = await database.query(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'user');`);

    if (tbExist.rows[0].exists === false) {
        console.log("[Database] No table found. Creating a new table");
        await database.query(`
            CREATE TABLE "user" (
                user_id SERIAL PRIMARY KEY NOT NULL,
                user_name VARCHAR(255),
                user_email VARCHAR(255),
                user_password VARCHAR(255),
                user_role VARCHAR(255),
                user_verified BOOLEAN
            );`
        );
        console.log("Created table 'user' ✅")
    } else {
        console.log("[Database] 'user' table exist");
    }

    // await database.end();
}

dbConfig();





client.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './public/index.html'));
});

client.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, './public/register.html'));
});

client.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const userExist = await database.query('SELECT * FROM "user" WHERE user_name = $1 OR user_email = $2', [username, email]);
        if (userExist.rows.length > 0) return res.status(400).json({ error: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const verifyStatus = false;

        const query = 'INSERT INTO "user" (user_name, user_email, user_password, user_role, user_verified) VALUES ($1, $2, $3, $4, $5) RETURNING user_id';

        database.query(query, [username, email, hashedPassword, 'member', verifyStatus], (err, result) => {
            if (err) {
                console.error(err);
                res.status(500).json({ error: 'Error registering user' });
            } else {
                console.log(result);
                res.status(201).json({ message: 'User registered successfully' });

                const id = result.rows[0].user_id;
                const token = jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '15m' });

                const link = `http://localhost:${port}/verify?register_token=${token}`;

                console.log(`Welcome ${username} to MessagingSystem! Please verify your account: ${link}`);
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

client.get('/verify', async (req, res) => {
    const { register_token } = req.query;

    try {
        const { id } = jwt.verify(register_token, process.env.JWT_SECRET);

        const fetch = await database.query('SELECT * FROM "user" WHERE user_id = $1', [id]);
        const user = fetch.rows[0];

        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.user_verified) return res.status(400).json({ message: 'User already verified' });

        await database.query('UPDATE "user" SET user_verified = $1 WHERE user_id = $2', [true, id]);

        return res.status(200).sendFile(path.join(__dirname, "./public/verified.html"));
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: 'Invalid or expired token' });
    }
});

client.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, './public/login.html'));
});

client.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const fetch = await database.query('SELECT * FROM "user" WHERE user_name = $1', [username]);
 
        if (fetch.rows.length === 0) return res.status(401).json({ error: 'Username is incorrect' });

        const validPassword = await bcrypt.compare(password, fetch.rows[0].user_password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

        const user = fetch.rows[0];
        if (!user.user_verified) return res.status(403).json({ error: 'Email not verified' });

        const userdata = {
            id: user.user_id,
            role: user.user_role
        };

        const user_token = jwt.sign({ userdata }, process.env.JWT_SECRET, { expiresIn: '1h' });

        return res.status(200).json({ message: 'Successfully logged in', user_token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

client.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, './public/chat.html'));
});

client.post('/chat', (req, res) => {
    try {
        const { message } = req.body;

        if (!message) return res.status(400).json({ message: 'You cannot send an empty message' })



        return res.status(200).json({ message: `Successfully send: ${message}` });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



client.listen(port, () => console.log(`Server started on port '${port}'`));
