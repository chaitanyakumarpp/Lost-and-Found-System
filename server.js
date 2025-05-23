//server.js
const path = require('path');
const http = require('http');
const bcrypt = require('bcrypt');
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cookieParser());
const server = http.createServer(app);

const port = 3000;
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
    console.log(`Received request: ${req.method} ${req.url}`);
    next();
});


// SQLite database connection
const db = new sqlite3.Database('lost_and_found.db', (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err);
    } else {
        console.log('Connected to SQLite database');

        // Create tables if they don't exist
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS lost_items (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                location_found TEXT NOT NULL,
                date_found DATE NOT NULL,
                category TEXT
            )
        
        `);
        console.log('Table structure:', db.exec("PRAGMA table_info('lost_items')"));


        db.run(`
            CREATE TABLE IF NOT EXISTS found_items (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                location_found TEXT NOT NULL,
                date_found DATE NOT NULL,
                finder_info TEXT,
                status TEXT
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS categories (
                category_id INTEGER PRIMARY KEY AUTOINCREMENT,
                category_name TEXT NOT NULL,
                description TEXT
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS locations (
                location_id INTEGER PRIMARY KEY AUTOINCREMENT,
                location_name TEXT NOT NULL,
                description TEXT
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                message TEXT NOT NULL,
                location_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                read_status BOOLEAN DEFAULT 0
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS real_time_updates (
                update_id INTEGER PRIMARY KEY AUTOINCREMENT,
                update_type TEXT NOT NULL,
                item_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Tables created');
    }
});

// Enable CORS for all routes
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*'); // Adjust as needed for your security requirements
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', true);

    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

app.use(bodyParser.json());

app.get('/index', (req, res) => {
    console.log('Received request for /index');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public','dashboard.html'));
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Function to send email to all registered users
async function sendEmailToUsers(subject, text) {
    try {
        // Retrieve all registered users' email addresses from the database
        const recipientEmails = await getAllUserEmails();

        // Compose the email message
        const mailOptions = {
            from: process.env.EMAIL_USERNAME,
            to: recipientEmails.join(','), // Join all email addresses separated by comma
            subject: subject,
            text: text
        };

        // Send the email
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
    } catch (error) {
        console.error('Error sending email to users:', error);
        throw error; // Re-throw the error to be caught by the caller
    }
}


// Function to send notification emails
async function sendNotificationEmail(message) {
    try {
        // Send notification email to all registered users
        await sendEmailToUsers('Notification', message);
    } catch (error) {
        console.error('Error sending notification email:', error);
        // Handle error, e.g., log it or return an appropriate response
    }
}

async function findExistingItem(table, description, location, date) {
    const query = `SELECT * FROM ${table} WHERE description = ? AND location_found = ? AND date_found = ?`;
    return new Promise((resolve, reject) => {
        db.get(query, [description, location, date], (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
}

app.post('/reportLostItem', async (req, res) => {
    const { lostCategory, lostDescription, lostLocation, lostDate } = req.body;

    try {
        // Check for missing fields
        if (!lostCategory || !lostDescription || !lostLocation || !lostDate) {
            return res.status(400).json({ message: 'Missing required fields.' });
        }

        // Check if the item already exists
        const existingItem = await findExistingItem('lost_items', lostDescription, lostLocation, lostDate);
        if (existingItem) {
            return res.status(400).json({ message: 'Item already reported as lost.' });
        }

        // Insert the lost item into the database
        db.run(
            'INSERT INTO lost_items (category, description, location_found, date_found) VALUES (?, ?, ?, ?)',
            [lostCategory, lostDescription, lostLocation, lostDate],
            async function (err) {
                if (err) {
                    console.error('Error reporting lost item:', err);
                    return res.status(500).json({
                        message: 'Lost item reporting failed. Please try again.',
                        error: err.message
                    });
                }

                console.log(`Lost item reported with ID: ${this.lastID}`);
                res.status(201).json({
                    message: 'Lost item reported successfully',
                    reportedItem: {
                        type: 'lost',
                        description: lostDescription,
                        location: lostLocation,
                        date: lostDate,
                        category: lostCategory
                    },
                });

                // Send notification email to all registered users
                const message = 'A new lost item has been reported. Please check the dashboard for more details.';
                await sendNotificationEmail(message);
            }
        );
    } catch (error) {
        console.error('Error reporting lost item:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/reportFoundItem', async (req, res) => {
    const { foundDescription, foundLocation, foundDate, finderInfo } = req.body;

    try {
        // Check for missing fields
        if (!foundDescription || !foundLocation || !foundDate || !finderInfo) {
            return res.status(400).json({ message: 'Missing required fields.' });
        }

        // Check if the item already exists
        const existingItem = await findExistingItem('found_items', foundDescription, foundLocation, foundDate);
        if (existingItem) {
            return res.status(400).json({ message: 'Item already reported as found.' });
        }

        // Insert the found item into the database
        db.run(
            'INSERT INTO found_items (description, location_found, date_found, finder_info) VALUES (?, ?, ?, ?)',
            [foundDescription, foundLocation, foundDate, finderInfo],
            async function (err) {
                if (err) {
                    console.error('Error reporting found item:', err);
                    return res.status(500).json({
                        message: 'Found item reporting failed. Please try again.',
                        error: err.message
                    });
                }

                console.log(`Found item reported with ID: ${this.lastID}`);
                res.status(201).json({
                    message: 'Found item reported successfully',
                    reportedItem: {
                        type: 'found',
                        description: foundDescription,
                        location: foundLocation,
                        date: foundDate,
                        finderInfo: finderInfo,
                    },
                });

                try {
                    // Send notification email to all registered users
                    const message = 'A new found item has been reported. Please check the dashboard for more details.';
                    await sendNotificationEmail(message);
                } catch (emailError) {
                    console.error('Error sending notification email:', emailError);
                    // Log the error, but don't return it to the client
                }
            }
        );
    } catch (error) {
        console.error('Error reporting found item:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
});


// Function to retrieve all registered users' email addresses from the database
async function getAllUserEmails() {
    try {
        // Make a database query to retrieve all user email addresses
        const emails = await new Promise((resolve, reject) => {
            db.all('SELECT email FROM users', (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows.map(row => row.email));
                }
            });
        });
        return emails;
    } catch (error) {
        console.error('Error retrieving user emails from database:', error);
        throw error; // Re-throw the error to be caught by the caller
    }
}

app.delete('/api/lost-items/:id', (req, res) => {
    const itemId = req.params.id;

    // Delete the item from the database
    db.run('DELETE FROM lost_items WHERE item_id = ?', [itemId], function(err) {
        if (err) {
            console.error('Error deleting item:', err);
            res.status(500).json({ message: 'Failed to delete item' });
        } else {
            if (this.changes > 0) {
                console.log('Item deleted successfully');
                res.status(200).json({ message: 'Item deleted successfully' });
            } else {
                res.status(404).json({ message: 'Item not found' });
            }
        }
    });
});



// Route to trigger sending notification emails to all registered users
app.post('/sendNotificationEmail', async (req, res) => {
    const { subject, message } = req.body;

    try {
        // Send notification email to all registered users
        await sendEmailToUsers(subject, message);
        res.status(200).json({ message: 'Notification emails sent successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send notification emails', details: error.message });
    }
});
    

app.get('/found_confirmation.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'found_confirmation.html'));
});


// Welcome Route (Corrected)
app.get('/', (req, res) => {
    res.redirect('/login'); // Redirect to the login page
});
app.get('/path/to/redirect', (req, res) => {
    // Handle the logic for this route
    res.send('This is the redirected page!');
});


// Login Route
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
// Register Route
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});
// User Registration Route
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    console.log('Received registration request:', { username, email });

    // Check if the username or email is already registered
    const existingUser = await checkExistingUser(username, email);
    if (existingUser) {
        console.log('Username or email already exists');
        return res.status(400).json({ error: 'Username or email already exists' });
    }
    

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    db.run('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
        [username, hashedPassword, email],
        function (err) {
            if (err) {
                console.error('Error registering user:', err);
                return res.status(500).json({ error: 'Internal server error. Please try again later.' });
            }

            console.log(`User registered with ID: ${this.lastID}`);
            res.status(201).json({ message: 'Registration successful' });
        }
    );
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Retrieve user from the database based on the provided username
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Error retrieving user:', err);
            return res.status(500).json({ error: 'Internal server error. Please try again later.' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // User authenticated successfully
        // Redirect to the index page or dashboard
        res.status(200).json({ success: true, message: 'Login successful', data: { userId: user.user_id, username: user.username } });
    });
});




async function getUserByUsername(username) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
            if (err) {
                reject(err);
            } else {
                resolve(user);
            }
        });
    });
}
async function checkExistingUser(username, email) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, user) => {
            if (err) {
                reject(err);
            } else {
                resolve(user);
            }
        });
    });
}

// Add a new route in your server code
// Add separate routes for lost items and found items
app.get('/api/lost-items', (req, res) => {
    const query = 'SELECT * FROM lost_items ORDER BY date_found DESC';
    db.all(query, (err, lostItems) => {
        if (err) {
            console.error('Error fetching lost items:', err);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json({ items: lostItems });
        }
    });
});

app.get('/api/found-items', (req, res) => {
    const query = 'SELECT * FROM found_items ORDER BY date_found DESC';
    db.all(query, (err, foundItems) => {
        if (err) {
            console.error('Error fetching found items:', err);
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json({ items: foundItems });
        }
    });
});

// Define a route for GET /dashboard
app.get('/dashboard', (req, res) => {
    // Send the HTML file or render it, depending on your setup
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});



// Helper function to check if a username or email is already registered
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error. Please try again later.' });
});

app.use((req, res, next) => {
    res.setHeader('Content-Type', 'application/json');
    next();
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
