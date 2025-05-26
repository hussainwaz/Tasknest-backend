const express = require('express')
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(express.json());
const PORT = 1000;
app.use(cors());
require('dotenv').config();
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

//authentication
app.post('/users/signup', async (req, res) => {
    const { full_name, email, password } = req.body;

    if (!full_name || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    try {
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rowCount > 0) {
            return res.status(400).json({ success: false, message: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users(full_name, email, password) VALUES ($1, $2, $3)',
            [full_name, email, hashedPassword]
        );

        res.status(201).json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/users/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rowCount === 0) {
            return res.json({ success: false, message: "User not found" });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({ success: false, message: "Wrong password" });
        }

        res.json({ success: true, userId: user.user_id });
    } catch (error) {
        console.log(error);
        res.status(500).send('Server Error');
    }
});


//user
app.get('/users/:user_id', async (req, res) => {
    const userId = req.params.user_id; 
    try {
        const result = await pool.query(
            'SELECT user_id, full_name, email FROM users WHERE user_id = $1', 
            [userId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ 
                success: false, 
                message: "User not found"
            });
        }

        const userData = result.rows[0];
        res.status(200).json({ 
            success: true, 
            data: userData 
        });

    } catch (err) {
        console.error("Error fetching user:", err);
        res.status(500).json({ 
            success: false, 
            message: "Failed to fetch user data" 
        });
    }
});

app.get('/users/summary/:user_id', async (req, res) => {
  const userId = req.params.user_id;

  try {
    const result = await pool.query(
      `SELECT
        COUNT(CASE WHEN completed = true THEN 1 END) AS completed,
        COUNT(CASE WHEN completed = false AND 
             (due_date IS NULL OR due_date >= CURRENT_DATE) THEN 1 END) AS pending,
        COUNT(CASE WHEN completed = false AND 
             due_date < CURRENT_DATE THEN 1 END) AS overdue
       FROM tasks
       WHERE user_id = $1`,
      [userId]
    );

    res.status(200).json(result.rows[0]);

  } catch (err) {
    console.error("Error fetching task summary:", err);
    res.status(500).json({ 
      error: "Failed to fetch task summary" 
    });
  }
});
app.post('/user/resetpassword', async (req, res) => {
    const { user_id, old_password, new_password } = req.body;

    // Basic validation
    if (!user_id || !old_password || !new_password) {
        return res.status(400).json({
            success: false,
            message: "Missing required fields"
        });
    }

    try {
        // 1. Verify old password
        const user = await pool.query(
            'SELECT password FROM users WHERE user_id = $1',
            [user_id]
        );

        if (user.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const isMatch = await bcrypt.compare(old_password, user.rows[0].password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: "Old password is incorrect"
            });
        }

        // 2. Hash new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(new_password, saltRounds);

        // 3. Update password
        await pool.query(
            'UPDATE users SET password = $1 WHERE user_id = $2',
            [hashedPassword, user_id]
        );

        res.status(200).json({
            success: true,
            message: "Password updated successfully!"
        });

    } catch (err) {
        console.error("Error updating password:", err);
        res.status(500).json({
            success: false,
            message: "Server error during password update"
        });
    }
});

//notes
app.get('/notes/:userId', async (req, res) => {
    const userId = req.params.userId;
    try {
        const result = await pool.query('SELECT * FROM notes where user_id = $1', [userId]);
        res.json(result.rows);
    }
    catch (err) {
        console.log(err);
        res.status(500).send('Server Error');
    }
});



app.post('/notes', async (req, res) => {
    const { title, content, creation_date, user_id } = req.body;

    try {
        const result = await pool.query(
            'INSERT INTO notes(title, content, creation_date, user_id) VALUES ($1, $2, $3, $4) RETURNING *',
            [title, content, creation_date, user_id]
        );

        const newNote = result.rows[0];
        res.status(201).json({ success: true, note: newNote });
    } catch (err) {
        console.error("Error inserting note:", err);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


app.put('/notes/update', async (req, res) => {
    const { noteId, is_pinned } = req.body;
    try {
        await pool.query('UPDATE notes set is_pinned = $1 WHERE id = $2', [is_pinned, noteId]);
        res.status(201).send("Note Updated");
    }
    catch (err) {
        console.log(err);
        res.status(500).send("Server Error");
    }
});
app.delete('/notes/:id', async (req, res) => {
    const noteId = req.params.id;
    try {
        const result = await pool.query('DELETE FROM notes where id = $1', [noteId]);
        if (result.rowCount === 0) {
            return res.status(404).send('Note not found');
        }

        res.status(204).send();
    }
    catch (err) {
        console.log(err);
        res.status(500).send("Server Error");
    }
});

//tasks
app.put('/tasks/update', async (req, res) => {
    const { taskId, is_pinned, completed } = req.body;
    try {
        await pool.query('UPDATE tasks set is_pinned = $1, completed = $2 WHERE id = $3', [is_pinned, completed, taskId]);
        res.status(201).send("Task Updated");
    }
    catch (err) {
        console.log(err);
        res.status(500).send("Server Error");
    }
});



app.get('/tasks/:userId', async (req, res) => {
    const userId = req.params.userId;
    try {
        const result = await pool.query('SELECT * FROM tasks where user_id = $1', [userId]);
        res.json(result.rows);
    }
    catch (err) {
        console.log(err);
        res.status(500).send('Server Error');
    }
});
app.post('/tasks', async (req, res) => {
    const { title, description, creation_date, due_date, completed, user_id } = req.body;
    try {
        await pool.query('INSERT INTO tasks(title, description, creation_date, due_date, completed, user_id) VALUES ($1, $2, $3, $4, $5, $6)', [title, description, creation_date, due_date, completed, user_id]);
        res.status(201).send("Task added");
    }
    catch (err) {
        console.log(err);
        res.status(500).send("Server Error");
    }
});

app.delete('/tasks/:id', async (req, res) => {
    const taskId = req.params.id;
    try {
        const result = await pool.query('DELETE FROM tasks where id = $1', [taskId]);
        if (result.rowCount === 0) {
            return res.status(404).send('Task not found');
        }

        res.status(204).send();
    }
    catch (err) {
        console.log(err);
        res.status(500).send("Server Error");
    }
});


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});