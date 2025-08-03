const express = require('express');
const mysql = require('mysql2');

const app = express();
const port = 3000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Replace with strong secret in real app
const JWT_SECRET = 'mustconnect_secret_key';

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token required' });

  jwt.verify(token, 'secret123', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });

    req.user = user; // Attach decoded token info (id, role) to request
    next();
  });
}

// Middleware to parse JSON bodies
app.use(express.json());
// Handle malformed JSON globally
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.error('Bad JSON:', err);
    return res.status(400).json({ error: 'Invalid or malformed JSON body.' });
  }
  next();
});

// MySQL connection setup
const db = mysql.createConnection({
  host: 'localhost',
  user: 'kelvin',
  password: 'test123',
  database: 'mustconnect'
});

db.connect(err => {
  if (err) {
    console.error('❌ Database connection failed:', err);
  } else {
    console.log('✅ Connected to MySQL!');
  }
});

// Sample welcome route
app.get('/', (req, res) => {
  res.send('Welcome to MustConnect backend!');
});

// Fetch all houses
app.get('/houses', (req, res) => {
  db.query('SELECT * FROM houses', (err, results) => {
    if (err) {
      console.error('❌ Error fetching houses:', err);
      return res.status(500).json({ error: 'Failed to fetch houses' });
    }
    res.json(results);
  });
});
app.get('/houses/landlord/:id', (req, res) => {
  const { id } = req.params;

  const sql = 'SELECT * FROM houses WHERE landlord_id = ?';

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error('❌ Error fetching houses:', err);
      return res.status(500).json({ error: 'Failed to fetch houses.' });
    }

    res.status(200).json(results);
  });
});

// Add a new house
// Add a new house
app.post('/houses', verifyToken, (req, res) => {
  if (req.user.role !== 'landlord') {
    return res.status(403).json({ error: 'Only landlords can add houses' });
  }

  const { location, price, description } = req.body;
  const landlord_id = req.user.id;

  const sql = 'INSERT INTO houses (landlord_id, location, price, description) VALUES (?, ?, ?, ?)';
  db.query(sql, [landlord_id, location, price, description], (err, result) => {
    if (err) {
      console.error('Add house error:', err);
      return res.status(500).json({ error: 'Failed to add house' });
    }
    res.status(201).json({ message: 'House added successfully' });
  });
});


// Start the server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
// Get a single house by ID
app.get('/houses/:id', (req, res) => {
  const houseId = req.params.id;

  const sql = 'SELECT * FROM houses WHERE id = ?';
  db.query(sql, [houseId], (err, results) => {
    if (err) {
      console.error('Error fetching house:', err);
      return res.status(500).json({ error: 'Failed to fetch house.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'House not found.' });
    }

    res.json(results[0]);
  });
});
// Update house by ID
app.put('/houses/:id', (req, res) => {
  const houseId = req.params.id;
  const { landlord_name, location, price, description } = req.body;

  if (!landlord_name || !location || !price || !description) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }

  const sql = `
    UPDATE houses 
    SET landlord_name = ?, location = ?, price = ?, description = ? 
    WHERE id = ?
  `;
  const values = [landlord_name, location, price, description, houseId];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Update error:', err);
      return res.status(500).json({ error: 'Database update failed.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'House not found.' });
    }

    res.json({ message: '✅ House updated successfully!' });
  });
});
// Delete house by ID
app.delete('/houses/:id', (req, res) => {
  const houseId = req.params.id;

  const sql = 'DELETE FROM houses WHERE id = ?';

  db.query(sql, [houseId], (err, result) => {
    if (err) {
      console.error('Delete error:', err);
      return res.status(500).json({ error: 'Database delete failed.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'House not found.' });
    }

    res.json({ message: '❌ House deleted successfully.' });
  });
});
// =================== Landlords =====================

// Add a new landlord
app.post('/landlords', (req, res) => {
  const { name, phone, email } = req.body;

  if (!name || !phone) {
    return res.status(400).json({ error: 'Name and phone are required.' });
  }

  const sql = 'INSERT INTO landlords (name, phone, email) VALUES (?, ?, ?)';
  const values = [name, phone, email];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error inserting landlord:', err);
      return res.status(500).json({ error: 'Database insert failed.' });
    }

    res.status(201).json({ message: '✅ Landlord added successfully!', landlordId: result.insertId });
  });
});

// Get all landlords
app.get('/landlords', (req, res) => {
  db.query('SELECT * FROM landlords', (err, results) => {
    if (err) {
      console.error('Error fetching landlords:', err);
      return res.status(500).json({ error: 'Failed to fetch landlords.' });
    }

    res.json(results);
  });
});

// Delete a landlord
app.delete('/landlords/:id', (req, res) => {
  const landlordId = req.params.id;

  db.query('DELETE FROM landlords WHERE id = ?', [landlordId], (err, result) => {
    if (err) {
      console.error('Error deleting landlord:', err);
      return res.status(500).json({ error: 'Failed to delete landlord.' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Landlord not found.' });
    }

    res.json({ message: '🗑️ Landlord deleted successfully.' });
  });
});

// Get houses by location
app.get('/houses', (req, res) => {
  const location = req.query.location;

  if (!location) {
    return res.status(400).json({ error: 'Location query parameter is required.' });
  }

  const sql = `
    SELECT houses.*, landlords.name AS landlord_name 
    FROM houses 
    JOIN landlords ON houses.landlord_id = landlords.id
    WHERE houses.location LIKE ?
  `;

  db.query(sql, [`%${location}%`], (err, results) => {
    if (err) {
      console.error('Error fetching houses by location:', err);
      return res.status(500).json({ error: 'Failed to fetch houses.' });
    }

    res.json(results);
  });
});
app.post('/auth/signup', async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const sql = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
    db.query(sql, [name, email, hashedPassword, role], (err, result) => {
      if (err) {
        console.error('Signup error:', err);
        return res.status(500).json({ error: 'Signup failed or user already exists.' });
      }
      res.status(201).json({ message: 'User registered successfully.' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, role: user.role },
      'secret123', // replace with env secret later
      { expiresIn: '1h' }
    );

    res.status(200).json({ message: 'Login successful', token });
  });
});
app.get('/profile', verifyToken, (req, res) => {
  res.json({
    message: '🔐 Token verified!',
    user: req.user // contains id, email, role
  });
});

