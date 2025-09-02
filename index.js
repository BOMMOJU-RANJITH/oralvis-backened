// --- Imports ---
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier'); // For uploading buffer to Cloudinary

// --- Cloudinary Setup ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// --- Multer Setup ---
const upload = multer(); // No storage, we upload manually via buffer

// --- Initialize Express ---
const app = express();
app.use(cors());
app.use(express.json());

// --- SQLite Database ---
const db = new sqlite3.Database('./oralvis.db', (err) => {
  if (err) console.error('Database connection error:', err.message);
  else console.log('Connected to SQLite database.');
});

// --- Seed Users ---
function seedUsers() {
  const users = [
    { email: 'dentist@oralvis.com', password: 'dentist123', role: 'Dentist' },
    { email: 'tech@oralvis.com', password: 'tech123', role: 'Technician' },
  ];

  users.forEach(user => {
    const hashedPassword = bcrypt.hashSync(user.password, 10);
    db.get(`SELECT * FROM users WHERE email = ?`, [user.email], (err, row) => {
      if (!row) {
        db.run(
          `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
          [user.email, hashedPassword, user.role],
          (err) => {
            if (err) console.error('❌ Error inserting user:', err.message);
            else console.log(`✅ User seeded: ${user.email} (${user.role})`);
          }
        );
      }
    });
  });
}
seedUsers();

// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key';

// --- Authentication Middleware ---
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, role }
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// --- Role Middleware ---
function roleMiddleware(requiredRole) {
  return (req, res, next) => {
    if (req.user.role !== requiredRole) {
      return res.status(403).json({ message: 'Access denied: insufficient role' });
    }
    next();
  };
}

// --- Routes ---
// Test route
app.get('/', (req, res) => res.send('OralVis Backend is running!'));

// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token, role: user.role });
  });
});

// Protected Routes
app.get('/profile', authMiddleware, (req, res) => {
  res.json({ message: `Welcome user ${req.user.id}`, role: req.user.role });
});
app.get('/dentist-dashboard', authMiddleware, roleMiddleware('Dentist'), (req, res) => {
  res.json({ message: 'Dentist dashboard data here' });
});
app.get('/technician-dashboard', authMiddleware, roleMiddleware('Technician'), (req, res) => {
  res.json({ message: 'Technician dashboard data here' });
});

// Upload Scan (Technician Only)
app.post('/upload', authMiddleware, roleMiddleware('Technician'), upload.single('scanImage'), async (req, res) => {
  try {
    const { patientName, patientId, scanType, region } = req.body;

    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    // Upload buffer to Cloudinary
    const streamUpload = (fileBuffer) => {
      return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'oralvis_scans' },
          (error, result) => {
            if (result) resolve(result);
            else reject(error);
          }
        );
        streamifier.createReadStream(fileBuffer).pipe(stream);
      });
    };

    const result = await streamUpload(req.file.buffer);
    const imageUrl = result.secure_url;

    // Save scan record in SQLite
    const query = `
      INSERT INTO scans (patientName, patientId, scanType, region, imageUrl, uploadDate)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const params = [patientName, patientId, scanType, region, imageUrl, new Date().toISOString()];

    db.run(query, params, function (err) {
      if (err) return res.status(500).json({ message: 'Database error', error: err.message });
      res.json({ message: 'Scan uploaded successfully!', scanId: this.lastID, imageUrl });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get all scans (Dentist Only)
app.get('/scans', authMiddleware, roleMiddleware('Dentist'), (req, res) => {
  const query = `SELECT * FROM scans ORDER BY uploadDate DESC`;

  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err.message });
    res.json(rows); // Send array of scan records
  });
});


// --- Start Server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
