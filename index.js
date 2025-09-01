// --- Imports ---
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3'); // Use better-sqlite3 instead of sqlite3
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');

// --- Cloudinary Setup ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// --- Multer Setup ---
const upload = multer(); // No storage, upload manually via buffer

// --- Initialize Express ---
const app = express();
app.use(cors());
app.use(express.json());

// --- SQLite Database ---
const db = new Database('./oralvis.db'); // better-sqlite3 auto-creates DB
console.log('Connected to SQLite database.');

// --- Seed Users ---
function seedUsers() {
  const users = [
    { email: 'dentist@oralvis.com', password: 'dentist123', role: 'Dentist' },
    { email: 'tech@oralvis.com', password: 'tech123', role: 'Technician' },
  ];

  users.forEach(user => {
    const hashedPassword = bcrypt.hashSync(user.password, 10);
    const row = db.prepare(`SELECT * FROM users WHERE email = ?`).get(user.email);
    if (!row) {
      db.prepare(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`)
        .run(user.email, hashedPassword, user.role);
      console.log(`✅ User seeded: ${user.email} (${user.role})`);
    }
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
    req.user = decoded;
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
app.get('/', (req, res) => res.send('OralVis Backend is running!'));

// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, role: user.role });
});

// Protected routes
app.get('/profile', authMiddleware, (req, res) => {
  res.json({ message: `Welcome user ${req.user.id}`, role: req.user.role });
});

app.get('/dentist-dashboard', authMiddleware, roleMiddleware('Dentist'), (req, res) => {
  res.json({ message: 'Dentist dashboard data here' });
});

app.get('/technician-dashboard', authMiddleware, roleMiddleware('Technician'), (req, res) => {
  res.json({ message: 'Technician dashboard data here' });
});

// Upload Scan
app.post('/upload', authMiddleware, roleMiddleware('Technician'), upload.single('scanImage'), async (req, res) => {
  try {
    const { patientName, patientId, scanType, region } = req.body;
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const streamUpload = (fileBuffer) => {
      return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ folder: 'oralvis_scans' }, (err, result) => {
          if (result) resolve(result);
          else reject(err);
        });
        streamifier.createReadStream(fileBuffer).pipe(stream);
      });
    };

    const result = await streamUpload(req.file.buffer);
    const imageUrl = result.secure_url;

    db.prepare(`
      INSERT INTO scans (patientName, patientId, scanType, region, imageUrl, uploadDate)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(patientName, patientId, scanType, region, imageUrl, new Date().toISOString());

    res.json({ message: 'Scan uploaded successfully!', imageUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get all scans
app.get('/scans', authMiddleware, roleMiddleware('Dentist'), (req, res) => {
  const rows = db.prepare(`SELECT * FROM scans ORDER BY uploadDate DESC`).all();
  res.json(rows);
});

// --- Start Server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
