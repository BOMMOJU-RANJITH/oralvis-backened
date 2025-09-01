const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Create/connect to SQLite database file
const db = new sqlite3.Database(path.join(__dirname, 'oralvis.db'), (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create users table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('Technician','Dentist')) NOT NULL
  )
`, (err) => {
  if (err) console.error('Error creating users table:', err.message);
  else console.log('Users table ready.');
});

// Create scans table
db.run(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patientName TEXT NOT NULL,
    patientId TEXT NOT NULL,
    scanType TEXT NOT NULL,
    region TEXT NOT NULL,
    imageUrl TEXT NOT NULL,
    uploadDate TEXT NOT NULL
  )
`, (err) => {
  if (err) console.error('Error creating scans table:', err.message);
  else console.log('Scans table ready.');
});


module.exports = db;
