const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  firstname: { type: String },
  lastname: { type: String}, 
  phone: { type: String}, 
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String }, // only for local login
  role: { type: String, enum: ['admin', 'manager', 'receptionist'], default: 'receptionist' },
  oauthProvider: { type: String }, // e.g., "google"
  oauthId: { type: String },       // store Google ID
}, { timestamps: true});

module.exports = mongoose.model('User', userSchema);
