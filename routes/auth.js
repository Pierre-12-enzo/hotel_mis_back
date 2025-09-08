const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const auth = require('../Middleware/auth'); // JWT middleware


// Traditional Signup
router.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, password, role } = req.body;

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: 'User already exists' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    user = await User.create({
      firstName,
      lastName,
      email,
      phone,
      password: hashedPassword,
      role
    });

    // Generate JWT
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // Send JWT as cookie
    res.cookie('token', token, { httpOnly: true });
    res.status(201).json({ message: 'User created successfully' });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// Traditional Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    // Check password
    if (!user.password) return res.status(400).json({ message: 'User registered via OAuth, use Google login' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate JWT
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // Send JWT as cookie
    res.cookie('token', token, { httpOnly: true });
    res.json({ message: 'Login successful' });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});




// Google OAuth Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../Models/User');

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ oauthId: profile.id });
    if (!user) {
      user = await User.create({
        username: profile.displayName,
        email: profile.emails[0].value,
        oauthProvider: 'google',
        oauthId: profile.id
      });
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// Initialize passport
router.use(passport.initialize());

// Routes
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback', 
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    // Generate JWT
    const token = jwt.sign(
      { id: req.user._id, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    // Send JWT as cookie
    res.cookie('token', token, { httpOnly: true });
    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
;
  }
);

//Get data for logged user
router.get('/me', auth, async (req, res) => {
 try {
    const user = await User.findById(req.user.id).select('-password -oauthId');
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
})


module.exports = router;
