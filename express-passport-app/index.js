const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const JWT_SECRET = 'your_jwt_secret_key';

// User database simulation
const users = [];

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// CORS middleware
app.use(cors({
    origin: 'http://your-frontend-domain.com', // Replace with your frontend domain
    credentials: true
}));

// Session middleware
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // Set to true if you're using HTTPS
        sameSite: 'lax'
    }
}));

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// Passport local strategy
passport.use(new LocalStrategy((username, password, done) => {
    const user = users.find(user => user.username === username);
    if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
    }
    if (!bcrypt.compareSync(password, user.password)) {
        return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, user);
}));

// Passport Google OAuth 2.0 strategy
passport.use(new GoogleStrategy({
  clientID: '682777072755-6kpqe96f53qf5va344v909msqb3rrgm2.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: 'http://localhost:5000/auth/google/callback'
}, (token, tokenSecret, profile, done) => {
    let user = users.find(user => user.googleId === profile.id);
    if (!user) {
        user = {
            id: users.length + 1,
            googleId: profile.id,
            username: profile.displayName
        };
        users.push(user);
    }
    return done(null, user);
}));

// Serialize user
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user
passport.deserializeUser((id, done) => {
    const user = users.find(user => user.id === id);
    done(null, user);
});

// JWT authentication middleware
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.sendStatus(403);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes
app.get('/', (req, res) => {
    res.send('<h1>Home</h1><a href="/login">Login</a> <a href="/auth/google">Login with Google</a>');
});

app.get('/login', (req, res) => {
    res.send('<h1>Login</h1><form action="/login" method="post"><div><label>Username:</label><input type="text" name="username"/></div><div><label>Password:</label><input type="password" name="password"/></div><div><input type="submit" value="Log In"/></div></form>');
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(401).json({ message: info.message });
        req.logIn(user, err => {
            if (err) return next(err);
            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ user, token });
        });
    })(req, res, next);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['https://www.googleapis.com/auth/plus.login'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
      const token = jwt.sign({ id: req.user.id, username: req.user.username }, JWT_SECRET, { expiresIn: '1h' });

      // Set the token in a secure HTTP-only cookie
      res.cookie('jwt', token, { httpOnly: true, secure: true, maxAge: 3600000 }); // 1 hour

      // Set the user info in a separate cookie (optionally not httpOnly to access it in frontend)
      res.cookie('user', JSON.stringify({ id: req.user.id, username: req.user.username }), { secure: true, maxAge: 3600000 });

      // Redirect the user to the frontend
      res.redirect('http://localhost:3000/success');
  }
);


app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

app.get('/protected', authenticateJWT, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

// Start server
const PORT = 5000;
app.listen(PORT, "103.145.138.74", () => {
    console.log(`Server is running on http://103.145.138.74:${PORT}`);
});
