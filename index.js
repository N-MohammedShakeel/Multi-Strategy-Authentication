import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

// Load environment variables
env.config();

// Initialize app
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// Middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

// Database configuration
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});
db.connect();

// Check for missing environment variables
if (!process.env.SESSION_SECRET || !process.env.GOOGLE_CLIENT_ID || !process.env.PG_USER) {
  console.error("Missing required environment variables. Check your .env file.");
  process.exit(1);
}

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return console.error(err);
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT secret FROM users WHERE email = $1", [req.user.email]);
      const secret = result.rows[0]?.secret || "No secrets yet!";
      res.render("secrets.ejs", { secret });
    } catch (err) {
      console.error(err);
      res.redirect("/");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Handle user registration
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) return console.error(err);
        const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
          username,
          hash,
        ]);
        req.login(newUser.rows[0], (err) => {
          if (err) return console.error(err);
          res.redirect("/secrets");
        });
      });
    }
  } catch (err) {
    console.error(err);
    res.redirect("/");
  }
});

// Handle user login
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Handle secret submission
app.post("/submit", async (req, res) => {
  const { secret } = req.body;
  if (req.isAuthenticated()) {
    try {
      await db.query("UPDATE users SET secret = $1 WHERE email = $2", [secret, req.user.email]);
      res.redirect("/secrets");
    } catch (err) {
      console.error(err);
    }
  } else {
    res.redirect("/login");
  }
});

// Passport Local Strategy
passport.use(
  "local",
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length === 0) return done(null, false);
      const user = result.rows[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) return done(err);
        if (isMatch) return done(null, user);
        return done(null, false);
      });
    } catch (err) {
      console.error(err);
      return done(err);
    }
  })
);

// Passport Google Strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
            profile.email,
            "google",
          ]);
          return done(null, newUser.rows[0]);
        }
        return done(null, result.rows[0]);
      } catch (err) {
        console.error(err);
        return done(err);
      }
    }
  )
);

// Passport Serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
