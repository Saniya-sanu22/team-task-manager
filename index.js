const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
console.log("THIS FILE IS RUNNING");

const app = express();

app.use(express.json());

// database connection
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.log(err.message);
  } else {
    console.log("Connected to database");
  }
});

// create table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    password TEXT
  )
`);

// home route
app.get("/", (req, res) => {
  res.send("Server is running");
});

// signup route
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
      [name, email, hashedPassword],
      function (err) {
        if (err) {
          return res.status(500).send({
            error: err.message,
          });
        }

        res.send({
          message: "User created successfully",
          userId: this.lastID,
        });
      }
    );
  } catch (error) {
    res.status(500).send({
      error: error.message,
    });
  }
});

// login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
      if (err) {
        return res.status(500).send({
          error: err.message,
        });
      }

      // user not found
      if (!user) {
        return res.status(404).send({
          message: "User not found",
        });
      }

      // compare password
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).send({
          message: "Invalid password",
        });
      }

      // generate token
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
        },
        "secretkey",
        {
          expiresIn: "1d",
        }
      );

      res.send({
        message: "Login successful",
        token,
      });
    }
  );
});
app.get("/login", (req, res) => {
  res.send("Login route works");
});
// JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  // token format: Bearer TOKEN
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send({
      message: "Token required",
    });
  }

  jwt.verify(token, "secretkey", (err, user) => {
    if (err) {
      return res.status(403).send({
        message: "Invalid token",
      });
    }

    req.user = user;
    next();
  });
}
// protected route
app.get("/dashboard", authenticateToken, (req, res) => {
  res.send({
    message: "Welcome to dashboard",
    user: req.user,
  });
});

// start server
app.listen(5001, () => {
  console.log("Server running on port 5001");
});
setInterval(() => {}, 1000);