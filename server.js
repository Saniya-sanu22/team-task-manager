const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

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

// ================= USERS TABLE =================
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    password TEXT,
    role TEXT DEFAULT 'member'
  )
`);

// ================= PROJECTS TABLE =================
db.run(`
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_by INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id)
  )
`);

// ================= TASKS TABLE =================
db.run(`
  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    assigned_to INTEGER,
    project_id INTEGER,
    deadline TEXT,
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (project_id) REFERENCES projects(id)
  )
`);

// ================= HOME ROUTE =================
app.get("/", (req, res) => {
  res.send("Server is running");
});

// ================= SIGNUP ROUTE =================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (name, email, password)
       VALUES (?, ?, ?)`,
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

// ================= LOGIN ROUTE =================
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

      if (!user) {
        return res.status(404).send({
          message: "User not found",
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).send({
          message: "Invalid password",
        });
      }

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

// ================= JWT MIDDLEWARE =================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

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
// admin middleware
function isAdmin(req, res, next) {
  db.get(
    `SELECT * FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      if (err) {
        return res.status(500).send({
          error: err.message,
        });
      }

      if (user.role !== "admin") {
        return res.status(403).send({
          message: "Admin access required",
        });
      }

      next();
    }
  );
}
// ================= DASHBOARD ROUTE =================
app.get("/dashboard", authenticateToken, (req, res) => {
  res.send({
    message: "Welcome to dashboard",
    user: req.user,
  });
});

// ================= CREATE PROJECT =================
app.post("/projects", authenticateToken, (req, res) => {
  const { name, description } = req.body;

  db.run(
    `INSERT INTO projects (name, description, created_by)
     VALUES (?, ?, ?)`,
    [name, description, req.user.id],
    function (err) {
      if (err) {
        return res.status(500).send({
          error: err.message,
        });
      }

      res.send({
        message: "Project created successfully",
        projectId: this.lastID,
      });
    }
  );
});

// ================= CREATE TASK =================
app.post("/tasks", authenticateToken,isAdmin, (req, res) => {
  const { title, assigned_to, project_id, deadline } = req.body;

  db.run(
    `INSERT INTO tasks
    (title, assigned_to, project_id, deadline)
    VALUES (?, ?, ?, ?)`,
    [title, assigned_to, project_id, deadline],
    function (err) {
      if (err) {
        return res.status(500).send({
          error: err.message,
        });
      }

      res.send({
        message: "Task created successfully",
        taskId: this.lastID,
      });
    }
  );
});

// ================= TEST ROUTE =================
app.get("/test123", (req, res) => {
  res.send("TEST WORKING");
});
// update task status
app.put("/tasks/:id", authenticateToken, (req, res) => {
  const { status } = req.body;

  db.run(
    `UPDATE tasks SET status = ? WHERE id = ?`,
    [status, req.params.id],
    function (err) {
      if (err) {
        return res.status(500).send({
          error: err.message,
        });
      }

      res.send({
        message: "Task status updated successfully",
      });
    }
  );
});
// get all tasks
app.get("/tasks", authenticateToken, (req, res) => {
  db.all(`SELECT * FROM tasks`, [], (err, tasks) => {
    if (err) {
      return res.status(500).send({
        error: err.message,
      });
    }

    res.send(tasks);
  });
});
// overdue tasks
app.get("/tasks/overdue", authenticateToken, (req, res) => {
  const today = new Date().toISOString().split("T")[0];

  db.all(
    `SELECT * FROM tasks
     WHERE deadline < ? AND status != 'completed'`,
    [today],
    (err, tasks) => {
      if (err) {
        return res.status(500).send({
          error: err.message,
        });
      }

      res.send(tasks);
    }
  );
});
// make user admin
app.put("/make-admin/:id", (req, res) => {
  db.run(
    `UPDATE users SET role = 'admin' WHERE id = ?`,
    [req.params.id],
    function (err) {
      if (err) {
        return res.status(500).send({
          error: err.message,
        });
      }

      res.send({
        message: "User is now admin",
      });
    }
  );
});
const PORT = process.env.PORT || 5007;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
