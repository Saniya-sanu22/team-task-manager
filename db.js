const sqlite3 = require("sqlite3").verbose();

// This creates database file automatically
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) {
    console.log("DB error:", err.message);
  } else {
    console.log("Database connected successfully");
  }
});

module.exports = db;
created_by) REFERENCES users(id)
  )
`);