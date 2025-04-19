const express = require("express");
const path = require("path");
const hbs = require("hbs");
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const db = require("./mysql");
require("dotenv").config();

const app = express();
const tokens = {};
const templatePath = path.join(__dirname, "../templates");

// Set view engine and views directory


app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "hbs");
// app.set("templates", templatePath);
app.set("views", templatePath);

// Email transporter
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.get("/", (req, res) => res.render("login"));
app.get("/signup", (req, res) => res.render("signup"));

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  if (password.length < 7) return res.render("signup", { error: "Password must be at least 7 characters." });

  const token = uuidv4();
  tokens[token] = { type: "create", data: { email, password } };

  const link = `http://localhost:4000/verify/${token}`;
  await transporter.sendMail({
    to: email,
    subject: "Verify your signup",
    html: `Click to verify signup: <a href="${link}">${link}</a>`,
  });

  res.send("Signup verification link sent to your email.");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

  if (!rows.length) return res.send("User not found.");
  if (rows[0].password !== password) return res.send("Wrong password!");

  res.render("home");
});

app.post("/update", async (req, res) => {
  const { email, newPassword } = req.body;

  const token = uuidv4();
  tokens[token] = { type: "update", data: { email, newPassword } };

  const link = `http://localhost:4000/verify/${token}`;
  await transporter.sendMail({
    to: email,
    subject: "Verify your password update",
    html: `Click to verify update: <a href="${link}">${link}</a>`,
  });

  res.send("Password update verification link sent.");
});

app.post("/delete", async (req, res) => {
  const { email } = req.body;

  const token = uuidv4();
  tokens[token] = { type: "delete", data: { email } };

  const link = `http://localhost:4000/verify/${token}`;
  await transporter.sendMail({
    to: email,
    subject: "Verify account deletion",
    html: `Click to confirm deletion: <a href="${link}">${link}</a>`,
  });

  res.send("Account deletion verification link sent.");
});

app.get("/verify/:token", async (req, res) => {
  const token = req.params.token;
  const entry = tokens[token];

  if (!entry) return res.send("Invalid or expired verification link.");

  let message = "";
  try {
    if (entry.type === "create") {
      await db.query("INSERT INTO users (email, password) VALUES (?, ?)", [entry.data.email, entry.data.password]);
      message = "Account created successfully!";
    } else if (entry.type === "update") {
      await db.query("UPDATE users SET password = ? WHERE email = ?", [entry.data.newPassword, entry.data.email]);
      message = "Password updated successfully!";
    } else if (entry.type === "delete") {
      await db.query("DELETE FROM users WHERE email = ?", [entry.data.email]);
      message = "Account deleted successfully!";
    }

    delete tokens[token];
    res.render("home", { message });

  } catch (err) {
    console.error("Verification Error:", err);
    res.send("Something went wrong. Check logs.");
  }
});

app.get("/logout", (req, res) => res.redirect("/login"));

app.listen(4000, () => {
  console.log("Running at http://localhost:4000/");
});
