import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import User from "./models/User.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(cors({
  origin: "https://your-github-username.github.io", // replace with your actual GitHub Pages URL
  methods: ["GET", "POST"]
}));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.log("❌ Database error:", err));

// Signup API
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.json({ success: false, message: "All fields required" });

  const existing = await User.findOne({ email });
  if (existing)
    return res.json({ success: false, message: "Email already registered" });

  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, password: hashed });

  res.json({ success: true, message: "Signup successful", user: { name: user.name, email: user.email } });
});

// Login API
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({ success: false, message: "All fields required" });

  const user = await User.findOne({ email });
  if (!user)
    return res.json({ success: false, message: "User not found" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid)
    return res.json({ success: false, message: "Incorrect password" });

  res.json({ success: true, message: "Login successful", user: { name: user.name, email: user.email } });
});

app.get("/", (req, res) => res.send("✅ Backend running successfully"));

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
