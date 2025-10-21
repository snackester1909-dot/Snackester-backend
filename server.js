require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const twilio = require("twilio");

const app = express();
app.use(express.json());
app.use(cors());

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  phone: String,
  otp: String,
  otpExpiry: Date,
  verified: { type: Boolean, default: false }
});
const User = mongoose.model("User", userSchema);

// JWT middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "No token" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ success: false, message: "Invalid token" });
  }
}

// Signup Route
app.post("/signup", async (req, res) => {
  const { name, email, password, phone } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 5*60*1000); // 5 mins

    const user = new User({ name, email, password: hashed, phone, otp, otpExpiry });
    await user.save();

    // Send OTP via Twilio
    await client.messages.create({
      body: `Your OTP code is ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: phone
    });

    res.json({ success: true, message: "OTP sent to your phone" });
  } catch (err) {
    console.log(err);
    res.json({ success: false, message: "Email or phone already exists" });
  }
});

// Verify OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.json({ success: false, message: "User not found" });

  if (user.otp !== otp || user.otpExpiry < new Date())
    return res.json({ success: false, message: "OTP invalid or expired" });

  user.verified = true;
  user.otp = null;
  user.otpExpiry = null;
  await user.save();

  const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, message: "Verified successfully", token });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.json({ success: false, message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.json({ success: false, message: "Incorrect password" });

  if (!user.verified) return res.json({ success: false, message: "User not verified" });

  const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "2h" });
  res.json({ success: true, message: "Login successful", token });
});

// Protected route example
app.get("/profile", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password -otp -otpExpiry");
  res.json({ success: true, user });
});



app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});

