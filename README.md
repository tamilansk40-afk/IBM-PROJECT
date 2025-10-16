🔐 USER AUTHENTICATION FOR SYSTEM
📖 Overview
User Authentication for System is a full-stack web application designed to provide secure login, registration, and session management using modern authentication techniques. The system ensures only authorized users can access protected routes or system resources, implementing password encryption, JWT-based authentication, and role-based access control.

🧠 Key Features
✅ User Registration & Login ✅ JWT (JSON Web Token) Authentication ✅ Password Hashing using bcrypt.js ✅ Role-based Access (Admin/User) ✅ Secure API Endpoints ✅ Form Validation (Frontend & Backend) ✅ Database Storage (MongoDB / SQLite) ✅ Error Handling & Input Sanitization ✅ Deployment on Vercel / Render

⚙️ Tech Stack
Layer	Technology
Frontend	HTML, CSS, JavaScript / React
Backend	Node.js, Express.js
Database	MongoDB (Mongoose) or SQLite
Version Control	Git & GitHub
Deployment	Vercel / Render / Netlify
Authentication	JWT, bcrypt.js
🏗️ Project Setup Guide
1️⃣ Clone the Repository
git clone https://github.com/username/user-authentication-system.git
cd user-authentication-system
2️⃣ Install Dependencies
npm install
3️⃣ Setup Environment Variables
Create a .env file in your root folder and add:

PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
4️⃣ Run the Project
npm start
5️⃣ Access the App
Backend API: http://localhost:5000
Frontend (if React used): http://localhost:3000
🧩 API Documentation
🔸 Register User
Endpoint: POST /api/register Body:

{
  "name": "Venkat",
  "email": "venkat@gmail.com",
  "password": "Venkat@123"
}
Response:

{
  "message": "User registered successfully!"
}
🔸 Login User
Endpoint: POST /api/login Body:

{
  "email": "venkat@gmail.com",
  "password": "Venkat@123"
}
Response:

{
  "message": "Login successful!",
  "token": "eyJhbGciOiJIUzI1NiIsInR..."
}
🔸 Get User Profile (Protected Route)
Endpoint: GET /api/profile Header:

Authorization: Bearer <JWT_TOKEN>
Response:

{
  "id": "66a2bb4e02e4",
  "name": "Venkat",
  "email": "venkat@gmail.com"
}
🧠 Challenges & Solutions
Challenge	Solution Implemented
Password Security	Implemented bcrypt.js to hash passwords
Token Expiry Management	Used JWT tokens with expiry time
Unauthorized Access	Middleware for route protection
Deployment Errors	Configured environment variables properly
CORS Issues	Added cors middleware in Express.js
💻 Sample Program (Backend Example)
Here’s the main backend code (server.js) for handling registration and login securely 👇

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log(err));

// Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

// Register Route
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashed });
  await user.save();
  res.json({ message: "User registered successfully!" });
});

// Login Route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });
  
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ message: "Invalid credentials" });
  
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful!", token });
});

// Protected Profile Route
app.get("/api/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Token required" });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    res.json(user);
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
});

app.listen(process.env.PORT || 5000, () => {
  console.log("🚀 Server running on port", process.env.PORT || 5000);
});
📸 Screenshots (Suggested)
Login Page
Registration Page
Dashboard (After Login)
MongoDB Database Records
Terminal showing successful registration/login
🚀 Deployment
Frontend: Netlify or Vercel
Backend: Render or Vercel Serverless Functions
GitHub Repository: https://github.com/username/user-authentication-system
🧾 Conclusion
This project demonstrates how secure authentication can be implemented using modern full-stack technologies. It can be extended to include OAuth (Google, GitHub Login), Password Reset, and Two-Factor Authentication (2FA) for future improvements.

