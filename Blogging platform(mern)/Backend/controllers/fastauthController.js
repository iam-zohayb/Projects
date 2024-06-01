// Backend/controllers/fastauthController.js
const FastUser = require('../models/FastUser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

exports.signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await FastUser.create({ email, password: hashedPassword });
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const existingUser = await FastUser.findOne({ email });
    if (!existingUser) {
      return res.status(400).json({ success: false, message: "User does not exist" });
    }

  
    const isPasswordValid = await bcrypt.compare(password, existingUser.password);
    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: "Incorrect password" });
    }

 
    const token = jwt.sign({ userId: existingUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    return res.json({ success: true, message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err); // Log the error for debugging purposes
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};
