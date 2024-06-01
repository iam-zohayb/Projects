// Backend/routes/authRoutes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const User = require('../models/User');

router.post('/bloggersignup', authController.signup);
router.post("/bloggerlogin",authController.login);
module.exports = router;
