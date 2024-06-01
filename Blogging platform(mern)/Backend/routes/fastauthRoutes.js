// Backend/routes/authRoutes.js
const express = require('express');
const router = express.Router();

const fastauthController=require('../controllers/fastauthController');
router.post('/fastsignup', fastauthController.signup);
router.post("/fastlogin",fastauthController.login);
module.exports = router;
