// Backend/routes/blogRoutes.js
const express = require('express');
const router = express.Router();
const multer = require('multer');
const Blog = require('../models/blog');

// Multer configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads'); // Make sure 'uploads' directory exists
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname); // Use the original filename
  }
});
const upload = multer({ storage });

// POST route to create a new blog post
router.post('/approve', async (req, res) => {
  try {
    const { title, description, image, content, community } = req.body;
    const newBlogPost = new Blog({
      title,
      description,
      image,
      content,
      community
    });
    const savedBlogPost = await newBlogPost.save();
    res.status(201).json(savedBlogPost);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
