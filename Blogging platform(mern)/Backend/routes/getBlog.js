
const express = require('express');
const router = express.Router();
const Blog = require('../models/blog');
router.get('/', async (req, res) => {
    try {
      const blogPosts = await Blog.find();
      res.status(200).json(blogPosts);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });
  module.exports = router;