// Backend/routes/blogRoutes.js
const express = require('express');
const router = express.Router();
const multer = require('multer');
const Request =require('../models/Request');

router.get('/', async (req, res) => {
  try {
    const blogPosts = await Request.find();
    res.status(200).json(blogPosts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads'); 
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname); 
  }
});
const upload = multer({ storage });


router.post('/', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { title, description, content, community } = req.body;
    const image = req.file.filename;
    const newBlogPost = new Request({
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
