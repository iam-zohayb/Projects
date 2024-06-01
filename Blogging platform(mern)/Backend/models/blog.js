// Backend/models/blog.js
const mongoose = require('mongoose');
const blogSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: String,
  image: String,
  content: {
    type: String,
    required: true
  },
  
  community: {
    type: String,
    required: true
  }
});

const Blog = mongoose.model('Blog', blogSchema);

module.exports = Blog;
