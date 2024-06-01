const express = require('express');
const router = express.Router();
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
router.delete('/:id', async (req, res) => {
    try {
      const requestId = req.params.id;
      const deletedRequest = await Request.findByIdAndDelete(requestId);
      if (!deletedRequest) {
        return res.status(404).json({ message: 'Request not found' });
      }
      res.status(200).json({ message: 'Request deleted successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });
module.exports = router;