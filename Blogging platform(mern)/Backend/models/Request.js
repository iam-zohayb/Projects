const mongoose = require('mongoose');

const RequestSchema = new mongoose.Schema({
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

const Request = mongoose.model('Request', RequestSchema);

module.exports = Request;
