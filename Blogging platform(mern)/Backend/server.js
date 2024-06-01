// Backend/server.js

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoutes = require('./routes/authRoutes');
const blogRoutes = require('./routes/blogRoutes');
const communityRoutes = require('./routes/communityRoutes'); // Import communityRoutes
const fastauthRoutes = require('./routes/fastauthRoutes');
const requestRoute = require('./routes/requestRoute');
const getRequestRoutes= require('./routes/getRequestRoutes');
const getBlog=require('./routes/getBlog')
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(bodyParser.json());
app.use(cors());
mongoose.connect(process.env.MONGODB_URI, {
  dbName: process.env.DB_NAME,
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

app.use('/api', authRoutes);
app.use('/api', fastauthRoutes);
app.use('/api/community', communityRoutes); 
app.use('/api/blog', requestRoute);
app.use('/api', blogRoutes);
app.use('/api/getblog', getBlog);
app.use('/api/request', getRequestRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
