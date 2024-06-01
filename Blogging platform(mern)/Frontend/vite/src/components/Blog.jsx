//blog.jsx

import React, { useState, useEffect } from 'react';
import BloggerNavbar from '../pages/Blogger/BloggerNavbar';
const Blog = () => {
  const [showPopup, setShowPopup] = useState(false);
  const [communityNames, setCommunityNames] = useState([]);
  const [selectedCommunity, setSelectedCommunity] = useState('');
  const [submittedData, setSubmittedData] = useState(null);
  
  const togglePopup = () => {
    setShowPopup(!showPopup);
  };
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    image: null,
    content: ''
  });

  const handleChange = (e) => {
    if (e.target.name === 'image') {
      setFormData({
        ...formData,
        image: e.target.files[0], 
        imageURL: URL.createObjectURL(e.target.files[0]) 
      });
    } else {
      const { name, value } = e.target;
      setFormData({
        ...formData,
        [name]: value
      });
      if (name === 'community') {
        setSelectedCommunity(value);
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formDataToSend = new FormData();
      formDataToSend.append('title', formData.title);
      formDataToSend.append('description', formData.description);
      formDataToSend.append('content', formData.content);
      formDataToSend.append('image', formData.image);
      formDataToSend.append('community', selectedCommunity);

      const response = await fetch('http://localhost:5000/api/blog', {
        method: 'POST',
        body: formDataToSend
      });
      if (response.ok) {
        setFormData({
          title: '',
          description: '',
          image: null,
          content: ''
        });
        alert('Blog post created successfully!');
        setSubmittedData(formData); // Save submitted data
      } else {
        const data = await response.json();
        alert(data.message || 'Failed to create blog post');
      }
    } catch (err) {
      console.error('Error:', err);
      alert('An error occurred. Please try again later.');
    }
  };

  useEffect(() => {
    const fetchCommunityNames = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/community');
        if (response.ok) {
          const data = await response.json();
          setCommunityNames(data);
        } else {
          console.error('Failed to fetch community names');
        }
      } catch (err) {
        console.error('Error:', err);
      }
    };

    fetchCommunityNames();
  }, []);

  return (
    <div>
         <BloggerNavbar/>
      <div className="bg-white py-24 sm:py-32">
        <div className="mx-auto max-w-7xl px-6 lg:px-8">
          <div className="mx-auto max-w-2xl lg:mx-0">
            <h2 className="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">From the blog</h2>
            <p className="mt-2 text-lg leading-8 text-gray-600">Learn how to grow your business with our expert advice.</p>
          </div>
          <button
            className="bg-blue-500 hover:bg-blue-400 text-white py-2 px-4 rounded mt-4"
            onClick={togglePopup}
          >
            Create Blog
          </button>
        </div>
        {formData.imageURL && (
          <img src={formData.imageURL} alt="Selected" className="mt-2 max-w-full" />
        )}
      </div>

      {showPopup && (
        <div className="fixed inset-0 flex items-center justify-center bg-gray-800 bg-opacity-75 p-10">
          <div className="bg-white rounded-lg max-w-4xl">
            <div className="flex justify-end p-4">
              <button className="text-gray-600 hover:text-gray-800" onClick={togglePopup}>
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleSubmit} className="p-11" encType="multipart/form-data">
              <div className="mb-4">
                <label className="text-xl text-gray-600">Community</label><br />
                <select
                  className="border-2 border-gray-300 p-2 w-full"
                  name="community"
                  id="community"
                  value={selectedCommunity}
                  onChange={handleChange}
                >
                  <option value="">Select a community</option>
                  {communityNames.map((name, index) => (
                    <option key={index} value={name}>{name}</option>
                  ))}
                </select>
              </div>

              <div className="mb-4">
                <label className="text-xl text-gray-600">Title <span className="text-red-500">*</span></label><br />
                <input type="text" className="border-2 border-gray-300 p-2 w-full" name="title" id="title" value={formData.title} onChange={handleChange} required />
              </div>

              <div className="mb-4">
                <label className="text-xl text-gray-600">Description</label><br />
                <input type="text" className="border-2 border-gray-300 p-2 w-full" name="description" id="description" value={formData.description} onChange={handleChange} placeholder="(Optional)" />
              </div>

              <div className="mb-4">
                <label className="text-xl text-gray-600">Image</label><br />
                <input type="file" className="border-2 border-gray-300 p-2 w-full" name="image" id="image" accept="image/*" onChange={handleChange} />
              </div>

              <div className="mb-8">
                <label className="text-xl text-gray-600">Content <span className="text-red-500">*</span></label><br />
                <textarea name="content" className="border-2 border-gray-500 w-full" value={formData.content} onChange={handleChange} required></textarea>
              </div>

              <div className="flex p-1">
                <button type="submit" className="p-3 bg-blue-500 text-white hover:bg-blue-400" required>Submit</button>
              </div>
            </form>
          </div>
        </div>
      )}


    </div>
  );
}
export default Blog;
