
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import FastNavbar from '../pages/Fast/FastNavbar';
const Community = () => {
  const [communityName, setCommunityName] = useState('');
  const [showTextField, setShowTextField] = useState(false);
  const [communityNames, setCommunityNames] = useState([]);

  useEffect(() => {
    const fetchCommunityData = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/community');
        setCommunityNames(response.data);
      } catch (error) {
        console.error('Error fetching community data:', error);
      }
    };

    fetchCommunityData();
  }, []); // Empty dependency array ensures the effect runs only once when the component mounts

  const handleCreateCommunity = () => {
    setShowTextField(true);
  };

  const handleCommunityNameChange = (event) => {
    setCommunityName(event.target.value);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      await axios.post('http://localhost:5000/api/community', { name: communityName });
      const response = await axios.get('http://localhost:5000/api/community');
      setCommunityNames(response.data);
      setCommunityName('');
      setShowTextField(false);
    } catch (error) {
      console.error('Error creating community:', error);
    }
  };

  return (
    <>
    
    <FastNavbar/>
    <div className="bg-white py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-2xl lg:mx-0">
          <h2 className="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">From the blog</h2>
          <p className="mt-2 text-lg leading-8 text-gray-600">Learn how to grow your business with our expert advice.</p>
        </div>
        <button
          type="button"
          className="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          onClick={handleCreateCommunity} >
          Create community
        </button>
        {showTextField && (
          <form onSubmit={handleSubmit} className="mt-4">
            <input
              type="text"
              value={communityName}
              onChange={handleCommunityNameChange}
              placeholder="Enter community name"
              className="w-full rounded-md border-gray-300 shadow-sm p-2 focus:ring-indigo-500 focus:border-indigo-500 mt-2"
              required/>
            <button
              type="submit"
              className="mt-2 bg-indigo-600 text-white rounded-md px-4 py-2 hover:bg-indigo-700">
              Create
            </button>
          </form>
        )}

        {communityNames.length > 0 && (
          <div className="mt-4">
            <h3 className="text-lg font-semibold leading-6 text-gray-900">Community Names:</h3>
            <ul className="mt-2">
              {communityNames.map((name, index) => (
                <li key={index} className="text-gray-600">{name}</li>
              ))}
            </ul>
          </div>
        )}
        
      </div>
      
    </div>
    
    </>
  );
};

export default Community;
