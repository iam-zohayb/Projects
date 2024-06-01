import React, { useState, useEffect } from 'react';
import FastNavbar from '../pages/Fast/FastNavbar';
import axios from 'axios';

const Request = () => {
  const [requests, setRequests] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/request');
        setRequests(response.data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };

    fetchData();
  }, []);

  const handleApprove = async (id, request) => {
    try {
      await axios.post('http://localhost:5000/api/approve', request);
      console.log('Request approved and saved to Blog database:', request);
      await axios.delete(`http://localhost:5000/api/request/${id}`);
      setRequests(requests.filter(req => req._id !== id));
    } catch (error) {
      console.error('Error approving request:', error);
    }
  };

  const handleDecline = async (id) => {
    try {
      await axios.delete(`http://localhost:5000/api/request/${id}`);
      setRequests(requests.filter(request => request._id !== id));
    } catch (error) {
      console.error('Error declining request:', error);
    }
  };

  return (
    <div>
      <FastNavbar />
      <div className="container mx-auto px-4">
       
        {requests.length === 0 ? (
          <h1 className="text-center text-gray-600 text-3xl mt-11 font-bold">No Pending Requests</h1>
        ) : (
          requests.map(request => (
            <div key={request._id} className="bg-white shadow-md p-4 rounded-lg mb-4">
              <p className="text-gray-600"><b>Title:</b> {request.title}</p>
              <p className="text-gray-600 mt-2"><b>Community:</b> {request.community}</p>
              <p className="text-gray-600 mt-2"><b>Description:</b>{request.description}</p>
              <p className="text-gray-600 mt-2"><b>Content:</b>{request.content}</p>
              <div className="mt-4">
                <button onClick={() => handleApprove(request._id, request)} className="bg-green-500 text-white rounded-md px-4 py-2 mr-2 hover:bg-green-600">Approve</button>
                <button onClick={() => handleDecline(request._id)} className="bg-red-500 text-white rounded-md px-4 py-2 hover:bg-red-600">Decline</button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Request;
