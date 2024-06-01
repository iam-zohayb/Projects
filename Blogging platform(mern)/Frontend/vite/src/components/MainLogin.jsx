import React from 'react';
import { useNavigate } from 'react-router-dom';
const MainLogin = () => {
    const navigate = useNavigate();

    const handleFastClick = () => {
      navigate('/fastlogin');
    };
    const handleBloggerClick = () => {
        navigate('/bloggerlogin');
      };

  return (
    <div>
      <div className='flex items-center justify-center min-h-screen from-teal-100 via-teal-300 to-teal-500 bg-gradient-to-br'>
        <div className='w-full max-w-lg px-10 py-8 mx-auto bg-white rounded-lg shadow-xl'>
          <div className='max-w-md mx-auto space-y-6'>


            <div className="flex flex-col">
              <h1 className="mb-3 text-3xl font-extrabold text-center">Login or Signup</h1>
              <button onClick={handleFastClick} className="text-indigo-100 transition-colors duration-150 bg-indigo-700 rounded-lg hover:bg-indigo-800 h-12 px-6 m-2 text-lg">As Fast</button>
              <button onClick={handleBloggerClick} className=" text-indigo-100 transition-colors duration-150 bg-indigo-700 rounded-lg hover:bg-indigo-800 h-12 px-6 m-2 text-lg">As Blogger</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default MainLogin;
