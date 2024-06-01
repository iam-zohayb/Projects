import React from 'react';
import LoginForm from '../../components/LoginForm';

const BloggerLogin = () => {
  return (
    <div>
      <LoginForm redirectPath="/bloggersignup" path="http://localhost:5000/api/bloggerlogin" dashboard="/bloggerdashboard"/>
    </div>
  );
};

export default BloggerLogin;
