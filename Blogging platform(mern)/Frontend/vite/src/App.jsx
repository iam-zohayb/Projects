//Frontend/vite/src/App.jsx
import React from 'react';
import { BrowserRouter ,  Routes, Route } from 'react-router-dom';
import Blog from './components/Blog';
import SignUpPage from './pages/SignUpPage';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import Community from './components/Community';
import Request from './components/Request';
import MainLogin from './components/MainLogin';
import BloggerLogin from './pages/Blogger/BloggerLogin';
import BloggerSignup from './pages/Blogger/BloggerSignup';
import FastLogin from './pages/Fast/FastLogin';
import FastSignup from './pages/Fast/FastSignup';
import FastDashboard from './pages/Fast/FastDashboard';
import BloggerDashboard from './pages/Blogger/BloggerDashboard';
const App = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route  path="/community" element={<Community/>} />
        <Route  path="/blog" element={<Blog/>} />
        <Route  path="/request" element={<Request/>} />
        <Route  path="/" element={<MainLogin/>} />
        <Route  path="/bloggerlogin" element={<BloggerLogin/>} />
        <Route  path="/bloggersignup" element={<BloggerSignup/>} />
        <Route  path="/fastlogin" element={<FastLogin/>} />
        <Route  path="/fastsignup" element={<FastSignup/>} />
        <Route  path="/fastdashboard" element={<FastDashboard/>} />
        <Route  path="/bloggerdashboard" element={<BloggerDashboard/>} />
      </Routes>
    </BrowserRouter>
  );
};
export default App;
