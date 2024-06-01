import React from 'react'
import SignUpForm from '../../components/SignUpForm'
const BloggerSignup = () => {
  return (
    <div>
        <SignUpForm redirectPath="/bloggerlogin" path="http://localhost:5000/api/bloggersignup" dashboard="/bloggerdashboard"/>
    </div>
)
}
export default BloggerSignup