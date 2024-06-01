import React from 'react'
import LoginForm from '../../components/LoginForm'
const FastLogin = () => {
  return (
    <div>
  <LoginForm redirectPath="/fastsignup" path="http://localhost:5000/api/fastlogin" dashboard="/fastdashboard"/>
    </div>
  )
}

export default FastLogin
