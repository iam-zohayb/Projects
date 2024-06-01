import React from 'react'
import SignUpForm from '../../components/SignUpForm'
const FastSignup = () => {
  return (
    <div>
          <SignUpForm redirectPath="/fastlogin" path="http://localhost:5000/api/fastsignup" dashboard="/fastdashboard"/>
    </div>
  )
}

export default FastSignup