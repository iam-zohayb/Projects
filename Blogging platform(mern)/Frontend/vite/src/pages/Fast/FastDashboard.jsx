import React from 'react'
import DashboardPage from '../DashboardPage'
import { useNavigate } from 'react-router-dom'; 
import FastNavbar from './FastNavbar';
const FastDashboard = () => {
  return (
    <div>
<FastNavbar/>
        <DashboardPage/>
    </div>
  )
}

export default FastDashboard