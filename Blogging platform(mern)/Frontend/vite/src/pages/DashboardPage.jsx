import React, { useState, useEffect } from 'react';
import axios from 'axios';

const DashboardPage = () => {
    const [blogs, setBlogs] = useState([]);
    const [expandedBlogs, setExpandedBlogs] = useState([]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get('http://localhost:5000/api/getblog');
                setBlogs(response.data);
                // Initially, set all blogs to not expanded
                setExpandedBlogs(Array(response.data.length).fill(false));
            } catch (error) {
                console.error('Error fetching blog data:', error);
            }
        };

        fetchData();
    }, []);

    const toggleDescription = (index) => {
        const newExpandedBlogs = [...expandedBlogs];
        newExpandedBlogs[index] = !newExpandedBlogs[index];
        setExpandedBlogs(newExpandedBlogs);
    };

    return (
        <>
        <div className="bg-white py-24 sm:py-32">
            <div className="mx-auto px-6 lg:px-8">
                <div className="mx-auto  lg:mx-0">
                    <h2 className="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl">From the blog</h2>
                    <p className="mt-2 text-lg leading-8 text-gray-600">Learn how to grow your business with our expert advice.</p>
                    <div className="mx-auto mt-3  border-t border-gray-200 sm:mt-16 lg:mx-0 lg:max-w-none lg:grid-cols-3">
                    <h2 className="text-3xl font-bold text-red-600 sm:text-4xl text-center mt-4 mb-3 ">Blogs</h2>
                     </div>
                </div>
   
                    {blogs.map((blog, index) => (
       
                        <div key={index} className="flex items-center justify-center bg-gray-200">
                            <div className="bg-white p-8 w-[32rem] mr-4 ml-4 mt-3 mb-3">
                                
                                <header className="flex font-light text-sm">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 rotate-90 -ml-2" viewBox="0 0 24 24" stroke="#b91c1c">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4" />
                                    </svg>
                                    <h1 className="font-bold"> {blog.community} </h1>
                                    
                                </header>
                                <div className=" m-0  shrink-0  rounded-xl rounded-r-none bg-white bg-clip-border text-gray-700">
                <img
                    src={blog.image}
                    alt="image"
                    className="h-full w-full object-cover"
                />
            </div>
                                <h2 className="font-bold text-3xl mt-2">{blog.title}</h2>
                                <p className="mt-5"> 
                                    By: 
                                    <a href="#" className="text-red-600"> Zohaib Safdar </a>, 
                                    <a href="#" className="text-red-600"> Saiqa Tahir</a>
                                </p>
                                <h3 className="font-bold text-xl mt-8"> Description </h3>
                                {expandedBlogs[index] ? (
                                    <p className="font-light">{blog.description}</p>
                                ) : (
                                    <p className="font-light line-clamp-3">{blog.description}</p>
                                )}
                                <button className="bg-red-600 text-white font-semibold py-2 px-5 text-sm mt-6 inline-flex items-center group" onClick={() => toggleDescription(index)}>
                                    <p> {expandedBlogs[index] ? 'Show Less' : 'Read More'} </p>
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1 group-hover:translate-x-2 delay-100 duration-200 ease-in-out" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                                    </svg>
                                </button>
                            </div>
                        </div>
                   
                    ))}
                </div>
          
        </div>
        
     
    </>
    );
};

export default DashboardPage;
