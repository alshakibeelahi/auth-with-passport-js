import React, { useState } from 'react';
import axios from 'axios';
import Cookies from 'js-cookie';

function App() {
    const [user, setUser] = useState(null);

    const handleLogin = async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const username = formData.get('username');
        const password = formData.get('password');

        try {
            const response = await axios.post('http://localhost:3000/login', { username, password });
            const { user, token } = response.data;
            setUser(user);
            Cookies.set('token', token);
        } catch (error) {
            console.error('Login error', error);
        }
    };

    const handleGoogleLogin = () => {
        window.location.href = 'http://103.145.138.74:5000/auth/google';
    };

    const handleLogout = () => {
        Cookies.remove('token');
        setUser(null);
    };

    return (
        <div className="App">
            <h1>Home</h1>
            {!user ? (
                <div>
                    <form onSubmit={handleLogin}>
                        <div>
                            <label>Username:</label>
                            <input type="text" name="username" required />
                        </div>
                        <div>
                            <label>Password:</label>
                            <input type="password" name="password" required />
                        </div>
                        <div>
                            <button type="submit">Log In</button>
                        </div>
                    </form>
                    <button onClick={handleGoogleLogin}>Login with Google</button>
                </div>
            ) : (
                <div>
                    <h2>Welcome, {user.username}</h2>
                    <button onClick={handleLogout}>Logout</button>
                </div>
            )}
        </div>
    );
}

export default App;
