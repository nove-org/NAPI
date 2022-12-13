import { useRef } from 'react';
import { API_URL } from './CONSTS';

function Login(props: { action: (value: string) => void }) {
    const errorRef = useRef<HTMLSpanElement>(null);

    function onSubmit(e: React.FormEvent<HTMLFormElement>) {
        e.preventDefault();
        const form = e.currentTarget;
        const formData = new FormData(form);
        const username = formData.get('username');
        const password = formData.get('password');

        if (username && password) {
            fetch(`${API_URL}/v1/users/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    password,
                }),
            })
                .then((res) => (res as Response).json())
                .then((data) => {
                    if (data.body.error) {
                        console.log(data.body.error);
                        (errorRef.current as any).style.display = 'block';
                        (errorRef.current as any).innerText = JSON.stringify(data.body.error, null, ' ');
                    } else {
                        localStorage.setItem('token', data.body.token);

                        const next = localStorage.getItem('after_login') || 'consent';
                        if (next === 'consent') props.action('consent');
                        else if (next === 'select_account') props.action('select_account');
                        else window.close();
                    }
                });
        }
    }

    return (
        <>
            <h1>Login</h1>
            <span
                ref={errorRef}
                style={{
                    borderColor: 'red',
                    backgroundColor: '#ff4545',
                    color: 'white',
                    padding: '5px',
                    borderWidth: '1px',
                    borderRadius: '5px',
                    display: 'none',
                }}></span>
            <br />
            <br />
            <br />
            <form onSubmit={onSubmit}>
                <label htmlFor="username">Email/Username</label>
                <br />
                <input type="text" id="username" name="username" />
                <br />
                <label htmlFor="password">Password</label>
                <br />
                <input type="password" id="password" name="password" />
                <br />
                <button type="submit">Login</button>
            </form>
        </>
    );
}

export default Login;
