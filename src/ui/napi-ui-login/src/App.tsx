import { useState } from 'react';
import Consent from './Consent';
import Login from './Login';
import SelectAccount from './SelectAccount';

function App() {
    const [action, setAction] = useState(localStorage.getItem('action') || 'login');

    return (
        <>
            {action === 'login' ? (
                <Login action={setAction} />
            ) : action === 'select_account' ? (
                <SelectAccount action={setAction} />
            ) : action === 'consent' ? (
                <Consent action={setAction} />
            ) : (
                <>oops</>
            )}
        </>
    );
}

export default App;
