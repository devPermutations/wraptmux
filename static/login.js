document.getElementById('login-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    var errEl = document.getElementById('error');
    errEl.textContent = '';
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    try {
        var resp = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password }),
        });
        if (resp.ok) {
            window.location.href = '/';
        } else {
            errEl.textContent = 'Invalid username or password';
        }
    } catch (ex) {
        errEl.textContent = 'Connection error';
    }
});
