const loginForm = document.getElementById('loginForm');
const messageDiv = document.getElementById('message');

function validateForm(email, password) {
  // Provide immediate feedback, while the server repeats these checks as the security boundary.
  if (!email || !password) {
    return 'Both fields are required.';
  }

  if (!email.includes('@')) {
    return 'Email must contain an "@" symbol.';
  }

  if (password.length < 8 || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return 'Password must be at least 8 characters and include a number and special character.';
  }

  return '';
}

loginForm.addEventListener('submit', async (event) => {
  // Keep the page from reloading and submit the credentials with fetch instead.
  event.preventDefault();

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const validationError = validateForm(email, password);

  messageDiv.className = '';
  messageDiv.textContent = '';

  if (validationError) {
    // Do not send obviously invalid input to the server.
    messageDiv.className = 'error';
    messageDiv.textContent = validationError;
    return;
  }

  try {
    // The server validates again, checks the bcrypt hash, and enforces lockout rules.
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const result = await response.json();

    // Use textContent so server messages are displayed as text rather than interpreted as HTML.
    messageDiv.className = response.ok ? 'success' : 'error';
    messageDiv.textContent = result.message;
  } catch (error) {
    // Handle network failures separately from rejected login credentials.
    messageDiv.className = 'error';
    messageDiv.textContent = 'Unable to reach the server.';
  }
});