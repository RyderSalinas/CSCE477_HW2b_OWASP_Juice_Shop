const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const port = process.env.PORT || 3000;
const rootDirectory = __dirname;
const maxLoginAttempts = 5;
const lockoutDurationMs = 60_000;
const sessions = new Map();
const database = new sqlite3.Database(path.join(rootDirectory, 'login-demo.sqlite'));

function sendJson(response, statusCode, body) {
  // Return consistent JSON responses and prevent browsers from caching login data.
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  response.end(JSON.stringify(body));
}

function getSessionId(request, response) {
  // Give each browser a server-side session so failed-login limits cannot be
  // reset by simply submitting another request from the same browser.
  const cookieHeader = request.headers.cookie || '';
  const sessionCookie = cookieHeader
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith('sessionId='));
  const existingSessionId = sessionCookie && sessionCookie.split('=')[1];

  if (existingSessionId && sessions.has(existingSessionId)) {
    return existingSessionId;
  }

  const sessionId = crypto.randomBytes(32).toString('hex');
  sessions.set(sessionId, { failedAttempts: 0, lockedUntil: 0 });
  response.setHeader(
    'Set-Cookie',
    `sessionId=${sessionId}; HttpOnly; SameSite=Strict; Path=/`
  );
  return sessionId;
}

function validateLogin(data) {
  // Validate untrusted request data before querying the database or checking a password.
  if (!data || typeof data.email !== 'string' || typeof data.password !== 'string') {
    return 'Email and password are required.';
  }

  if (!data.email.trim() || !data.password) {
    return 'Email and password are required.';
  }

  if (!data.email.includes('@')) {
    return 'Email must contain an "@" symbol.';
  }

  if (data.password.length < 8 || !/\d/.test(data.password) || !/[^A-Za-z0-9]/.test(data.password)) {
    return 'Password must be at least 8 characters and include a number and special character.';
  }

  return '';
}

function initializeDatabase() {
  // Create the table once, then seed any missing demo accounts with bcrypt hashes.
  return new Promise((resolve, reject) => {
    database.serialize(() => {
      database.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
        )
      `, (error) => {
        if (error) {
          reject(error);
          return;
        }

        // ADD NEW TEST USERS HERE. Use a strong plaintext password; it is hashed below
        // before it is stored in SQLite. Existing email addresses are not overwritten.
        const profiles = [
          { email: 'student@example.com', password: 'Password1!', role: 'user' },
          { email: 'admin@example.com', password: 'AdminPass1!', role: 'admin' },
          { email: 'analyst@example.com', password: 'Analyst1!', role: 'user' }
        ];

        // Hash each password before using the parameterized INSERT statement.
        Promise.all(profiles.map(async (profile) => ({
          ...profile,
          passwordHash: await bcrypt.hash(profile.password, 12)
        }))).then((hashedProfiles) => {
          const statement = database.prepare(
            'INSERT OR IGNORE INTO users (email, password_hash, role) VALUES (?, ?, ?)'
          );
          hashedProfiles.forEach((profile) => {
            statement.run(profile.email, profile.passwordHash, profile.role);
          });
          statement.finalize((finalizeError) => {
            if (finalizeError) {
              reject(finalizeError);
              return;
            }
            resolve();
          });
        }).catch(reject);
      });
    });
  });
}

function findUserByEmail(email) {
  // The placeholder prevents email input from being interpreted as SQL code.
  return new Promise((resolve, reject) => {
    database.get(
      'SELECT id, email, password_hash, role FROM users WHERE email = ?',
      [email],
      (error, user) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(user);
      }
    );
  });
}

function serveIndex(response) {
  fs.readFile(path.join(rootDirectory, 'index.html'), (error, content) => {
    if (error) {
      response.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      response.end('Unable to load the page.');
      return;
    }
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end(content);
  });
}

const server = http.createServer((request, response) => {
  if (request.method === 'GET' && request.url === '/') {
    serveIndex(response);
    return;
  }

  if (request.method === 'GET' && request.url === '/script.js') {
    fs.createReadStream(path.join(rootDirectory, 'script.js')).pipe(response);
    return;
  }

  if (request.method !== 'POST' || request.url !== '/api/login') {
    sendJson(response, 404, { message: 'Not found.' });
    return;
  }

  let requestBody = '';
  request.on('data', (chunk) => {
    requestBody += chunk;
    if (requestBody.length > 10_000) {
      request.destroy();
    }
  });

  request.on('end', () => {
    // Parse the request body before applying session limits and authentication checks.
    let data;
    try {
      data = JSON.parse(requestBody);
    } catch (error) {
      sendJson(response, 400, { message: 'Request body must be valid JSON.' });
      return;
    }

    const sessionId = getSessionId(request, response);
    const session = sessions.get(sessionId);
    const now = Date.now();

    if (session.lockedUntil > now) {
      // Reject requests during the one-minute lockout window.
      const retryAfterSeconds = Math.ceil((session.lockedUntil - now) / 1000);
      response.setHeader('Retry-After', retryAfterSeconds);
      sendJson(response, 429, {
        message: `Too many failed attempts. Try again in ${retryAfterSeconds} seconds.`
      });
      return;
    }

    const validationError = validateLogin(data);
    if (validationError) {
      // Invalid input counts as a failed attempt so malformed requests cannot bypass rate limiting.
      session.failedAttempts += 1;
      if (session.failedAttempts >= maxLoginAttempts) {
        session.lockedUntil = now + lockoutDurationMs;
      }
      sendJson(response, 400, { message: validationError });
      return;
    }

    // Look up the account, then compare the submitted password with its bcrypt hash.
    findUserByEmail(data.email.trim()).then((user) => {
      if (!user) {
        return false;
      }
      return bcrypt.compare(data.password, user.password_hash).then((passwordMatches) => ({
        passwordMatches,
        user
      }));
    }).then((authenticationResult) => {
      if (!authenticationResult || !authenticationResult.passwordMatches) {
        session.failedAttempts += 1;
        if (session.failedAttempts >= maxLoginAttempts) {
          session.lockedUntil = Date.now() + lockoutDurationMs;
        }
        sendJson(response, 401, { message: 'Invalid email or password.' });
        return;
      }

      session.failedAttempts = 0;
      session.lockedUntil = 0;
      sendJson(response, 200, {
        message: 'Login successful.',
        profile: {
          email: authenticationResult.user.email,
          role: authenticationResult.user.role
        }
      });
    }).catch(() => {
      sendJson(response, 500, { message: 'Unable to process login.' });
    });
  });
});

initializeDatabase().then(() => {
  // Do not accept login traffic until the schema and demo accounts are ready.
  server.listen(port, () => {
    console.log(`Login demo running at http://localhost:${port}`);
  });
}).catch(() => {
  console.error('Unable to initialize password hashing.');
  process.exitCode = 1;
});