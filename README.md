# OWASP Juice Shop Login Demo

This project is a CSCE 477 HW 2-B demonstration of a login form modeled after OWASP Juice Shop. It includes a browser form, a Node.js backend, bcrypt password hashing, and a SQLite database with user and admin profiles. It is intended for local security demonstrations, including testing how parameterized SQL queries prevent SQL injection.

## Project Structure

| File | Purpose |
| --- | --- |
| `index.html` | Login form and page layout. |
| `script.js` | Client-side validation and request submission. |
| `server.js` | HTTP server, database initialization, authentication, and login-attempt limits. |
| `login-demo.sqlite` | Local SQLite database created or updated when the server starts. |
| `schema.sql` | Reference schema for the `users` table. |
| `package.json` | Node.js project metadata and start command. |

## Requirements

- Node.js 18 or newer
- npm

## Running the Application

1. Clone the repository:

	```powershell
	git clone <YOUR_PUBLIC_GITHUB_REPOSITORY_URL>
	cd HW_2b_OWASP_Juice_Shop
	```

2. Install dependencies:

	```powershell
	npm install
	```

3. Start the server:

	```powershell
	npm start
	```

4. Open `http://localhost:3000` in a browser.

Opening `index.html` directly displays the form, but login requests require the Node.js server.

## Demo Accounts

The following profiles are seeded by `initializeDatabase()` in `server.js`:

| Email | Password | Role |
| --- | --- | --- |
| `student@example.com` | `Password1!` | User |
| `admin@example.com` | `AdminPass1!` | Admin |
| `analyst@example.com` | `Analyst1!` | User |
| `user2@example.com` | `secretPass1!` | User |

To add another local test account, add an object to the `profiles` array in `initializeDatabase()`. Existing email addresses are not overwritten because the seed query uses `INSERT OR IGNORE`.

## Security Measures

### Client and server validation

`script.js` checks that the email is nonempty, contains `@`, and that the password is at least eight characters long with a number and special character. `server.js` repeats these checks because client-side validation can be bypassed.

### Bcrypt password hashing

Passwords are hashed with bcrypt before being inserted into SQLite. Login uses `bcrypt.compare()` against the stored hash, so plaintext passwords are not stored or logged.

### Parameterized SQL

User lookup uses a parameterized query:

```javascript
database.get(
  'SELECT id, email, password_hash, role FROM users WHERE email = ?',
  [email],
  callback
);
```

Input such as `' OR 1=1 --` is treated as an email value rather than executable SQL, preventing the classic SQL injection login bypass.

### Session login limits

Each browser receives an HttpOnly session cookie. After five failed attempts, that session receives a 60-second lockout. A successful login resets the failure counter.

### Safe output handling

The client displays server messages with `textContent`, not `innerHTML`, so returned text is not interpreted as executable HTML or JavaScript.

## Inspecting the Database

`login-demo.sqlite` is the database file, and `users` is the table inside it. To visualize the database, open the file with [DB Browser for SQLite](https://sqlitebrowser.org/) or SQLiteStudio. The **Browse Data** view displays the records, and the **Database Structure** view displays the columns and constraints.

From a SQLite command-line installation:

```text
sqlite3 login-demo.sqlite
.schema users
SELECT id, email, role FROM users;
```

Do not replace `password_hash` with a plaintext password. To change test credentials, edit the `profiles` array in `server.js`, delete `login-demo.sqlite`, and restart the application so the database is recreated with new bcrypt hashes. Do not use these demo credentials in production.

## Security Testing

To test the SQL injection defense, submit the following as the email through a direct request or browser developer tools:

```text
' OR 1=1 --
```

Use a password that meets the client and server requirements, such as `Password1!`. The request should return `Invalid email or password.` rather than logging in. This demonstrates that the input is handled as data, not SQL code.

To test the lockout, submit invalid credentials five times within the same browser session. The sixth attempt should receive HTTP status `429` and a one-minute retry message.

## Production Considerations

This is an educational local demo. A production implementation should use HTTPS, secure production session storage, environment-managed configuration, account recovery, audit logging, a persistent database backup strategy, and a rate limiter that can coordinate across multiple server instances.