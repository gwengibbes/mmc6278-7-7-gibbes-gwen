# Module 7 Assignment: Adding authentication

(**NOTE:** View a rendered version of this file in VS Code with `ctrl-shift-v` or `cmd-shift-v`)

&nbsp;
## Introduction

For this assignment, you will be adding authentication to the Music Shop application. [You can see an example of the completed application here](https://music-shop-auth.herokuapp.com/).

&nbsp;
## Setup

Copy the starter files inside of `unsolved` into the root directory of your GitHub repository.

Ensure you include a `.gitignore` file in your repo that includes at minimum:

```
**/.DS_Store
**/node_modules/
.env
```

Run `npm i` in the root directory of your repository (your `package.json` should be in the root directory).

You'll see that there is a `.env.EXAMPLE` file included in the unsolved folder. You'll need to create a `.env` file with the same contents, but replace the fake session key with your own value. This can be any string of words or characters (no spaces).

&nbsp;
## Instructions

First, open `schema/schema.sql` and add the user table and a foreign key on the cart table. This will allow users to make accounts, login, and associate cart data with individual accounts.

You'll also need to add code to `app.js` to set Express to use sessions. Import `express-sessions` and the MySQL store package, as well as `db.js`, which allows the sessions package to communicate with MySQL:

```js
const session = require('express-session')
const MySQLStore = require('express-mysql-session')(session);
const db = require('./db')
```
&nbsp;

Then add the following code to set Express up with sessions:

```js
const sessionStore = new MySQLStore({}, db);
app.use(session({
	key: 'session_cookie',
	secret: process.env.SESSION_SECRET,
	store: sessionStore,
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		maxAge: 1000 * 60 * 60 * 24
	}
}));
```
&nbsp;

Next, open `routes/api-routes.js` and follow the instructions within to implement the following routes:

- POST to /user
- POST to /login
- GET to /logout

The login page routes are already created for you in `routes/html-routes.js` along with handlebars templates for the create account and login pages. Do note how the HTML and API routes employ `req.session.loggedIn`, as well as how the handlebars templates respond to authenticated vs unauthenticated users.

Also note that a number of routes are using the `checkAuth` middleware function to prevent unauthenticated users from accessing them. Navigate to `/middleware/auth.js` and follow the instructions to implement the `checkAuth` middleware.

Finally, deploy your application to [Heroku](https://www.heroku.com/) and use JawsDB for the production database.

&nbsp;
## App Behavior

The completed application should behave in the same manner as [this example](https://music-shop-hbs.herokuapp.com/).

To run the application locally, run:

```
npm run dev
```

You can then navigate to [http://localhost:3000](http://localhost:3000) to view the application.

&nbsp;
## Testing

Automated tests are included with this assignment. To receive full credit, all automated tests must pass.

To run the tests once, run:

```
npm test
```

To run the tests in watch mode, run:

```
npm run test:watch
```

&nbsp;
## Requirements for full credit

To receive full credit for this assignment, your program MUST:

  * Be implemented according to the above [instructions](#instructions).
  * Be deployed to Heroku with a JawsDB-powered database that is seeded.
  * Pass all automated tests.

&nbsp;
## Submission

When submitting this assignment, please include:

  * A link to the assignment's GitHub repository.
  * A link to the deployed application on Heroku.
  * A screenshot of the automated test results.