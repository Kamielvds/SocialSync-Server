const express = require('express');
const app = express();
const PORT = process.env.PORT || 4000;
const { pool } = require('./dbConfig');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');

const initializePassport = require('./passportConfig');

initializePassport(passport);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: 'secret',
    resave: 'false',
    saveUninitialized: 'false',
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/users/register', (req, res) => {
  res.render('register');
});

app.get('/users/login', (req, res) => {
  res.render('login');
});

app.get('/users/dashboard', (req, res) => {
  res.render('dashboard', { user: 'Kamiel' });
});

app.post('/users/register', async (req, res) => {
  let { name, email, password, password2 } = req.body;

  let errors = [];

  console.log({
    name,
    email,
    password,
    password2,
  });

  //#region password checks

  //fields
  if (!name || !email || !password || !password2) {
    errors.push({ message: 'Please enter all fields' });
  }

  //password
  if (password.length < 6) {
    errors.push({ message: 'Password must be a least 6 characters long' });
  }
  if (password !== password2) {
    errors.push({ message: 'Passwords do not match' });
  }

  // email
  if (!email.contains('@')) {
    errors.push({ message: 'Give a valid email' });
  }
  if (!email.split('@')[1].contains('.')) {
    errors.push({ message: 'Give a valid email' });
  }

  //#endregion

  if (errors.length > 0) {
    res.render('register', { errors, name, email, password, password2 });
  } else {
    hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    // Validation passed
    pool.query(
      `SELECT * FROM users
        WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          return res.render('register', {
            message: 'Email already registered',
          });
        } else {
          pool.query(
            `INSERT INTO users (name, email, password)
                VALUES ($1, $2, $3)
                RETURNING password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
              req.flash('success_msg', 'You are now registered. Please log in');
              res.redirect('/users/login');
            }
          );
        }
      }
    );
  }
});

app.post(
  '/users/login',
  passport.authenticate('local', {
    // redirect when logged in
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true,
  })
);

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});

app.use('/public', express.static('public'));
