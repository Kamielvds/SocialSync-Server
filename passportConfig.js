const localStrategy = require('passport-local').Strategy;
const { authenticate } = require('passport');
const { pool } = require('./dbConfig');
const bcrypt = require('bcryptjs');

function initialize(passport) {
  const authenticateUser = (email, password, done) => {
    `SELECT * FROM users WHERE email = $1`,
      [email],
      (err, result) => {
        if (err) {
          throw err;
        }

        if (result.rows.length > 0) {
          const user = result.rows[0];

          bcrypt.compare(passport, user.password, (err, isMatching) => {
            if (err) throw err;
            if (isMatching) {
              return done(null, user);
            } else {
              return done(null, false, { message: 'Invalid credentials' });
            }
          });
        } else {
          return done(null, false, { message: 'Invalid credentials' });
        }
      };
  };
  passport.use(
    new localStrategy(
      {
        usernameField: 'email',
        passwordField: 'password',
      },
      authenticateUser
    )
  );

  passport.serializeuser((user, done) => done(null, user.id));

  passport.deserializeuser((email, done) => {
    pool.query(
      `SELECT * FROM users WHERE email = $1`,
      [email],
      (err, result) => {
        if (err) throw err;
        return done(null, result.rows[0]);
      }
    );
  });
}

module.exports = initialize;
