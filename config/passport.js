var LocalStrategy = require('passport-local').Strategy;
var User          = require('../app/models/user');

// the statement in server.js that requires this file is
// require(./config/passport.js)(passport), so passport gets passed in
module.exports = function(passport) {
  // passport session setup: serialize and deserialize users for persistent sessions
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

  // LOCAL SIGNUP ==============================================================
  passport.use('local-signup', new LocalStrategy({
    // by default local strategy uses username and password, override with email
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
  },
  function(req, email, password, done) {
    // wrap User.findOne in this so it won't fire unless data is returned
    process.nextTick(function() {
      User.findOne({ 'local.email': email }, function(err, user) {
        if (err)
          return done(err);

        if (user) {
          return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
        } else {
          // create a new user with the model we required earlier
          var newUser = new User();
          newUser.local.email    = email;
          newUser.local.password = newUser.generateHash(password);

          newUser.save(function(err) {
            if (err)
              throw new Error(err);
            return done(null, newUser);
          });
        }
      });
    });
  }));
  // LOCAL LOGIN ===============================================================
  passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
  },
  function(req, email, password, done) {
    User.findOne({ 'local.email': email }, function(err, user) {
      if (err)
        return done(err);

      if (!user)
        return done(null, false, req.flash('loginMessage', 'No user found.'));

      if (!user.validPassword(password))
        return done(null, false, req.flash('loginMessage', 'Oops! Wrong password'));

      return done(null, user);
    });
  }));
};
