var express = require('express')
  , app       = express()
  , port      = process.env.PORT || 8080
  , mongoose  = require('mongoose')
  , passport  = require('passport')
  , flash     = require('connect-flash');

var configDB  = require('./config/database.js');

// configuration =====
mongoose.connect(configDB.url);
// pass passport for configuration
// require('./config/passport.js')(passport);

app.configure(function() {
  // set up express app
  app.use(express.logger('dev'));
  app.use(express.cookieParser());
  app.use(express.bodyParser());

  app.set('view engine', 'ejs');

  app.use(express.session({ secret: 'iloveemiliesomuch' }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(flash());
});

// routes =====
require('./app/routes.js')(app, passport);

// launch =====
app.listen(port);
console.log('Welcome to fun on port ' + port);
