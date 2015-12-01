/* Sample code for CS290 final project: Passport.js How-To */

var express = require('express');

var app = express();
var handlebars = require('express-handlebars').create({defaultLayout:'main'});
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.engine('handlebars', handlebars.engine);
app.set('view engine', 'handlebars');
app.set('port', 3000);

//setup for sessions
var session = require('express-session');
app.use(session({secret: 'superSecret'}));

//setup for flash messages
var flash = require('connect-flash');
app.use(flash());

//some files for processing and storing passwords
var hash = require('./hash');
var credentials = require('./credentials');
var request = require('request');

//database configuration
var mysql = require('mysql');
var pool = mysql.createPool({
	host: 'localhost',
	user: credentials.dbuser,
	password: credentials.dbpass,
	database: credentials.dbname
});

//Passport authentication configuration
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var RememberMeStrategy = require('passport-remember-me').Strategy;
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var GitHubStrategy = require('passport-github2').Strategy;
app.use(passport.initialize());
app.use(passport.session());
app.use(passport.authenticate('remember-me'));

//Serialize and Deserialize functions to be used by passport.session
passport.serializeUser(function(user, done){
	done(null, user.id);
});
passport.deserializeUser(function(id, done){
	pool.query('SELECT * FROM user WHERE id=?', [id], function(err, rows, fields){
		var user = rows[0];
		if (user.github_usrn)
			user.username = user.usrn;
		done(err, user);
	});
});

//Configuration of the username/password ('local') password strategy.
//It contains an object with optional parameters and a verify function.
passport.use(new LocalStrategy(
	function(username, password, done){
		pool.query('SELECT * FROM user WHERE username=?', [username], 
			function(err, rows, fields){
			var user = rows[0];
			if (err){ 
				return done(err);
			}
			if (!user){
				return done(null, false, {message: 'Incorrect username'});
			}
			if (!hash.isValid(password, user.password_hash)){
				return done(null, false);
			}
			return done(null, user);
		});
	})
);

//Configuration for remember-me strategy, containing
//a verify and an issue callback
passport.use(new RememberMeStrategy(
	function(token, done){

		pool.query('SELECT * FROM user WHERE token_hash=?', 
			[hash.hashToken(token)],
			function(err, rows, fields){	
				var user = rows[0];

				if (err) return done(err);
				
				if (!user) return done(null, false);
				
				return done(null, user);

		});
		
	},

	function(user, done){
		var token = hash.generateToken();
		pool.query('UPDATE user SET token_hash=? WHERE id=?',
			[hash.hashToken(token), user.id],
			function(err, result){
				if (err) return done(err);
				return done(null, token);
		});
	})
);


//Configuration for generic AOuth2 strategy (using GitHub).
//In this case, this is a session-less authorization strategy.
passport.use('provider', new OAuth2Strategy({
		authorizationURL: 'https://github.com/login/oauth/authorize',
		tokenURL: 'https://github.com/login/oauth/access_token',
		clientID: credentials.gh_oauth_client_id,
		clientSecret: credentials.gh_oauth_client_secret,
		callbackURL: 'http://localhost:3000/auth/provider/callback'
	},
	function(accessToken, refreshToken, profile, done){
		var options = {
				url: 'https://api.github.com/users/' + username + 
				'?access_token=' + req.user.accessToken,
				headers: {
					'User-Agent': 'FancyApp'
				}
		}
		request(options, function(err, res, body){
			var username = JSON.parse(body).login;
			var user = {};
			user.accessToken = accessToken;
			user.username = username;
			return done(null, user);
		});			
	}
));

//Configuration for GitHub-specific AOuth2 strategy
passport.use(new GitHubStrategy({
	clientID: credentials.gh_oauth_client_id,
	clientSecret: credentials.gh_oauth_client_secret,
	callbackURL: 'http://localhost:3000/auth/github/callback'
},
function(accessToken, refreshToken, profile, done){

			if (!profile.id) return done(null, false);

			pool.query('SELECT * FROM user WHERE github_id=?', [profile.id],
				function(err, rows, fields){
				var user = rows[0];
				if (err) return done(err);
				
				if (!user){
					pool.query('INSERT INTO user (github_usrn, github_id) VALUES (?, ?)',
					[data.login, data.id], function(err, result){
						if (err) return done(err);

						pool.query('SELECT * FROM user WHERE id=?',
						[result.insertId], function(err, rows, fields){
							var newUser = rows[0];
							if(err) return done(err);
							return done(null, newUser);
						});
					});
				}
				else 
					return done(null, user);
				
			});
				
		})
);



//handler for home page
app.get('/', function(req, res){
	var context = {};
	context.user = req.user;
	/* The user may be null */
	res.render('home', context);
});


//handler for rendering sign up page
app.get('/signup', function(req, res){
	res.render('signup', {message: req.flash('error')});
});


//handler that signs up users with local strategy
app.post('/signup', function(req, res, next){
	var username = req.body.username;
	if (req.body.password != req.body.confirm)
		res.render('/signup', {error: 'Passwords do not match'});
		
	else{
		var password_hash = hash.hashPassword(req.body.password);
	

		pool.query('INSERT INTO user(username, password_hash) VALUES (?, ?)', 
			[username, password_hash], function(err, result){
			if (err){
				next(err);
				return;
			}
			pool.query('SELECT * FROM user WHERE id=?', [result.insertId],
				function(err, rows, fields){
					var user = rows[0];
					if (err){
						next(err);
						return;
					}
					req.login(user, function(err){
						if (err){
							next(err);
							return;
						}
						res.redirect('/');
					});
				});

			});
	}
});


//handler that renders log in form
app.get('/login', function(req, res){
	res.render('login', {message: req.flash('error')});
});

//handler for logging in with local strategy
app.post('/login', passport.authenticate('local', {failureRedirect: '/login',
	failureFlash: true}),
	function(req, res){
		if (req.body.remember_me == 'on'){
			//create token and store it in database
			var token = hash.generateToken();
			//put the plain token in a remember-me cookie
			res.cookie('remember_me', token, {path: '/', httpOnly: true, 
				maxAge: 604800000});
			pool.query('UPDATE user SET token_hash=? WHERE id=?', 
				[hash.hashToken(token), req.user.id],
				function(err, result){
					if (err) return done(err);
					res.redirect('/');
			});
		}
		else{
			res.redirect('/');
		}
});


//handler to log out with any strategy
app.get('/logout', function(req, res){
	res.clearCookie('remember_me');
	req.logout();
	res.redirect('/');
});

//test handler for using session-less authentication
app.get('/get_data', function(req, res){
	res.redirect('/auth/provider');
});	


// //handler for user to log on with OAuth provider (github)
app.get('/auth/provider', passport.authenticate('provider', {scope: ['user', 'repo']}));

// //handler for redirection after user logs in with OAuth provider (github)
app.get('/auth/provider/callback', passport.authenticate('provider',
	{failureRedirect: '/login', session: false}),
	function(req, res){
		var options = {
			url: 'https://api.github.com/user?access_token='+req.user.accessToken,
			headers: {
				'User-Agent': 'FancyApp'
			}
		};
		request(options, function(err, response, body){
			var username = JSON.parse(body).login;
			options = {
				url: 'https://api.github.com/users/' + username + 
				'/followers?access_token=' + req.user.accessToken,
				headers: {
					'User-Agent': 'FancyApp'
				}}
			request(options, function(err, r, b){
				console.log(b);
				res.redirect('/');
			});
		}); 
	}
);



//handler for user to log on with github
app.get('/auth/github', passport.authenticate('github', {scope: ['user', 'repo']}));

//handler for redirection after user authenticates with github
app.get('/auth/github/callback', passport.authenticate('github',
	{successRedirect: '/', failureRedirect: '/login', session: false}));



//error handlers
app.use(function(req,res){
  res.status(404);
  res.render('404');
});

app.use(function(err, req, res, next){
  console.error(err.stack);
  res.type('plain/text');
  res.status(500);
  res.render('500');
});

app.listen(app.get('port'), function(){
  console.log('Express started on http://localhost:' + app.get('port') + '; press Ctrl-C to terminate.');
});
