const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const User = require('./user.model');
const handlebar = require('express-handlebars');
const flash =  require('connect-flash');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const LocalStrategy = require('passport-local').Strategy;
const validator = require('express-validator');
const mongo = require('mongodb');
const path = require('path');

const router = express.Router();
const app = express();
const port = process.env.PORT || 3000;
const db = "mongodb://localhost:27017/usersData";

app.set('views', path.join(__dirname, 'views'));
app.engine('hbs', handlebar({extname: 'hbs', defaultLayout: 'layout', layoutsDir: __dirname + '/views/layouts/'}));
app.set('view engine', 'hbs');

app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
     secret: "Itissavedincookies",
     saveUninitialized: true,
     resave: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(validator());
app.use('/', router);

app.use((req,res, next)=>{
	res.locals.sucMsg = req.flash('sucMsg');
	res.locals.errMsg = req.flash('errMsg');
	res.locals.error = req.flash('error');
	next();
});

passport.serializeUser((user, done)=>{
		done(null, user.id);
});

passport.deserializeUser((id, done)=>{
	User.findById(id,(err, user)=>{
		done(err, user);
	});
});

passport.use('local-login', new LocalStrategy({passReqToCallback : true},
  (req, username, password, done)=>{
    User.findOne({ 'username': username },(err, user)=>{
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, req.flash('errMsg', 'Incorrect username.'));
      }
      bcrypt.compare(password, user.password, (err, res)=>{
	       if(res === true){
	       	 return done(null, user);
	       }else{
	       	 return done(null, false, req.flash('errMsg','Invalid password.'));
	       }
      })
    });
  }
));


mongoose.Promise = global.Promise;
mongoose.connection.openUri(db);

router.get('/',(req, res)=>{
     res.render('index', {title: 'Dashboard', msg: 'Welcome to our website' });
});


router.get('/register', (req, res)=>{
     res.render('singup');
});

router.post('/register', (req, res)=>{

	 req.checkBody('username', 'Invalid username').notEmpty();
	 req.checkBody('email', 'Invalid email').isEmail();
	 req.checkBody('password', 'Password is required').notEmpty();
	 req.checkBody('passwordConfirm', 'Password should match').equals(req.body.password);

	 var errors = req.validationErrors();

	 if(errors){
	 	res.render('singup', {errors: errors});
	 }else{
         bcrypt.genSalt(10,(err, salt)=>{
		    bcrypt.hash(req.body.password, salt,(err, hash)=>{
		    	var newUser = {
		    		username: req.body.username,
		    		email: req.body.email,
		    		password: hash
		    	}
		        User.create(newUser)
			    .then(user=>{
		                res.render('login', {username: user.username});
			    }).catch(err=> console.log(err)); 
		    });
		});
	 	 
	 } 
});


router.post('/login',(req, res, next)=>{
		passport.authenticate('local-login',(err, user, info)=>{
	    if (err) { return next(err); }
	    if (!user) { return res.redirect('/login'); }
	    req.logIn(user,(err)=>{
	      if (err) { return next(err); }
	       req.flash('username', user.username)
	      return res.redirect('/');
	    });
    })(req, res, next);}
      // passport.authenticate('local', { successRedirect: '/dashboard',
	     //                               failureRedirect: '/login',
	     //                               failureFlash: true })
);

router.get('/',checkAuthentication, (req, res)=>{
	     res.render('index', {title: 'Dashboard', msg: 'Welcome to your dashboard ' + req.flash('username')});
	});

router.get('/login', (req, res)=>{
     res.render('login');
});

router.get('/logout', (req, res)=>{
	req.logout();
	req.flash('sucMsg', 'Seuccessfully logout');
	res.redirect('/login');
});

function checkAuthentication(req,res,next){
    if(req.isAuthenticated()){
        next();
    } else{
    	req.flash('errMsg', 'Wrong username & password');
        res.redirect("/login");
    }
}

app.listen(port, ()=> console.log('Server is running on port ' + port));