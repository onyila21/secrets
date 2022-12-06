const dotenv = require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// Using passport: hashing salting authentication
const session = require("express-session");
const passport = require("passport");

// Don't need to require passport local
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;// from our third party
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Use session with following confid ie set up session
app.use(
    session({
        secret: "MylittleSecret.",
        resave: false,
        saveUninitialized: false
    })
);
// Initialize passport
app.use(passport.initialize());

// Use passport to setup session
app.use(passport.session());
async function run() {

await mongoose.connect("mongodb+srv://admin-onyeka:<password>@cluster0.nnfn505.mongodb.net/secretDB", {
    useNewUrlParser: true,


    // useUnifiedTopology: true
});
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

// Plugin passportLocalMongoose to Schema
// This will hash, salt the password then save to mongoDB
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
await mongoose.model('User').findOne(); // Works!
}

// Simplified Passport/Passport-Local Configuration
passport.use(User.createStrategy());

// Create cookie and put user identification in it
// serialize creates cookies and stuff the message namely our user identification
// into the cookie while deserialize allows passport to crumble the cookie and
// discover the message inside to see who the user is and their identification
//copied from third party passport
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

// copied from our third party
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://onyila21-secrets.onrender.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" // to retrieve
    //their profile from user info instead of google+ which is depracated
  },
  //accessToken allows us to get data related from the user, refresh from the profile
  //findOrCreate helps if a user logs in if we have the id we find it else we create
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// -------FACEBOOK STRATEGY--------
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "https://onyila21-secrets.onrender.com/auth/facebook/secrets",
    enableProof: true
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id, username: profile.displayName},
      function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/", function(req, res) {
    res.render("home");
});

//for our third party login ie use passport to authenticate our user
// which we set up in tye google strategy in line 77 and we want the user profile
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  // -----FACEBOOK AUTHENTICATION-----
  app.get('/auth/facebook',
    passport.authenticate('facebook', { scope: ["email"] }));


  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect secrets.
      res.redirect('/secrets');
  });

app.get("/register", function(req, res) {
    res.render("register");
});

//to find all the secrets submitted in the database, not equal to null &ne
// ie it exists
app.get("/secrets", function(req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets", {usersWithSecret: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res) {
    // Check if an user if already logged in
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

// to save the secret after the user submits it
app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  console.log(req.user.id);

// to find the user and save the secret in their file
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save(function(){
        res.redirect("/secrets");
      });
      }
    }
  });
});

app.get("/logout",  function (req, res) {
res.render("home")
});

// Use passport local mongoose's .register() method for username and Password
// the user types in
app.post("/register", function(req, res) {
  User.register({ username: req.body.username }, req.body.password, function(err,user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            // we authenticate our user using Passport method local
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.post("/login", function(req, res){
const user = new User({
  username: req.body.username,
  password: req.body.password
});

// we use passport to login the user and authenticate them
req.login(user,function(err){
  if(err){ // if we cant find their details
    console.log(err);
  }else{
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
    });
  }
});

});

  app.listen(process.env.PORT || 3000, function(){
      console.log("Server started on port: 3000!");
  });

//callbackURL: "https://sleepy-castle-96772.herokuapp.com/auth/google/secrets","http://localhost:3000/auth/google/secrets",
