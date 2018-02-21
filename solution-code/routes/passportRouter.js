const express        = require("express");
const router         = express.Router();

// User model
const User           = require("../models/user");

// Bcrypt to encrypt passwords
const bcrypt         = require("bcrypt");
const bcryptSalt     = 10;

// Iteration 3 - Private Page
const ensureLogin = require("connect-ensure-login");

const passport      = require("passport");



// Iteration 1 - Signup

router.get("/signup", (req, res, next) => {
  // Point it to your "views/passport/signup.ejs"
  res.render("passport/signup");
});

router.post("/signup", (req, res, next) => {
  var username = req.body.username;
  var password = req.body.password;

  if (username === "" || password === "") {
    res.render("passport/signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
    if (user !== null) {
      res.render("passport/signup", { message: "The username already exists" });
      return;
    }

    var salt     = bcrypt.genSaltSync(bcryptSalt);
    var hashPass = bcrypt.hashSync(password, salt);

    var newUser = User({
      username,
      password: hashPass
    });

    newUser.save((err) => {
      if (err) {
        res.render("passport/signup", { message: "The username already exists" });
      } else {
        res.redirect("/login");
      }
    });
  });
});

// Iteration 2 - Login Feature

router.get("/login", (req, res, next) => {
  res.render("passport/login", { "message": req.flash("error") });
});


router.post("/login", passport.authenticate("local", {
  successRedirect: "/private-page",
  failureRedirect: "/login",
  failureFlash: true,
  passReqToCallback: true
}));

// Iteration 3 - Private Page
router.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});

// Optional "Log Out" Function
router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/login");
});

module.exports = router;
