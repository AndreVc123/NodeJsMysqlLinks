const passport = require('passport');
const LocalStrategy = require('passport-local');
const pool = require('../database');
const helpers = require('./handlebars');
const helpears = require('./helpers');

passport.use('local.signup', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) => {
    const { fullname } = req.body;

    const newPassword = await helpears.encryptPassword(password);

    const newUser = {
        username,
        password: newPassword,
        fullname
    }

    const result = await pool.query('INSERT INTO users SET ? ', [newUser]);
    newUser.id = result.insertId

    return done(null, newUser);

}));

passport.use('local.signin', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) => {
    const rows = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

    if(rows.length > 0) {
        const user = rows[0];
        const validPassword = await helpears.matchPassword(password, user.password);

        if(validPassword) {
            done(null, user, req.flash('success','Welcome ' + user.username));
        }else {
            done(null, false, req.flash('message', 'The Username o Password Incorrect'));
        }
    }else {
        return done(null, false, req.flash('message', 'The Username o Password Incorrect'));
    }


}))


passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const filas = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
    done(null, filas[0]);
})