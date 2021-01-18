
module.exports = {

    isLoggedIn(req, res, next) {
        if(req.isAuthenticated()) {
            next()
        }else {
            res.redirect('/auth/signin');
        }
    },

    isNotLoggedIn(req, res, next) {
        if(!req.isAuthenticated()) {
            next();
        }else {
            res.redirect('/auth/profile');
        }

    }

}