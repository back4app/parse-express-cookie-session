const _ = require("underscore");

/**
 * This will forcefully set the sessionToken in the user object.
 * Will try more reliable ways first, falling back to simply
 * replacing the getSessionToken function in the User object.
 */
function setSessionToken(user, sessionToken) {
    if (typeof user._finishFetch === 'function') {
        user._finishFetch({sessionToken: sessionToken});
    }
    if (user.getSessionToken() == sessionToken) {
        return;
    }

    var oldGet = user.get;
    user.get = function (attr) {
        if (attr == 'sessionToken') {
            return sessionToken;
        }
        oldGet.apply(this, arguments);
    }
    if (user.getSessionToken() != sessionToken) {
        user.get = oldGet;
        user.getSessionToken = function () {
            return sessionToken;
        }
    }
}

module.exports = function (options) {
  options = options || {};
  var key = options.key || 'parse.sess';
  var cookieOptions = options.cookie || {};
  var forcedCookieOptions = {httpOnly: true, secure: true};
  // forcedCookieOptions will overwrite same keys in cookieOptions.
  cookieOptions = _.extend({path: '/', maxAge: null, httpOnly: true},
    _.defaults(forcedCookieOptions, cookieOptions));

  return function parseExpressCookieSession(req, res, next) {
    // Add login method to req
    req.logIn = function (username, password) {
      return Parse.User.logIn(username, password)
        .then(function (user) {
          res.cookie(key, JSON.stringify({id: user.id, sessionToken: user.getSessionToken()}));
          return user;
        }, function (err) {
          return err;
        })
    };

    req.logOut = function () {
      // TODO remove user session? Parse.User.logOut();
      res.cookie(key, '', {maxAge: 0});
    };

    // Expect cookieParser to set req.secret before this middleware.
    if (_.isEmpty(req.secret)) {
      throw new Error('cookieParser middleware must be included before this one and initialized with a signing secret');
    }

    // Ignore if cookie path does not match
    if (req.originalUrl.indexOf(cookieOptions.path) !== 0) {
      return next();
    }

    // Parse the signed cookie.
    // Assume cookieParser already verified the signature and put the
    // cookie's contents at req.signedCookies[key].
    var reqCookieJson;
    var reqCookieBody = req.cookies[key];
    if (!_.isEmpty(reqCookieBody)) {
      try {
        reqCookieJson = JSON.parse(reqCookieBody);
        if (reqCookieJson && !reqCookieJson.id || !reqCookieJson.sessionToken) {
          throw new Error("Invalid session");
        }
      } catch (e) {
        // Catch any JSON parsing exceptions.
        console.warn("Invalid Parse session cookie: ", e);
      }
    }

    var user = null;
    if (reqCookieJson && reqCookieJson.id && reqCookieJson.sessionToken) {
      // Create new user
      user = new Parse.User({id: reqCookieJson.id});
      setSessionToken(user, reqCookieJson.sessionToken);
    }
    req.user = user;

    if (options.fetchUser && user !== null) {
      user.fetch()
        .then(
          function (user) {
            if (user != req.user) {
              req.user = user;
              setSessionToken(user, reqCookieJson.sessionToken);
            }
            next();
          },
          function (err) {
            // If user from cookie is invalid, reset user to null.
            req.user = null;
            next();
          }
        );
    } else {
      next();
    }
  };
};