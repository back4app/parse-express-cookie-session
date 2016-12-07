const _ = require("underscore");

const _defaultUserGet = Parse.User.prototype.get;

/**
 * This will forcefully set the sessionToken in the user object.
 * Will try more reliable ways first, falling back to simply
 * replacing the getSessionToken function in the User object.
 */
function setSessionToken(user, sessionToken) {
  // Prevent messing with obj if it's already working
  if (user.getSessionToken() === sessionToken) return;

  if (typeof user._finishFetch === 'function') {
    user._finishFetch({sessionToken: sessionToken});
  }

  if (user.getSessionToken() === sessionToken) {
    return;
  }

  user.get = function (attr) {
    if (attr === 'sessionToken') {
      return sessionToken;
    }
    _defaultUserGet.apply(this, arguments);
  };

  if (user.getSessionToken() !== sessionToken) {
    user.get = _defaultUserGet;
    user.getSessionToken = function () {
      return sessionToken;
    }
  }
}

module.exports = function (options) {
  options = options || {};
  var key = options.key || 'parse.sess';
  var cookieOptions = options.cookie || {};
  var forcedCookieOptions = {httpOnly: true, secure: true, signed: true};
  // forcedCookieOptions will overwrite same keys in cookieOptions.
  cookieOptions = _.extend({path: '/', maxAge: null, httpOnly: true},
    _.defaults(forcedCookieOptions, cookieOptions));

  return function parseExpressCookieSession(req, res, next) {
    // Expect cookieParser to set req.secret before this middleware.
    if (_.isEmpty(req.secret)) {
      throw new Error('cookieParser middleware must be included before this one and initialized with a signing secret');
    }

    // Ignore if cookie path does not match
    if (req.originalUrl.indexOf(cookieOptions.path) !== 0) {
      return next();
    }

    // Add login method to req
    req.logIn = function () {
      return Parse.User.logIn.apply(Parse.User, arguments)
        .then(function (user) {
          req.user = user;
          res.cookie(key, JSON.stringify({id: user.id, sessionToken: user.getSessionToken()}), cookieOptions);
          return Parse.Promise.as(user);
        }, function (err) {
          return Parse.Promise.error(err);
        });
    };

    // Parse the signed cookie.
    // Assume cookieParser already verified the signature and put the
    // cookie's contents at req.signedCookies[key].
    var reqCookieJson;
    var reqCookieBody = req.signedCookies[key];
    if (!_.isEmpty(reqCookieBody)) {
      try {
        reqCookieJson = JSON.parse(reqCookieBody);
      } catch (e) {
        // Catch any JSON parsing exceptions.
      }
    }

    var user = null;
    if (reqCookieJson && reqCookieJson.id && reqCookieJson.sessionToken) {
      // Create new user
      user = new Parse.User({id: reqCookieJson.id});
      setSessionToken(user, reqCookieJson.sessionToken);
    }
    req.user = user;

    req.logOut = function () {
      if (user === null) {
        return;
      }

      req.user = null;
      res.clearCookie(key);

      return Parse.Cloud.httpRequest({
        method: 'POST',
        url: Parse.serverURL + '/logout',
        headers: {
          'X-Parse-Application-Id': Parse.applicationId,
          'X-Parse-Javascript-Key': Parse.javaScriptKey,
          'X-Parse-Session-Token': user.getSessionToken()
        }
      })
        .then(
          function (httpResponse) {
            return Parse.Promise.as(httpResponse);
          },
          function (httpResponse) {
            return Parse.Promise.error(httpResponse);
          });
    };

    if (options.fetchUser && user !== null) {
      user.fetch()
        .then(
          function (user) {
            req.user = user;
            setSessionToken(user, reqCookieJson.sessionToken);
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