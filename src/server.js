import * as url from 'url';
import Promise from 'promise';
import passport from 'moped-runtime/lib/passport';
import GitHubStrategy from 'passport-github2';

export const name = 'github';

function encode(input) {
  return new Buffer(input).toString('base64')
    .replace(/\//g, '_')
    .replace(/\+/g, '-');
}
function decode(input) {
  return new Buffer(
    input
      .replace(/\_/g, '/')
      .replace(/\-/g, '+'),
    'base64',
  ).toString();
}

let configured = false;
function defaultVerifier(accessToken, refreshToken, profile, done) {
  profile.accessToken = accessToken;
  profile.refreshToken = refreshToken;
  return profile;
}
export default function configure(verify = defaultVerifier) {
  if (configured) {
    throw new Error('GitHub authentication can only be configured once');
  }
  configured = true;
  const {GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, DOMAIN_NAME} = process.env;

  let returnLocation;
  if (!DOMAIN_NAME) {
    if (process.env.NODE_ENV === 'production') {
      console.error('You must configure a DOMAIN_NAME environment variable.');
      console.error('This should be the domain at which you host your application.  e.g.');
      console.error('www.example.com');
      process.exit(1);
    } else {
      returnLocation = 'http://localhost:' + (process.env.PORT || 3000);
    }
  } else if (process.env.NODE_ENV === 'production' && process.env.DISABLE_SSL !== 'true') {
    returnLocation = 'https://' + DOMAIN_NAME;
  } else {
    returnLocation = 'http://' + DOMAIN_NAME;
  }
  if (!(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET)) {
    console.error('To use GitHub authenciation in your application, you must register your app at:');
    console.error('');
    console.error('  https://github.com/settings/developers');
    console.error('');
    console.error('You should set the "Authorization callback URL" to:');
    console.error('');
    console.error('  ' + returnLocation + '/auth/github');
    console.error('');
    if (process.env.NODE_ENV !== 'production') {
      console.error('You will need to set up a separate application for your production environment.');
      console.error('');
    }
    console.error('Once your application has been set up, you need to create two environment variables:');
    console.error('');
    console.error('  GITHUB_CLIENT_ID: Copy the "Client ID" value from GitHub');
    console.error('  GITHUB_CLIENT_SECRET: Copy the "Client Secret" value from GitHub');
    process.exit(1);
  }
  passport.use(name, new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
  }, (accessToken, refreshToken, profile, done) => {
    Promise.resolve(verify(accessToken, refreshToken, profile)).nodeify(done);
  }));
  return (req, res, next) => {
    if (req.method === 'GET' && req.path === '/auth/' + name) {
      const returnURL = url.parse(req.query.returnURL || '/');
      passport.authenticate(name, {
        callbackURL: returnLocation + '/auth/' + name + '/callback/' + encode(returnURL.path) + '/',
        scope: req.query.scope,
      })(req, res, next);
      return;
    }
    let match;
    if (req.method === 'GET' && (match = /^\/auth\/github\/callback\/([^\/]*)\/$/.exec(req.path))) {
      const returnURL = url.parse(decode(match[1]));
      passport.authenticate(name, {successRedirect: returnURL.path, failureRedirect: returnURL.path})(req, res, next);
      return;
    }
    next();
  };
}
