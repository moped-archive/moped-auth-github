import {stringify} from 'querystring';

export default function getUrl(options) {
  // returnURL
  // scope
  return '/auth/github?' + stringify(options);
}
