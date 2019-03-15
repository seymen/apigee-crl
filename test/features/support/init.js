'use strict';

const apickli = require('apickli');
const {Before, setDefaultTimeout} = require('cucumber');

Before(function({Before}) {
  this.apickli = new apickli.Apickli('http', 'localhost:9001', './features/fixtures');
  this.apickli.addRequestHeader('Cache-Control', 'no-cache');
});
