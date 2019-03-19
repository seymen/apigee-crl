'use strict';

const apickli = require('apickli');
const {Before, setDefaultTimeout} = require('cucumber');
const config = require('../../config.js');

Before(function({Before}) {
  this.apickli = new apickli.Apickli(config.protocol, config.domain, './features/fixtures');
  this.apickli.addRequestHeader('Cache-Control', 'no-cache');

  const self = this;
  Object.keys(config).map(function(key) {
    self.apickli.scenarioVariables[key] = config[key];
  });
});

setDefaultTimeout(10 * 1000);
