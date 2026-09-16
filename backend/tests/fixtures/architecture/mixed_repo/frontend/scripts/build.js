const path = require('path')
const helpers = require('./helpers')
const plugin = require(process.env.PLUGIN_NAME)
const missing = require('./does-not-exist')

module.exports = { out: path.join(__dirname, 'dist'), helpers, plugin, missing }
