'use strict'
const { VM } = require('vm2')
const src = require('fs').readFileSync(0, 'utf8')
const vm = new VM({ timeout: 2000 })
try { vm.run(src) }
catch (e) { process.stderr.write(String((e && e.stack) || e) + '\n') }
