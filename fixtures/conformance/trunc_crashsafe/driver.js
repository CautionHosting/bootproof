#!/usr/bin/env node
// driver.js — the 3-line thin-driver shape (ratified). Zero truth here: every
// expectation is in expectations.json; the harness owns evaluation + loaders.
const { run } = require('../harness.js');
const impl = process.argv[2] || 'bootproof-js';
const allowSkip = process.argv.slice(3).includes('--allow-skip');
process.exit(run(__dirname + '/expectations.json', impl, { allowSkip }));
