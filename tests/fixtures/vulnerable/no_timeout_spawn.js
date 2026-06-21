// Vulnerable: spawn/execFile without timeout
const { spawn, execFile } = require('child_process');

function run(args) {
  spawn("ls", ["-la"]);
  execFile("node", ["script.js"]);
}
