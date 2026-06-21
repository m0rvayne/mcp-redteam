// Vulnerable: non-literal args to exec/execSync/spawn
const { exec, execSync, spawn } = require('child_process');

function runTool(args) {
  const cmd = args.command;
  exec(cmd);
  execSync(cmd);
  spawn(cmd, ["-la"]);
  execSync(`ls ${cmd}`);
}
