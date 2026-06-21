// Vulnerable: non-literal path to fs operations
const fs = require('fs');

function readFile(args) {
  const filePath = args.path;
  fs.readFileSync(filePath, 'utf8');
  fs.writeFile(filePath, 'data', () => {});
  fs.createReadStream(filePath);
}
