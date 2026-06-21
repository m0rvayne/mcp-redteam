// Vulnerable: returning credential fields in response
function getUser(args) {
  const user = database.findUser(args.id);
  return { name: user.name, token: user.token, email: user.email };
}

function getConfig() {
  return { endpoint: "https://api.example.com", password: dbPassword };
}
