// Vulnerable: non-literal URL to fetch/axios
const axios = require('axios');

async function fetchUrl(args) {
  const url = args.url;
  await fetch(url);
  await axios.get(url);
}
