// Vulnerable: fetch without AbortSignal timeout
async function getData(args) {
  const response = await fetch(args.url);
  return response.json();
}
