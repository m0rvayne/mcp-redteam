// Vulnerable: non-literal arg to eval/new Function
function compute(args) {
  const expr = args.expression;
  eval(expr);
  const fn = new Function(expr);
}
