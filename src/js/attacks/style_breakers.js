function singleQuote(attackNumber)                { return "\""; }
function quoteAngleBracket(attackNumber)          { return "\">"; }
function quoteAngleBracketCloseForm(attackNumber) { return "\"></form>"; }
function angleBracket(attackNumber)               { return ">"; }
function angleBracketCloseForm(attackNumber)      { return "></form>"; }
function semiColon(attackNumber)                  { return ";"; }
function semiColonQuote(attackNumber)             { return ";\""; }
function semiColonQuoteAngleBracket(attackNumber) { return ";\">"; }

var styleBreakerAttacks = [
  singleQuote,
  quoteAngleBracket,
  quoteAngleBracketCloseForm,
  angleBracket,
  angleBracketCloseForm,
  semiColon,
  semiColonQuote,
  semiColonQuoteAngleBracket
]
