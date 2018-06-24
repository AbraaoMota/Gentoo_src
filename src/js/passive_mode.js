// Message handling logic - contains a flag to synchronously process messages
// to avoid async DB overwrites
var passiveMessageHandlerBusy = false;
var passiveRequestStored = false;
var passiveMessageHandler = function(message, sender, sendResponse) {

  if (passiveMessageHandlerBusy) {
    window.setTimeout(function() {
      passiveMessageHandler(message, sender, sendResponse);
    }, 0);
    return;
  }

  passiveMessageHandlerBusy = true;

  chrome.storage.local.get(function(storage) {
    var enablePassiveMode = storage["enablePassiveMode"];

    if (message.name === "devToolsParams" && enablePassiveMode) {
      console.log("HANDLING PASSIVE REQUESTS");
      storePassiveRequests(storage, message);
      runPassiveAnalysis(message);
      passiveMessageHandlerBusy = false;
    }
  });

  // return true;
}
// Listen for messages
chrome.runtime.onMessage.addListener(passiveMessageHandler);

// Log any requests and responses for analysis
function storePassiveRequests(storage, message) {

  var passiveModeRequests = storage["passiveModeRequests"];
  if (!passiveModeRequests) {
    passiveModeRequests = [];
  }

  var passiveModeEnabled = storage["enablePassiveMode"];
  if (passiveModeEnabled) {
    passiveModeRequests.push({
      url:         message.url,
      reqCookies:  message.reqCookies,
      reqHeaders:  message.reqHeaders,
      reqParams:   message.reqParams,
      respCookies: message.respCookies,
      respHeaders: message.respHeaders,
      respContent: message.respContent
    });

    chrome.storage.local.set(
      { "passiveModeRequests": passiveModeRequests },
      function() { passiveRequestStored = true; }
    );
  }
}

// Passive Analysis algorithm
function runPassiveAnalysis(r) {

  chrome.storage.local.get(function(storage) {
    // This mode *should* only be enabled after turning it on in the settings, meaning
    // it won't attempt an undefined array access
    var settings = storage["settings"];
    var passiveModeCSRFEnabled, passiveModeCookiesEnabled, passiveModeCrossChecksEnabled;
    if (settings) {
      passiveModeCSRFEnabled    = settings["passiveModeCSRFEnabled"];
      passiveModeCookiesEnabled = settings["passiveModeCookiesEnabled"];
      passiveModeCrossChecks    = settings["passiveModeCrossChecks"];
    }

    // We only want to analyse "text/html" type requests for now
    var contentTypeIndex = headerIndex(r, "respHeaders", "Content-type");

    if (contentTypeIndex >= 0 && r["respHeaders"][contentTypeIndex].value.includes("text/html")) {

      analyseRequestHeaders(r);
      analyseRequestReflectedInputs(r);

      if (passiveModeCSRFEnabled)    analyseRequestForCSRF(r);
      if (passiveModeCookiesEnabled) analyseRequestForCookies(r);
      if (passiveModeCrossChecks)    analyseCrossRequests(storage, r);
    }
  });
}

// Function performing cross request checks
function analyseCrossRequests(storage, r) {

  var settings = storage["settings"];
  // Window size includes the current request
  var crossCheckWindow = settings["passiveModeWindowSize"];
  var passiveRequests = storage["passiveModeRequests"];
  if (passiveRequests.length === 1) return;
  var checkLimit = (crossCheckWindow > passiveRequests.length) ? passiveRequests.length : crossCheckWindow;

  console.log("CHECK LIMIT IS " + checkLimit);
  // We assume we are already looking at the last request all the time, skip that
  for (var i = 0; i < checkLimit; i++) {
    // Read the requests from the list in reverse order
    console.log("We are comparing latest request (" + (passiveRequests.length-1) + ") against request (" + (passiveRequests.length - 2 - i));
    var comparisonRequest = passiveRequests[passiveRequests.length - 2 - i];

    // Consider only requests of type "text/html"
    var contentTypeIndex = headerIndex(comparisonRequest, "respHeaders", "Content-type");

    if (!(contentTypeIndex >= 0) ||
        !comparisonRequest["respHeaders"][contentTypeIndex].value.includes("text/html")) {
      // This doesn't count as a check in our window.
      console.log("SKIPPING A REQUEST - WRONG COMPARISON. ADDING 1 TO CHECKLIMIT");
      checkLimit++;
      continue;
    }

    // Since we are analysing the latest request, we want to compare the output of the latest
    // to the input of the previous requests. This may point out potential 2nd order attacks

    // Return 1 if successful in finding a comparison. Stop here to avoid cluttering with
    // more comparisons
    var successfulComparison = compareRequests(comparisonRequest, r);

    if (successfulComparison) return;
  }
}

// Helper function for algorithm of comparing 2 cross requests
// Returns 1 if successfully found a dangerous comparison, 0 otherwise
function compareRequests(inputRequest, outputRequest) {
  var userInputs = [];

  // Append all cookies from the input request into list
  var allInputCookies = inputRequest.reqCookies.concat(inputRequest.respCookies);
  for (var i = 0; i < allInputCookies.length; i++) {
    if (allInputCookies[i].value === "") continue;
    var uInput = {
      type:  "cookie",
      url:   inputRequest.url,
      name:  allInputCookies[i].name,
      value: allInputCookies[i].value
    }
    userInputs.push(uInput);
  }

  // Append all query parameters from input request into the list
  var allInputQueryParams = inputRequest.reqParams;
  for (var j = 0; j < allInputQueryParams.length; j++) {
    if (allInputQueryParams[j].value === "") continue;
    var uInput = {
      type:  "param",
      url:   inputRequest.url,
      name:  allInputQueryParams[j].name,
      value: allInputQueryParams[j].value
    }
    userInputs.push(uInput);
  }

  // Append all header values from input request into the list
  var allInputHeaders = inputRequest.reqHeaders.concat(inputRequest.respHeaders);
  for (var k = 0; k < allInputHeaders.length; k++) {
    if (allInputHeaders[k].value === "") continue;
    var uInput = {
      type:  "header",
      url:   inputRequest.url,
      name:  allInputHeaders[k].name,
      value: allInputHeaders[k].value
    }
    userInputs.push(uInput);
  }

  if (!userInputs) return 0;

  // We now have all the possible inputs from the input request into the
  // userInput array. We can now analyse the output from the responseContent of
  // outputRequest for any similarities between the two. This may point out
  // delayed reflected / 2nd order attacks

  // Compare against the latest request
  var content = outputRequest.respContent;


  var w = window.open(outputRequest.url);
  $(w.document.body).load(outputRequest.url, function() {
    setTimeout(function() {
      $(w).ready(function() {
        var realContent = w.document.body.innerHTML;

        var warnings = [];
        // Loop over all possible inputs
        for (var l = 0; l < userInputs.length; l++) {
          var currUserInput = userInputs[l];
          if (couldBeDangerous(content, currUserInput) ||
            (currUserInput.type === "param" && realContent.includes(currUserInput.value))) {
            // Not every input may be malicious / dangerous but if content includes it may be
            // worth looking into. Parameters more likely to be directly included.
            warning = "A <b>" + currUserInput.type + "</b> from a request made at " + currUserInput.url + " was identified at " + outputRequest.url + ".<br />Name: " + currUserInput.name + "<br />Value: " + currUserInput.value
            warnings.push(warning);
          }
        }

        if (!outputRequest["warnings"]) {
          outputRequest["warnings"] = [];
        }
        outputRequest["warnings"] = outputRequest["warnings"].concat(warnings);

        // Store requests with weak headers
        chrome.storage.local.get(function(storage) {
          var passiveModeWeakHeaderRequests = storage["passiveModeWeakHeaderRequests"];
          if (!passiveModeWeakHeaderRequests) {
            passiveModeWeakHeaderRequests = [];
          }

          passiveModeWeakHeaderRequests.push(outputRequest);

          chrome.storage.local.set({ "passiveModeWeakHeaderRequests": passiveModeWeakHeaderRequests });

          // Send warning to extension to display weak requests
          sendWeakRequestWarning(passiveModeWeakHeaderRequests);
        });

        return 1;
      }); // end ready callback
    }, 3000); // end setTimeout
  });
}

// Function checking for reflected inputs across requests
function analyseRequestReflectedInputs(r) {

  // Here we need to produce a list of parameters and other content which may be user
  // injected - this could be query parameters or cookie values
  var userInputs = [];
  var potentiallyDangerousInputs = [];

  // Here we want to create a userInput object which stores different values
  // pertinent to a user input. This is necessary to know which parameters to
  // override in the request when being replayed. More info in design.txt

  // Append all cookies to the list
  for (var j = 0; j < r.reqCookies.length; j++) {
    var uInput = {
      type:  "cookie",
      url:   r.url,
      name:  r.reqCookies[j].name,
      value: r.reqCookies[j].value
    }
    userInputs.push(uInput);
  }

  // Append all query parameter values to the list
  for (var k = 0; k < r.reqParams.length; k++) {
    var uInput = {
      type:  "param",
      url:   r.url,
      name:  r.reqParams[k].name,
      value: r.reqParams[k].value
    }
    userInputs.push(uInput);
  }

  // Append all header values to the list
  for (var l = 0; l < r.reqHeaders.length; l++) {
    var uInput = {
      type:  "header",
      url:   r.url,
      name:  r.reqHeaders[l].name,
      value: r.reqHeaders[l].value
    }
    userInputs.push(uInput);
  }

  setTimeout(function() {
    var content = r.respContent;

    if (!userInputs) {
      return;
    }

    // Loop over all possible user inputs to compare against
    for (var m = 0; m < userInputs.length; m++) {
      var currUserInput = userInputs[m];
      if (couldBeDangerous(content, currUserInput)) {
        // Here we flag up these inputs as a warning because it looks
        // as though content has been injected into the page
        // However that is the complete list, we only want to replay
        // the newly added dangerous inputs
        potentiallyDangerousInputs.push(currUserInput);
      }
    }

    var warnings = [];

    for (var n = 0; n < potentiallyDangerousInputs.length; n++) {
      var dangerousInput = potentiallyDangerousInputs[n];
      var warning = "There was a <b>" + dangerousInput.type + "</b> named <b>" + dangerousInput.name + "</b>, with value <b>" + dangerousInput.value + "</b>. The value was reflected somewhere in the response - this could potentially lead to a reflection attack.";
      warnings.push(warning);
    }

    if (!r["warnings"]) {
      r["warnings"] = [];
    }
    r["warnings"] = r["warnings"].concat(warnings);

    // Store requests with weak headers
    chrome.storage.local.get(function(storage) {
      var passiveModeWeakHeaderRequests = storage["passiveModeWeakHeaderRequests"];
      if (!passiveModeWeakHeaderRequests) {
        passiveModeWeakHeaderRequests = [];
      }

      passiveModeWeakHeaderRequests.push(r);

      chrome.storage.local.set({ "passiveModeWeakHeaderRequests": passiveModeWeakHeaderRequests });

      // Send warning to extension to display weak requests
      sendWeakRequestWarning(passiveModeWeakHeaderRequests);
    });

  }, 3000);
}

// Function that checks for weak header settings
function analyseRequestHeaders(r) {

  var secureHeaders = {
    "content-security-policy":   "",
    "referrer-policy":           "",
    "strict-transport-security": "",
    "x-content-type-options":    "",
    "x-frame-options":           "",
    "x-xss-protection":          ""
  }

  var reqHeaders = r.reqHeaders;
  var respHeaders = r.respHeaders;
  var allHeaders = reqHeaders.concat(respHeaders);

  // Loop over all headers in the request, if they match
  // any in the secure headers, keep their value
  for (var i = 0; i < allHeaders.length; i++) {
    var headerName = allHeaders[i]["name"].toLowerCase();
    var headerValue = allHeaders[i]["value"];

    if (Object.keys(secureHeaders).indexOf(headerName) >= 0) {
      // Current header is a secure header
      secureHeaders[headerName] = headerValue;
    }
  }

  var warnings = [];
  var secureHeaderKeys = Object.keys(secureHeaders);
  // Loop over security header values and produce appropriate response
  for (var j = 0; j < secureHeaderKeys.length; j++) {
    var header = secureHeaderKeys[j];
    var value = secureHeaders[header];

    switch (header) {
      case "content-security-policy":
        if (value === "") {
          warnings.push("The <b>Content-Security-Policy</b> header is not set. This may result in malicious assets being loaded.");
        }
        break;

      case "referrer-policy":
        if (value === "") {
          warnings.push("The <b>Referrer-Policy</b> header is not set. This controls how much information is given by the site on navigation away from it.");
        }

        break;

      case "strict-transport-security":
        if (value === "") {
          warnings.push("The <b>Strict-Transport-Security</b> header is not set. Setting it strengthens the TLS implementation by enforcing the User Agent to use HTTPS.");
        }


        break;

      case "x-content-type-options":
        if (value === "") {
          warnings.push("The <b>X-Content-Type-Options</b> header is not set. Setting it to <b>\"nosniff\"</b> prevents any MIME type sniffing attacks.");
        }

        break;

      case "x-frame-options":
        if (value === "") {
          warnings.push("The <b>X-Frame-Options</b> header is not set. Setting it can prevent clickjacking attacks by rendering the site in external frames. Recommended value is: <b>\"SAMEORIGIN\"</b>.");
        }

        break;

      case "x-xss-protection":
        if (value === "") {
          warnings.push("The <b>X-XSS-Protection</b> header is not set. Setting it to <b>\"1;mode=block\"</b> will prevent the page from loading on some browsers if reflected XSS is detected.");
        }

        break;
    } // end switch
  } // end header loop

  // Proceed no further if no warnings for this request
  if (warnings.length === 0) {
    return;
  }

  // Attach warnings to request
  if (!r["warnings"]) {
    r["warnings"] = [];
  }
  r["warnings"] = r["warnings"].concat(warnings);

  // Store requests with weak headers
  chrome.storage.local.get(function(storage) {
    var passiveModeWeakHeaderRequests = storage["passiveModeWeakHeaderRequests"];
    if (!passiveModeWeakHeaderRequests) {
      passiveModeWeakHeaderRequests = [];
    }

    passiveModeWeakHeaderRequests.push(r);

    chrome.storage.local.set({ "passiveModeWeakHeaderRequests": passiveModeWeakHeaderRequests });

    // Send warning to extension to display weak requests
    sendWeakRequestWarning(passiveModeWeakHeaderRequests);
  });

}

// Function to warn popup page about requests with weak headers
function sendWeakRequestWarning(passiveModeWeakHeaderRequests) {
  chrome.runtime.sendMessage({
    msg: "weakHeaderRequest",
    data: {
      subject: "These requests have weak security header settings",
      content: passiveModeWeakHeaderRequests
    }
  });
}

// Run some basic CSRF warning checks on the request
function analyseRequestForCSRF(r) {

  // In this check we are assuming that the page in question matches some basic
  // requirements:
  // 1) Must have a form for submission
  // 2) A session related cookie has been set
  // 3) The form does not contain a hidden input
  // If the website has a mix of these then it is possible that the website is
  // purely using cookies to handle sessions as opposed to extra form inputs
  // in the form of Anti-CSRF tokens or extra randomised URL inputs. This
  // is very difficult to fully automate checks for so will only produce a warning
  // for now. Matching names will be done based on rudimentary checks against a
  // preformed list.

  var responseContent = r.respContent;

  // No form to submit to potentially cause CSRF
  if (!responseContent.includes("<form")) return;

  var allCookies = r.reqCookies.concat(r.respCookies);

  // A basic list of potential matches to check for in cookies
  var cookieNameMatch = [
    "phpsessid",
    "jsessionid",
    "cfid",
    "cftoken",
    "asp.net_sessionid",
    "id",
    "sess",
    "auth"
  ];

  var potentialSessionIdSet = false;
  for (var i = 0; i < allCookies.length; i++) {
    var currCookie = allCookies[i];

    for (var j = 0; j < cookieNameMatch.length; j++) {
      var currMatch = cookieNameMatch[j];

      if (currCookie["name"].toLowerCase().includes(currMatch)) {
        potentialSessionIdSet = true;
        break;
      }
    }
    if (potentialSessionIdSet) break;
  }

  // Couldn't find a potentially matching cookie for a session id
  if (!potentialSessionIdSet) return;

  // Search response content for a hidden input
  var inputSearchRegex = /(<input)([^>])+>/g;

  var matchInputs;
  while ((matchInputs = inputSearchRegex.exec(responseContent)) !== null) {
    var matchedString = matchInputs[0];
    if (matchedString.toLowerCase().includes("type=\"hidden\"")) {
      // We got this far and found a hidden input. Don't know for sure
      // if it's an Anti-CSRF token but we will leave it there
      return;
    }
  }

  // We got this far and didn't find a hidden input. Issue a warning for potential CSRF
  // Attach warnings to request
  var warnings = ["This request showed signs of a <b>potential CSRF vulnerability</b>. It looks like a session cookie was set, and a form on this page is not using an Anti-CSRF token."];
  if (!r["warnings"]) {
    r["warnings"] = [];
  }
  r["warnings"] = r["warnings"].concat(warnings);

  // Store requests with weak headers
  chrome.storage.local.get(function(storage) {
    var passiveModeWeakHeaderRequests = storage["passiveModeWeakHeaderRequests"];
    if (!passiveModeWeakHeaderRequests) {
      passiveModeWeakHeaderRequests = [];
    }

    passiveModeWeakHeaderRequests.push(r);

    chrome.storage.local.set({ "passiveModeWeakHeaderRequests": passiveModeWeakHeaderRequests });

    // Send warning to extension to display weak requests
    sendWeakRequestWarning(passiveModeWeakHeaderRequests);
  });

}

// Analyses the request for weak cookie settings for potential session cookies
function analyseRequestForCookies(r) {
  // A basic list of potential matches to check for in cookies
  var sessionCookieNameMatch = [
    "phpsessid",
    "jsessionid",
    "cfid",
    "cftoken",
    "asp.net_sessionid",
    "id",
    "sess",
    "auth"
  ];

  var allCookies = r.reqCookies.concat(r.respCookies);

  var warnings = [];

  for (var i = 0; i < allCookies.length; i++) {
    var currCookie = allCookies[i];
    var cookieName = currCookie["name"];
    var secureSet = currCookie["secure"];
    var httpOnlySet = currCookie["httpOnly"];
    var cookieMatched = false;

    for (var j = 0; j < sessionCookieNameMatch.length; j++) {
      if (cookieMatched) break;
      var currMatch = sessionCookieNameMatch[j];
      if (currCookie["name"].toLowerCase().includes(currMatch)) {
        // This is potentially a session id cookie, check for security
        cookieMatched = true;
        if (!secureSet || !httpOnlySet) {
          var cookieWarning = "The cookie <b>" + cookieName + "</b> does not have the ";
          if (!secureSet && httpOnlySet) {
            cookieWarning = cookieWarning.concat("<b>secure</b> flag set.");
          }
          if (!httpOnlySet && secureSet) {
            cookieWarning = cookieWarning.concat("<b>httpOnly</b> flag set.");
          }
          if (!secureSet && !httpOnlySet) {
            cookieWarning = cookieWarning.concat("<b>httpOnly</b> or the <b>secure</b> flag set.");
          }
          warnings.push(cookieWarning);
        }
      }
    }

  }

  if (!r["warnings"]) {
    r["warnings"] = [];
  }
  r["warnings"] = r["warnings"].concat(warnings);

  // Store requests with weak headers
  chrome.storage.local.get(function(storage) {
    var passiveModeWeakHeaderRequests = storage["passiveModeWeakHeaderRequests"];
    if (!passiveModeWeakHeaderRequests) {
      passiveModeWeakHeaderRequests = [];
    }

    passiveModeWeakHeaderRequests.push(r);

    chrome.storage.local.set({ "passiveModeWeakHeaderRequests": passiveModeWeakHeaderRequests });

    // Send warning to extension to display weak requests
    sendWeakRequestWarning(passiveModeWeakHeaderRequests);
  });
}

