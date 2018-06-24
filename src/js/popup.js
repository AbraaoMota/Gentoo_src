// Store an object for the default settings
var initialSettings = {
  "recommenderSensitivity": "1",
  "recommendationsEnabled": 0,
  "passiveModeCSRFEnabled": 0,
  "passiveModeCookiesEnabled": 0,
  "passiveModeCrossChecks": 0,
  "passiveModeWindowSize": 2
}

// Initialize modals whenever the page is ready
$(document).ready(function() {
  $('#xssWarning').modal();
  $("#potentialWarning").modal();
  $("#clearExtensionStorage").modal();
  $("#weakHeaderWarning").modal();
  $("#passiveRequestWarning").modal();
  $("#settings").modal({
    ready: settingsModalLoaded
  });
});

// Load listeners in the settings page
function settingsModalLoaded() {
  var recommenderSensitivity    = document.getElementById("recommenderSensitivity");
  var recommenderSensitivityVal = document.getElementById("recommenderSensitivityVal");
  var passiveModeWindowSize     = document.getElementById("passiveModeWindowSize");
  var passiveModeWindowSizeVal  = document.getElementById("passiveModeWindowSizeVal");
  chrome.storage.local.get(function(storage) {
    var settings = storage["settings"];
    if (!settings) {
      settings = initialSettings;
    }
    recommenderSensitivity.value        = settings["recommenderSensitivity"];
    recommenderSensitivityVal.innerHTML = settings["recommenderSensitivity"];
    passiveModeWindowSize.value         = settings["passiveModeWindowSize"];
    passiveModeWindowSizeVal.innerHTML  = settings["passiveModeWindowSize"];
  });

  // Add appropriate listeners for whenever the settings modal is opened
  saveSettingsListener();
  forgetSettingsListener();
  recommenderSensitivityValueListener();
  recommenderEnablerListener();
  passiveModeCSRFEnablerListener();
  passiveModeCookiesEnablerListener();
  passiveModeCrossChecksEnablerListener();
  passiveModeWindowSizeListener();
}

// Add listeners to the page for events created from the popup page
document.addEventListener('DOMContentLoaded', function() {

  // Settings regarding activating Action replay
  var actionReplay = document.getElementById("actionReplayEnabled");
  actionReplay.addEventListener("click", function() {
    toggleActionReplay();
  });

  // Settings for activating Passive Mode
  var passiveMode = document.getElementById("passiveModeEnabled");
  passiveModeEnabled.addEventListener("click", function() {
    togglePassiveMode();
  });

  // Activate the listeners for the active tab
  clearReflectedXSS();
  clearDangerousInputs();
  clearWeakHeaders();
  clearPassiveRequests();
  deleteExtensionStorage();

  // Reactivate listeners for when we switch back into this tab
  // and DOM can't find the elements anymore
  var xssTab = document.getElementById("xssTab");
  xssTab.addEventListener("load", function() {
    clearReflectedXSS();
    clearDangerousInputs();
    deleteExtensionStorage();
  });

  chrome.storage.local.get(function(storage) {
    console.log("ABOUT TO SET INNER HTML");
    var passiveRequestsNumber = document.getElementById("clearPassiveRequestsButton");
    var passiveModeRequests = storage["passiveModeRequests"];
    if (passiveModeRequests) {
      passiveRequestsNumber.innerHTML = "<i class=\"material-icons right\">clear</i> Clear " + passiveModeRequests.length + " passively stored requests";
    } else {
      passiveRequestsNumber.style["pointer-events"] = "none";
      passiveRequestsNumber.innerHTML = "No passively stored requests to clear";
    }
  });

  var passiveTab = document.getElementById("passiveTab");
  passiveTab.addEventListener("load", function() {
    clearWeakHeaders();
    clearPassiveRequests();
  });

});

// Update visuals on popup page load
window.addEventListener("load", function() {
  // Make notification badge disappear from popup when window opened
  chrome.browserAction.setBadgeText({ text: "" });
  chrome.browserAction.setIcon({ path: "img/gentoo.png" });

  // Visual switch checking is a separate element to the lever that
  // triggers the switch
  var checkboxAR = document.getElementById("checkboxAR");
  chrome.storage.local.get("enableAR", function(flag) {
    if (flag["enableAR"] === 1) {
      checkboxAR.checked = flag;
    }
  });

  var checkboxPassiveMode = document.getElementById("checkboxPassiveMode");
  chrome.storage.local.get(function(storage) {
    checkboxPassiveMode.checked = storage["enablePassiveMode"];
  });

  chrome.storage.local.get(function(storage) {
    renderWeakURLs(storage);
    renderPotentialXSS(storage);
    renderWeakHeaderRequests(storage);
  });

}, false);

// Create elements for the weak URL list to appear
// This list is kept in chrome storage under the 'weakURLs' key
function renderWeakURLs(storage) {
  var weakURLs = storage["weakURLs"];

  var reflectedList = document.getElementById("xssURLs");
  if (weakURLs) {
    for (var i = 0; i < weakURLs.length; i++) {
      var weakURLObject = weakURLs[i];
      var p = document.createElement("p");
      p.innerHTML = "URL: <b>" + weakURLObject["url"] + "</b><br>Attack Name: " + weakURLObject["attackName"] + "<br>Attack Number: " + weakURLObject["attackNo"];
      reflectedList.appendChild(p);
    }
  }
}

// Create elements for the potentialXSS warning list,
// this list is also kept in chrome storage under "potentialXSS"
function renderPotentialXSS(storage) {
  var potentialXSS = storage["potentialXSS"];
  var potentiallyDangerousList = document.getElementById("potentialXSS");

  if (potentialXSS) {
    var collection = document.createElement("ul");
    collection.classList.add("collection");

    for (var i = 0; i < potentialXSS.length; i++) {
      var collItem = document.createElement("li");
      collItem.classList.add("collection-item");

      var inputTypeAndUrl = document.createElement("p");
      inputTypeAndUrl.innerHTML = "This input is a <strong>" + potentialXSS[i].type + "</strong> from the URL:<br />" + potentialXSS[i].url;

      var inputValues = document.createElement("p");
      inputValues.innerHTML = "Name: " + potentialXSS[i].name + "<br />Value: " + potentialXSS[i].value;

      collItem.appendChild(inputTypeAndUrl);
      collItem.appendChild(inputValues);

      collection.appendChild(collItem);
    }
    potentiallyDangerousList.appendChild(collection);
  }
}

// Create elements for the requests with weak security headers
function renderWeakHeaderRequests(storage) {
  var passiveModeWeakHeaderRequests = storage["passiveModeWeakHeaderRequests"];
  var weakHeaderRequestList = document.getElementById("insecureRequests");

  if (passiveModeWeakHeaderRequests) {
    var collection = document.createElement("ul");
    collection.classList.add("collection");

    for (var i = 0; i < passiveModeWeakHeaderRequests.length; i++) {
      var collItem = document.createElement("li");
      collItem.classList.add("collection-item");

      var reqDescription = document.createElement("p");
      reqDescription.innerHTML = "This request is from <b>" + passiveModeWeakHeaderRequests[i].url + "</b>";
      collItem.appendChild(reqDescription);

      var warnings = document.createElement("ul");
      for (var j = 0; j < passiveModeWeakHeaderRequests[i]["warnings"].length; j++) {
        var warning = document.createElement("p");
        warning.innerHTML = passiveModeWeakHeaderRequests[i]["warnings"][j];
        warnings.appendChild(warning);
      }

      collItem.appendChild(warnings);
      collection.appendChild(collItem);
    }
    weakHeaderRequestList.appendChild(collection);
  }
}

// Enables and disables recommender engine
function recommenderEnablerListener() {
  var checkboxRecommendations = document.getElementById("checkboxRecommendations");
  // Get the setting if it has already been set
  chrome.storage.local.get(function(storage) {
    var settings = storage["settings"];
    if (!settings) {
      settings = initialSettings;
    }
    chrome.storage.local.set({ "settings": settings });

    var recommendationsEnabled = settings["recommendationsEnabled"];
    var sensitivity = document.getElementById("recommenderSensitivity");

    checkboxRecommendations.checked = recommendationsEnabled;
    if (recommendationsEnabled) {
      sensitivity.disabled = false;
    } else {
      sensitivity.disabled = true;
    }
  });

  var recommendationsEnabled = document.getElementById("recommendationsEnabled");
  recommendationsEnabled.addEventListener("click", function() {
    toggleRecommendations();
  });
}

// Enables and disables basic CSRF checks for the passive Mode
function passiveModeCSRFEnablerListener() {
  var checkboxPassiveCSRF = document.getElementById("checkboxPassiveCSRF");
  // Get the setting if it has already been set
  chrome.storage.local.get(function(storage) {
    var settings = storage["settings"];
    if (!settings) {
      settings = initialSettings;
    }
    chrome.storage.local.set({ "settings": settings });

    var passiveModeEnabled = storage["enablePassiveMode"];
    var passiveModeCSRFEnabled = settings["passiveModeCSRFEnabled"];

    if (passiveModeEnabled) {
      checkboxPassiveCSRF.disabled = false;
      checkboxPassiveCSRF.checked = passiveModeCSRFEnabled;
    } else {
      checkboxPassiveCSRF.disabled = true;
    }
  });

  var passiveCSRFEnabled = document.getElementById("passiveCSRFEnabled");
  passiveCSRFEnabled.addEventListener("click", function() {
    togglePassiveCSRF();
  });
}

// Enables and disables weak Cookie settings in passive Mode
function passiveModeCookiesEnablerListener() {
  var checkboxPassiveCookies = document.getElementById("checkboxPassiveCookies");
  // Get the setting if it has already been set
  chrome.storage.local.get(function(storage) {
    var settings = storage["settings"];
    if (!settings) {
      settings = initialSettings;
    }
    chrome.storage.local.set({ "settings": settings });

    var passiveModeEnabled = storage["enablePassiveMode"];
    var passiveModeCookiesEnabled = settings["passiveModeCookiesEnabled"];

    if (passiveModeEnabled) {
      checkboxPassiveCookies.disabled = false;
      checkboxPassiveCookies.checked = passiveModeCookiesEnabled;
    } else {
      checkboxPassiveCookies.disabled = true;
    }
  });

  var passiveCookiesEnabled = document.getElementById("passiveCookiesEnabled");
  passiveCookiesEnabled.addEventListener("click", function() {
    togglePassiveCookies();
  });
}

// Enables and disables cross request passive checks
function passiveModeCrossChecksEnablerListener() {
  var checkboxPassiveCrossChecks = document.getElementById("checkboxPassiveCrossChecks");
  // Get the setting if it has already been set
  chrome.storage.local.get(function(storage) {
    var settings = storage["settings"];
    if (!settings) {
      settings = initialSettings;
    }
    chrome.storage.local.set({ "settings": settings });

    var passiveModeEnabled = storage["enablePassiveMode"];
    var passiveModeCrossChecksEnabled = settings["passiveModeCrossChecks"];
    var passiveModeWindowSize = document.getElementById("passiveModeWindowSize");
    if (passiveModeEnabled) {
      checkboxPassiveCrossChecks.disabled = false;
      checkboxPassiveCrossChecks.checked = passiveModeCrossChecksEnabled;
    } else {
      checkboxPassiveCrossChecks.disabled = true;
    }
    if (passiveModeEnabled && passiveModeCrossChecksEnabled) {
      passiveModeWindowSize.disabled = false;
    } else {
      passiveModeWindowSize.disabled = true;
    }
  });

  var passiveCrossChecksEnabled = document.getElementById("passiveCrossChecksEnabled");
  passiveCrossChecksEnabled.addEventListener("click", function() {
    togglePassiveCrossChecks();
  });
}

// Enable or disable passive mode cross request checking
function togglePassiveCrossChecks() {
  chrome.storage.local.get(function(storage) {
    var cachedSettings = storage["cachedSettings"];
    if (!cachedSettings) {
      var settings = storage["settings"];
      if (!settings) {
        settings = initialSettings;
        chrome.storage.local.set({ "settings": settings });
      }
      cachedSettings = settings;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    }

    var passiveModeEnabled = storage["enablePassiveMode"];
    var passiveCrossChecksEnabled = cachedSettings["passiveModeCrossChecks"];
    var passiveModeWindowSize = document.getElementById("passiveModeWindowSize");

    if (passiveModeEnabled) {
      if (passiveCrossChecksEnabled) {
        // Disable cross checks
        cachedSettings["passiveModeCrossChecks"] = 0;
        passiveModeWindowSize.disabled = true;
        chrome.storage.local.set({ "cachedSettings": cachedSettings });
      } else {
        // Enable cross checks
        cachedSettings["passiveModeCrossChecks"] = 1;
        passiveModeWindowSize.disabled = false;
        chrome.storage.local.set({ "cachedSettings": cachedSettings });
      }
    }
  });
}

// Enable or disable passive mode basic CSRF checks
function togglePassiveCSRF() {
  chrome.storage.local.get(function(storage) {
    var cachedSettings = storage["cachedSettings"];
    if (!cachedSettings) {
      var settings = storage["settings"];
      if (!settings) {
        settings = initialSettings;
        chrome.storage.local.set({ "settings": settings });
      }
      cachedSettings = settings;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    }

    var passiveModeEnabled = storage["enablePassiveMode"];
    var passiveModeCSRFEnabled = cachedSettings["passiveModeCSRFEnabled"];

    if (passiveModeEnabled) {
      if (passiveModeCSRFEnabled) {
        // Disabled passive CSRF
        cachedSettings["passiveModeCSRFEnabled"] = 0;
        chrome.storage.local.set({ "cachedSettings": cachedSettings });
      } else {
        cachedSettings["passiveModeCSRFEnabled"] = 1;
        chrome.storage.local.set({ "cachedSettings": cachedSettings });
      }
    }
  });
}

// Enable or disable passive mode weak Cookie checks
function togglePassiveCookies() {
  chrome.storage.local.get(function(storage) {
    var cachedSettings = storage["cachedSettings"];
    if (!cachedSettings) {
      var settings = storage["settings"];
      if (!settings) {
        settings = initialSettings;
        chrome.storage.local.set({ "settings": settings });
      }
      cachedSettings = settings;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    }

    var passiveModeEnabled = storage["enablePassiveMode"];
    var passiveModeCookiesEnabled = cachedSettings["passiveModeCookiesEnabled"];

    if (passiveModeEnabled) {
      if (passiveModeCookiesEnabled) {
        // Disable passive cookie checks
        cachedSettings["passiveModeCookiesEnabled"] = 0;
        chrome.storage.local.set({ "cachedSettings": cachedSettings });
      } else {
        cachedSettings["passiveModeCookiesEnabled"] = 1;
        chrome.storage.local.set({ "cachedSettings": cachedSettings });
      }
    }
  });
}

// Enable and disable recommendations
function toggleRecommendations() {
  chrome.storage.local.get(function(storage) {
    var cachedSettings = storage["cachedSettings"];
    if (!cachedSettings) {
      var settings = storage["settings"];
      if (!settings) {
        settings = initialSettings;
        chrome.storage.local.set({ "settings": settings });
      }
      cachedSettings = settings;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    }
    var recommendationsEnabled = cachedSettings["recommendationsEnabled"];
    var sensitivity = document.getElementById("recommenderSensitivity");

    if (!recommendationsEnabled) {
      cachedSettings["recommendationsEnabled"] = 1;
      sensitivity.disabled = false;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    } else {
      cachedSettings["recommendationsEnabled"] = 0;
      sensitivity.disabled = true;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    }
  });
}

// Forgets any setting changes when cancelling them
function forgetSettingsListener() {
  var forgetSettings = document.getElementById("forgetSettings");
  forgetSettings.addEventListener("click", function() {
    chrome.storage.local.get(function(storage) {
      var settings = storage["settings"];
      if (!settings) {
        // Set the default settings
        settings = initialSettings;
      }

      // Reset the cached settings to the previously known settings list
      chrome.storage.local.set({ cachedSettings: settings });
    });
  });
}

// This saves any settings being changed on the settings page
function saveSettingsListener() {
  var saveSettings = document.getElementById("saveSettings");
  saveSettings.addEventListener("click", function() {
    chrome.storage.local.get(function(storage) {
      var cachedSettings = storage["cachedSettings"];
      var oldSettings = storage["settings"];
      if (!cachedSettings) {
        if (!oldSettings) {
          // Set the default settings
          oldSettings = initialSettings;
        }
        cachedSettings = oldSettings;
      }
      // Set the used settings to the cachedSettings we have
      chrome.storage.local.set({ settings: cachedSettings });
    });
  });
}

// Clears out list of requests with weak header settings
function clearWeakHeaders() {
  var clearHeaders = document.getElementById("clearWeakHeaders");
  clearHeaders.addEventListener("click", function() {
    chrome.storage.local.remove("passiveModeWeakHeaderRequests");
    var weakRequests = document.getElementById("insecureRequests");
    while (weakRequests.firstChild) {
      weakRequests.removeChild(weakRequests.firstChild);
    }
  });
}

// Clears out list of passively stored requests
function clearPassiveRequests() {
  var clearPassiveRequests = document.getElementById("clearPassiveRequests");
  var passiveRequestsNumber = document.getElementById("clearPassiveRequestsButton");
  clearPassiveRequests.addEventListener("click", function() {
    chrome.storage.local.remove("passiveModeRequests");
    passiveRequestsNumber.innerHTML = "No passively stored requests to clear";
    passiveRequestsNumber.style["pointer-events"] = "none";
  });
}

// Clears out the list of URLs to which we have been redirected from to reach
// the `request_logger` page
function clearReflectedXSS() {
  // Clear weakURL list
  var clearXssURLs = document.getElementById("clearXssURLs");
  clearXssURLs.addEventListener('click', function() {
    chrome.storage.local.remove("weakURLs");
    var xssURLs = document.getElementById("xssURLs");
    while (xssURLs.firstChild) {
      xssURLs.removeChild(xssURLs.firstChild);
    }
  });
}

// Clears out the list of potentially dangerous inputs added on attack inspection
function clearDangerousInputs() {
  var clearDangerousInputs = document.getElementById("clearDangerousInputs");
  clearDangerousInputs.addEventListener("click", function() {
    chrome.storage.local.remove("potentialXSS");
    var potentialXSS = document.getElementById("potentialXSS");
    while (potentialXSS.firstChild) {
      potentialXSS.removeChild(potentialXSS.firstChild);
    }
  });
}

// This function deletes all extension storage content
function deleteExtensionStorage() {
  var deleteStorageContent = document.getElementById("deleteExtStorage");
  deleteExtStorage.addEventListener("click", function() {
    chrome.storage.local.clear();
    location.reload();
  });
}

// Update recommender sensitivity settings on change
function recommenderSensitivityValueListener() {
  var recommenderSensitivity = document.getElementById("recommenderSensitivity");
  recommenderSensitivity.addEventListener("input", function() {
    var newVal = recommenderSensitivity.value;
    chrome.storage.local.get(function(storage) {
      var cachedSettings = storage["cachedSettings"];
      var oldSettings = storage["settings"];
      if (!cachedSettings) {
        if (!oldSettings) {
          // Use default settings
          oldSettings = initialSettings;
        }
        cachedSettings = oldSettings;
      }

      cachedSettings["recommenderSensitivity"] = newVal;
      var recommenderSensitivityVal = document.getElementById("recommenderSensitivityVal");
      recommenderSensitivityVal.innerHTML = newVal;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    });
  });
}

// Update passive mode window size settings on change
function passiveModeWindowSizeListener() {
  var passiveModeWindowSize = document.getElementById("passiveModeWindowSize");
  passiveModeWindowSize.addEventListener("input", function() {
    var newVal = passiveModeWindowSize.value;
    chrome.storage.local.get(function(storage) {
      var cachedSettings = storage["cachedSettings"];
      var oldSettings = storage["settings"];
      if (!cachedSettings) {
        if (!oldSettings) {
          // Use default Settings
          oldSettings = initialSettings;
        }
        cachedSettings = oldSettings;
      }

      cachedSettings["passiveModeWindowSize"] = newVal;
      var passiveModeWindowSizeVal = document.getElementById("passiveModeWindowSizeVal");
      passiveModeWindowSizeVal.innerHTML = newVal;
      chrome.storage.local.set({ "cachedSettings": cachedSettings });
    });
  });
}

// Function switch for activating the passive mode
function togglePassiveMode() {
  chrome.storage.local.get(function(storage) {
    var enablePassiveMode = storage["enablePassiveMode"];
    if (!enablePassiveMode) {
      // Either unset or set to 0 - enable now
      chrome.storage.local.set({ "enablePassiveMode": 1 });
    } else {
      // Disable
      chrome.storage.local.set({ "enablePassiveMode": 0 });
      var settings = storage["settings"];
      // Ensure other passive sub modes are disabled
      if (settings["passiveModeCrossChecks"])    togglePassiveCrossChecks();
      if (settings["passiveModeCSRFEnabled"])    togglePassiveCSRF();
      if (settings["passiveModeCookiesEnabled"]) togglePassiveCookies();
    }
  });
}

// Function switch for activating the AR button functionality on a page
function toggleActionReplay() {
  chrome.storage.local.get(function(storage) {
    var enableAR = storage["enableAR"];
    var ARsession = storage["ARsession"];

    if (!enableAR) {
      // This hasn't been set yet, switch was just enabled, therefore set to 1
      chrome.storage.local.set({ "enableAR": 1 });
    } else {
      // Toggle Storage
      chrome.storage.local.set({ "enableAR": 1 - enableAR });
      if (ARsession === "recording") {
        chrome.storage.local.set({ "ARsession": "finished" });
      }
    }
  });

  // Send out a message
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    chrome.tabs.sendMessage(
      tabs[0].id,
      {
        msg: "toggleAR"
      },
      function(response) {}
    );
  });
}
