// This page logs requests as well as a referrer page
// This page is used as a sure way to ensure an XSS attack
// was successful - currently, the only way to reach this
// page is programatically, so the referrer must have suffered
// from an executed XSS attack


// Whenever this page is loaded, store information regarding
// the referrer URL and append it to the list of weak URLs
// kept in localStorage
window.addEventListener("load", function() {

  var url = new URL(window.location.href);
  console.log("REQUEST LOGGER HAS THIS URL");
  console.log(url);
  var referrerFull = new URL(url.searchParams.get("ref"));
  var attackNumber = url.searchParams.get("attackNo");
  var attackName   = url.searchParams.get("attackName");
  var weakReferrer = referrerFull.toString();
  document.getElementById("output").innerHTML = weakReferrer;

  var weakURLObject = {
    url:        weakReferrer,
    attackNo:   attackNumber,
    attackName: attackName
  }

  // Attempt to write the contents of the URL from which
  // the XSS request came from to LocalStorage
  chrome.storage.local.get(function(storage) {
    var urlList = storage["weakURLs"];
    if (!urlList) {
      // First time this field is set in storage
      chrome.storage.local.set({ "weakURLs": [ weakURLObject ] });
    } else {
      // Append to existing field
      var urlSet = new Set(urlList);
      urlSet.add(weakURLObject);
      var weakURLs = Array.from(urlSet);
      chrome.storage.local.set({ "weakURLs": weakURLs });
    }
  });

  sendReflectedXSSNotification(weakURLObject);

}, false);


// (function(open) {
//     XMLHttpRequest.prototype.open = function() {
//         this.addEventListener("readystatechange", function() {
//           console.log(this.readyState);
//           console.log("HELlO MUM");
//         }, false);
//         open.apply(this, arguments);
//     };
// })(XMLHttpRequest.prototype.open);


// var open = window.XMLHttpRequest.prototype.open;
// var send = window.XMLHttpRequest.prototype.send;

// function openReplacement(method, url, async, user, password) {
//   this._url = url;
//   return open.apply(this, arguments);
// }

// function sendReplacement(data) {
//   if(this.onreadystatechange) {
//     this._onreadystatechange = this.onreadystatechange;
//   }

//   console.log("WE HAVE REPLACED THE SEND PROTOTYPE");

//   var url = new URL(window.location.href);
//   var weakReferrer = url.searchParams.get("ref");

//   // Attempt to write the contents of the URL from which
//   // the XSS request came from to LocalStorage
//   chrome.storage.local.get(function(storage) {
//     var urlList = storage["weakURLs"];
//     if (!urlList) {
//       // First time this field is set in storage
//       chrome.storage.local.set({ "weakURLs": [weakReferrer] });
//     } else {
//       // Append to existing field
//       var urlSet = new Set(urlList);
//       urlSet.add(weakReferrer);
//       var weakURLs = Array.from(urlSet);
//       chrome.storage.local.set({ "weakURLs": weakURLs });
//     }
//   });

//   sendReflectedXSSNotification(weakReferrer);

//   /**
//    * PLACE HERE YOUR CODE WHEN REQUEST IS SENT
//    */
//   this.onreadystatechange = onReadyStateChangeReplacement;
//   return send.apply(this, arguments);
// }

// function onReadyStateChangeReplacement() {
//   var url = new URL(window.location.href);
//   var weakReferrer = url.searchParams.get("ref");


//   console.log("WE HAVE REPLACED THE ONREADYSTATECHANGE PROTOTYPE");
//   // Attempt to write the contents of the URL from which
//   // the XSS request came from to LocalStorage
//   chrome.storage.local.get(function(storage) {
//     var urlList = storage["weakURLs"];
//     if (!urlList) {
//       // First time this field is set in storage
//       chrome.storage.local.set({ "weakURLs": [weakReferrer] });
//     } else {
//       // Append to existing field
//       var urlSet = new Set(urlList);
//       urlSet.add(weakReferrer);
//       var weakURLs = Array.from(urlSet);
//       chrome.storage.local.set({ "weakURLs": weakURLs });
//     }
//   });

//   sendReflectedXSSNotification(weakReferrer);

//   /**
//    * PLACE HERE YOUR CODE FOR READYSTATECHANGE
//    */
//   if(this._onreadystatechange) {
//     return this._onreadystatechange.apply(this, arguments);
//   }
// }

// window.XMLHttpRequest.prototype.open = openReplacement;
// window.XMLHttpRequest.prototype.send = sendReplacement;


// Send a message to the popup page to notify a new weak URL has been found
function sendReflectedXSSNotification(weakURLObject) {
  chrome.runtime.sendMessage({
    msg: "reflectedXSS",
    data: {
      subject:       "New reflected XSS URL found!",
      weakURLObject: weakURLObject
    }
  });
}
