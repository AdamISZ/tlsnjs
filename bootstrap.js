//from https://raw.githubusercontent.com/dgutov/bmreplace/67ad019be480fc6b5d458dc886a2fb5364e92171/bootstrap.js
var bootstrapjs_exception;
var thisaddon;
var jsloaded = false;
try {

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/AddonManager.jsm");

var self = this, icon;

function include(addon, path) {
  Services.scriptloader.loadSubScript("chrome://tlsnotary/content/"+path, self);
}

function $(node, childId) {
  if (node.getElementById) {
    return node.getElementById(childId);
  } else {
    return node.querySelector("#" + childId);
  }
}

function loadIntoWindow(window) {
  if (!window) return;
  
  let doc = window.document;
  let toolbox = $(doc, "navigator-toolbox");
  
  if (toolbox) { // navigator window
    // add to palette
    let button = doc.createElement("toolbarbutton");
    button.setAttribute("id", BUTTON_ID);
    button.setAttribute("type","menu-button")
    button.setAttribute("label", "TLSNotary");
    button.setAttribute("class", "toolbarbutton-1 chromeclass-toolbar-additional");
    button.setAttribute("tooltiptext", "TLSNotary menu");
    button.style.listStyleImage = "url(" + icon + ")";
    button.addEventListener("command", main.action, false);
    let mpu = doc.createElement("menupopup");
    mpu.setAttribute("id","tlsnmpu");
    let menuentries = ['Notarize this page','Verify tlsn file', 'Manage files'];
    for (var i=0; i < menuentries.length; i++){
      let mi = doc.createElement("menuitem");
      mi.setAttribute("label",menuentries[i]);
      mi.setAttribute("value","blah");
      mi.addEventListener("command",main.action, false)
      mpu.appendChild(mi);
    }
    button.appendChild(mpu);
    toolbox.palette.appendChild(button);
    
    // move to saved toolbar position
    let {toolbarId, nextItemId} = main.getPrefs(),
        toolbar = toolbarId && $(doc, toolbarId);
    if (toolbar) {
      let nextItem = $(doc, nextItemId);
      toolbar.insertItem(BUTTON_ID, nextItem &&
                         nextItem.parentNode.id == toolbarId &&
                         nextItem);
    }
    window.addEventListener("aftercustomization", afterCustomize, false);
    
    // add hotkey
    let replaceKey = doc.createElementNS(NS_XUL, "key");
    replaceKey.setAttribute("id", "RB:Replace");
    replaceKey.setAttribute("key", "D");
    replaceKey.setAttribute("modifiers", "accel,alt");
    replaceKey.setAttribute("oncommand", "void(0);");
    replaceKey.addEventListener("command", main.action, true);
    $(doc, "mainKeyset").appendChild(replaceKey);
  }
}

function afterCustomize(e) {
  let toolbox = e.target;
  let button = $(toolbox.parentNode, BUTTON_ID);
  let toolbarId, nextItemId;
  if (button) {
    let parent = button.parentNode,
        nextItem = button.nextSibling;
    if (parent && parent.localName == "toolbar") {
      toolbarId = parent.id;
      nextItemId = nextItem && nextItem.id;
    }
  }
  main.setPrefs(toolbarId, nextItemId);
}

function unloadFromWindow(window) {
  if (!window) return;
  let doc = window.document;
  let button = $(doc, BUTTON_ID) ||
    $($(doc, "navigator-toolbox").palette, BUTTON_ID);
  button && button.parentNode.removeChild(button);
  window.removeEventListener("aftercustomization", afterCustomize, false);
}

function eachWindow(callback) {
  let enumerator = Services.wm.getEnumerator("navigator:browser");
  while (enumerator.hasMoreElements()) {
	if (!jsloaded){
		loadjs();
	}
    let win = enumerator.getNext();
    if (win.document.readyState === "complete") {
      callback(win);
    } else {
      runOnLoad(win, callback);
    }
  }
}

function runOnLoad (window, callback) {
  window.addEventListener("load", function() {
	if (!jsloaded){
		loadjs();
	}
    window.removeEventListener("load", arguments.callee, false);
    callback(window);
  }, false);
}

function windowWatcher (subject, topic) {
  if (topic === "domwindowopened") {
    runOnLoad(subject, loadIntoWindow);
  }
}

function startup(data, reason) AddonManager.getAddonByID(data.id, function(addon) {
  thisaddon = addon;
  icon = addon.getResourceURI("icon.png").spec;
  // existing windows
  eachWindow(loadIntoWindow);
  // new windows
  Services.ww.registerNotification(windowWatcher);
});

//we want to load js files only after browser started, so we wait for a window object
//to be exposed first and then loadjs get triggered
function loadjs(){
  jsloaded = true;
  var addon = thisaddon;
  include(addon, "button.js");
  include(addon, "main.js");
  include(addon, "testdriver.js");
  include(addon, "CryptoJS/components/core.js");
  include(addon, "CryptoJS/components/md5.js");
  include(addon, "CryptoJS/components/evpkdf.js");
  include(addon, "CryptoJS/components/enc-base64.js");
  include(addon, "CryptoJS/components/sha1.js");
  include(addon, "CryptoJS/components/sha256.js");
  include(addon, "CryptoJS/components/hmac.js");
  include(addon, "CryptoJS/components/cipher-core.js");
  include(addon, "CryptoJS/components/aes.js");
  include(addon, "CryptoJS/components/pad-nopadding.js");
  include(addon, "jsbn.js");
  include(addon, "jsbn2.js");
  include(addon, "pako.js");
  include(addon, "tlsn.js");
  include(addon, "tlsn_utils.js");
}


function shutdown(data, reason) {
  Services.ww.unregisterNotification(windowWatcher);
  eachWindow(unloadFromWindow);
}
function install(data,reason) {}
function uninstall(data,reason) {}

} catch (e){
	bootstrapjs_exception = e;
}
