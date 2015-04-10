//from https://raw.githubusercontent.com/dgutov/bmreplace/67ad019be480fc6b5d458dc886a2fb5364e92171/content/main.js

"use strict";

let prompts = Services.prompt;
let prefs = Services.prefs;

const NS_XUL = "http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul",
      PREFS_BRANCH = Services.prefs.getBranch("extensions.tlsnotary.button-position."),
      PREF_TB = "toolbar",
      PREF_NEXT = "next-item",
      BUTTON_ID = "tlsnotary-button";

let main = {
  notarize: function() {
	  if (testing){
		  startTesting();
	  }
	  else {
		startNotarizing();
	}
  },
  verify: function() {
	const nsIFilePicker = Components.interfaces.nsIFilePicker;
	var fp = Components.classes["@mozilla.org/filepicker;1"]
				   .createInstance(nsIFilePicker);
	fp.init(window, "Select the tlsn file you want to verify", nsIFilePicker.modeOpen);
	var rv = fp.show();
	if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
	  var path = fp.file.path;
	  verify_tlsn_and_show_html(path);
	}
  },
  manage: function() {
	alert('Not implemented yet')
  },
  
  
  /*
   * @return {toolbarId, nextItemId}
   */
  getPrefs: function() {
    try {
      return {
        toolbarId: PREFS_BRANCH.getCharPref(PREF_TB),
        nextItemId: PREFS_BRANCH.getCharPref(PREF_NEXT)
      };
    } catch(e) {
      return { // default position
        toolbarId: "nav-bar",
        nextItemId: "bookmarks-menu-button-container"
      };
    }
  },
  
  setPrefs: function(toolbarId, nextItemId) {
    PREFS_BRANCH.setCharPref(PREF_TB, toolbarId || "");
    PREFS_BRANCH.setCharPref(PREF_NEXT, nextItemId || "");
  }
};

