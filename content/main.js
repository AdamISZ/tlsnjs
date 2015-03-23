var script_exception;
try {	

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;
Cu.import("resource://gre/modules/PopupNotifications.jsm");
Cu.import('resource://gre/modules/Services.jsm');
Cu.import("resource://gre/modules/osfile.jsm")
var testingMode = false;
var dict_of_status = {};
var dict_of_httpchannels = {};

var win = Cc['@mozilla.org/appshell/window-mediator;1']
	.getService(Ci.nsIWindowMediator).getMostRecentWindow('navigator:browser');
var gBrowser = win.gBrowser;
//navigator must be exposed for jsbn.js
var navigator = win.navigator;
var setTimeout = win.setTimeout;
var alert = win.alert;
var btoa = win.btoa;
var atob = win.atob;



function init(){
	//sometimes gBrowser is not available
	if (gBrowser === null || typeof(gBrowser) === "undefined"){
		gBrowser = win.gBrowser;
		setTimeout(init, 100);
		return;
	}	
	startListening();
	if (envvar.get("TLSNOTARY_TEST") == "true"){
		setTimeout(tlsnInitTesting,3000);
		testingMode = true;
	}
}

function popupShow(text) {
	var notify  = new PopupNotifications(gBrowser,
                    win.document.getElementById("notification-popup"),
                    win.document.getElementById("notification-popup-box"));
	notify.show(gBrowser.selectedBrowser, "tlsnotary-popup", text,
	null, /* anchor ID */
	{
	  label: "Close this notification",
	  accessKey: "C",
	  callback: function() {},
	},
	null  /* secondary action */
	);
}

/*Show the notification with default buttons (usebutton undefined), 'AUDIT' and 'FINISH'
or with just the AUDIT button (usebutton true or truthy) or no buttons (usebutton false) */
function notBarShow(text,usebutton){
    var _gNB = win.document.getElementById("global-notificationbox"); //global notification box area
    _gNB.removeAllNotifications();
    var buttons;
    if (typeof(usebutton)==='undefined'){
    //Default: show both buttons
	buttons = [{
	    label: 'AUDIT THIS PAGE',
	    popup: null,
	    callback: startRecording
	},
	{
	    label: 'FINISH',
	    accessKey: null,
	    popup: null,
	    callback: stopRecording
	    }];
    }
    else if (usebutton===false){
	buttons = null;
    }
    else{
	buttons = [{
	    label: 'AUDIT THIS PAGE',
	    accessKey: "U",
	    popup: null,
	    callback: startRecording
	}];
    }
	const priority = _gNB.PRIORITY_INFO_MEDIUM;
	_gNB.appendNotification(text, 'tlsnotary-box',
			     'chrome://tlsnotary/content/icon.png',
			      priority, buttons);
}


function startListening(){
//from now on, we will check the security status of all loaded tabs
//and store the security status in a lookup table indexed by the url.
    gBrowser.addProgressListener(myListener);
}


function startRecording(){	
    var audited_browser = gBrowser.selectedBrowser;
    var tab_url_full = audited_browser.contentWindow.location.href;
    
    //remove hashes - they are not URLs but are used for internal page mark-up
    sanitized_url = tab_url_full.split("#")[0];
    
    if (!sanitized_url.startsWith("https://")){
	var btn = win.document.getElementsByAttribute("label","FINISH")[0]; //global notification box area
	errmsg="ERROR You can only audit pages which start with https://";
	if (typeof(btn)==='undefined'){
	    notBarShow(errmsg,true);
	}
	else{
	    notBarShow(errmsg);
	}
	return;
    }
    //XXX this check is not needed anymore
    if (dict_of_status[sanitized_url] != "secure"){
	alert("The page does not have a valid SSL certificate. Try to refresh the page and then press AUDIT THIS PAGE.");
	notBarShow("Go to a page and press AUDIT THIS PAGE. Then wait for the page to reload automatically.");
	return;
    }
    
    //passed tests, secure, grab headers, update status bar and start audit:
    var x = sanitized_url.split('/');
    x.splice(0,3);
    var tab_url = x.join('/');
	
    var httpChannel = dict_of_httpchannels[sanitized_url];
	var headers = "";
	headers += httpChannel.requestMethod + " /" + tab_url + " HTTP/1.1" + "\r\n";
	httpChannel.visitRequestHeaders(function(header,value){
                                  headers += header +": " + value + "\r\n";});
    if (httpChannel.requestMethod == "GET"){
		headers += "\r\n";
	}       
    if (httpChannel.requestMethod == "POST"){
		//for POST, extra "\r\n" is already included in uploaddata (see below) to separate http header from http body 
		var uploadChannel = httpChannel.QueryInterface(Ci.nsIUploadChannel);
		var uploadChannelStream = uploadChannel.uploadStream;
		uploadChannelStream.QueryInterface(Ci.nsISeekableStream);                 
		uploadChannelStream.seek(0,0);                               
		var stream = Cc['@mozilla.org/scriptableinputstream;1'].createInstance(Ci.nsIScriptableInputStream);
		stream.init(uploadChannelStream);
		var uploaddata = stream.read(stream.available());
		//FF's uploaddata contains Content-Type and Content-Length headers + '\r\n\r\n' + http body
		headers += uploaddata;
	}
	var server = headers.split('\r\n')[1].split(':')[1].replace(/ /g,'');
	notBarShow("Audit is underway, please be patient.",false);  
	  
	var modulus;
	var certsha256;
	get_certificate(server).then(function(cert){
		console.log('got certificate');
		var b64cert = b64encode(cert);
		if (! verifyCert(b64cert)){
			alert("This website cannot be audited by TLSNotary because it presented an untrusted certificate");
			return;
		}
		modulus = getModulus(b64cert);
		certsha256 = sha256(cert);
		//loop prepare_pms 10 times until succeeds
		return new Promise(function(resolve, reject) {
			var tries = 0;
			var loop = function(resolve, reject){
				tries += 1;
				prepare_pms(modulus).then(function(args){
					resolve(args);
				}).catch(function(error){
					console.log('caught error', error);
					if (tries == 10){
						alert('10 tries')
						reject('10 tries');
						return;
					}
					loop(resolve, reject);
				});
			};
			loop(resolve, reject);
		});
	})
	.then(function(args){
		return start_audit(modulus, certsha256, server, headers, args[0], args[1], args[2]);
	})
	.then(function(args){
		save_session_and_open_html(args[0], args[1], args[2], args[3], args[4], server);
	})
	.catch(function(err){
	 //TODO need to get a decent stack trace
		console.log('There was an error: ' + err);
		alert('There was an error: ' + err);
	});
}

function save_session_and_open_html(html, pms2, response, modulus, sig, server){
	var localDir = Cc["@mozilla.org/file/directory_service;1"].
			getService(Ci.nsIProperties).get("ProfD", Ci.nsIFile);

	localDir.append("TLSNotary");
	 if (!localDir.exists() || !localDir.isDirectory()) {
		// read and write permissions to owner and group, read-only for others.
		localDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0774);
	}

	var today = new Date();
	var time = today.getFullYear()+'-'+("00"+(today.getMonth()+1)).slice(-2)+'-'+("00"+today.getDate()).slice(-2)+'-'+
	("00"+today.getHours()).slice(-2)+':'+("00"+today.getMinutes()).slice(-2)+':'+("00"+today.getSeconds()).slice(-2);

	localDir.append(time+'-'+server); 
	localDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0774);

	var path_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	path_html.initWithPath(localDir.path);
	path_html.append('page.html')
	 //see "Byte order mark"
	return OS.File.writeAtomic(path_html.path, ba2ua([0xef, 0xbb, 0xbf]))
	.then(function(){
		OS.File.writeAtomic(path_html.path, ba2ua(str2ba(html)))
	})
	.then(function(){
		var path_pms2 = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		path_pms2.initWithPath(localDir.path);
		path_pms2.append('pms2');
		return OS.File.writeAtomic(path_pms2.path, ba2ua(pms2));
	})
	.then(function(){
		var path_response = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		path_response.initWithPath(localDir.path);
		path_response.append('response');
		return OS.File.writeAtomic(path_response.path, ba2ua(response));
	})
	.then(function(){
		var path_modulus = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		path_modulus.initWithPath(localDir.path);
		path_modulus.append('modulus');
		return OS.File.writeAtomic(path_modulus.path, ba2ua(modulus));
	})
	.then(function(){
		var path_sig = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		path_sig.initWithPath(localDir.path);
		path_sig.append('sig');
		return OS.File.writeAtomic(path_sig.path, ba2ua(sig));
	})
	.then(function(){
		gBrowser.addTab(path_html.path);
	});
}
	



//extracts modulus from PEM certificate
function getModulus(certBase64){
	const nsASN1Tree = "@mozilla.org/security/nsASN1Tree;1";
	const nsIASN1Tree = Ci.nsIASN1Tree;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	var certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	var cert = certdb.constructX509FromBase64(certBase64);
	var hexmodulus = "";
	
	var certDumpTree = Cc[nsASN1Tree].createInstance(nsIASN1Tree);
	certDumpTree.loadASN1Structure(cert.ASN1Structure);
	var modulus_str = certDumpTree.getDisplayData(12);
	if (! modulus_str.startsWith( "Modulus (" ) ){
		//most likely an ECC certificate
		alert ("Unfortunately this website is not compatible with TLSNotary. (could not parse RSA certificate)");
		return;
	}
	var lines = modulus_str.split('\n');
	var line = "";
	for (var i = 1; i<lines.length; ++i){
		line = lines[i];
		//an empty line is where the pubkey part ends
		if (line === "") {break;}
		//remove all whitespaces (g is a global flag)
		hexmodulus += line.replace(/\s/g, '');
	}
	return hex2ba(hexmodulus);
}


function verifyCert(certBase64){
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	const nsIX509Cert = Ci.nsIX509Cert;
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert = certdb.constructX509FromBase64(certBase64);
	let a = {}, b = {};
	let retval = certdb.verifyCertNow(cert, nsIX509Cert.CERT_USAGE_SSLServerWithStepUp, nsIX509CertDB.FLAG_LOCAL_ONLY, a, b);
	if (retval === 0){ 		//success
		return true;
	}
	else {
		return false;
	}
}


function go_offline_for_a_moment(){
	win.document.getElementById("goOfflineMenuitem").doCommand();
	setTimeout(function(){
			win.document.getElementById("goOfflineMenuitem").doCommand();
		}, 1000);
}



function dumpSecurityInfo(channel,urldata) {
    // Do we have a valid channel argument?
    if (! channel instanceof  Ci.nsIChannel) {
        console.log("No channel available\n");
        return;
    }
    var secInfo = channel.securityInfo;
    // Print general connection security state
    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
        secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
        // Check security state flags
	latest_tab_sec_state = "uninitialised";
        if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) == Ci.nsIWebProgressListener.STATE_IS_SECURE)
            latest_tab_sec_state = "secure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) == Ci.nsIWebProgressListener.STATE_IS_INSECURE)
            latest_tab_sec_state = "insecure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) == Ci.nsIWebProgressListener.STATE_IS_BROKEN)
            latest_tab_sec_state = "unknown";
	
	//remove hashes - they are not URLs but are used for internal page mark-up
	sanitized_url = urldata.split("#")[0];
	dict_of_status[sanitized_url] = latest_tab_sec_state;
	dict_of_httpchannels[sanitized_url]  = channel.QueryInterface(Ci.nsIHttpChannel);
    }
    else {
        console.log("\tNo security info available for this channel\n");
    }
}


var	myListener =
{
    QueryInterface: function(aIID)
    {
        if (aIID.equals(Ci.nsIWebProgressListener) ||
           aIID.equals(Ci.nsISupportsWeakReference) ||
           aIID.equals(Ci.nsISupports))
            return this;
        throw Components.results.NS_NOINTERFACE;
    },
    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) { },
    onLocationChange: function(aProgress, aRequest, aURI) { },
    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) { },
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) { },
    onSecurityChange: function(aWebProgress, aRequest, aState) 
    {
        // check if the state is secure or not
        if(aState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
        {
            // this is a secure page, check if aRequest is a channel,
            // since only channels have security information
            if (aRequest instanceof Ci.nsIChannel)
            {
                dumpSecurityInfo(aRequest,gBrowser.selectedBrowser.contentWindow.location.href);          
            }
        }    
    }
};

//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
init();


} catch (e){
	script_exception = e;
}
