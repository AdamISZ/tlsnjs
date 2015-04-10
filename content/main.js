var script_exception;
try {	

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;
Cu.import("resource://gre/modules/PopupNotifications.jsm");
Cu.import('resource://gre/modules/Services.jsm');
Cu.import("resource://gre/modules/osfile.jsm")
var dict_of_status = {};
var dict_of_httpchannels = {};

var win = Cc['@mozilla.org/appshell/window-mediator;1']
	.getService(Ci.nsIWindowMediator).getMostRecentWindow('navigator:browser');
var gBrowser = win.gBrowser;
var block_urls = []; //an array of urls (filesystem paths) for which all http requests must be blocked
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
}


function startListening(){
//from now on, we will check the security status of all loaded tabs
//and store the security status in a lookup table indexed by the url.
    gBrowser.addProgressListener(myListener);
	Services.obs.addObserver(httpRequestBlocker, "http-on-modify-request", false);
}


//callback is used in testing to signal when this page's n10n finished
function startNotarizing(callback){	
    var audited_browser = gBrowser.selectedBrowser;
    var tab_url_full = audited_browser.contentWindow.location.href;
    
    //remove hashes - they are not URLs but are used for internal page mark-up
    sanitized_url = tab_url_full.split("#")[0];
    
    if (!sanitized_url.startsWith("https://")){
		alert('"ERROR You can only audit pages which start with https://');
		return;
    }
    //XXX this check is not needed anymore
    if (dict_of_status[sanitized_url] != "secure"){
	alert("The page does not have a valid SSL certificate. Refresh the page and then try to notarize it again");
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
		stream.close();
		//FF's uploaddata contains Content-Type and Content-Length headers + '\r\n\r\n' + http body
		headers += uploaddata;
	}
	var server = headers.split('\r\n')[1].split(':')[1].replace(/ /g,'');
	
	eachWindow(unloadFromWindow);
	icon =  "chrome://tlsnotary/content/icon_spin.gif";
	eachWindow(loadIntoWindow);
	  
	var modulus;
	var certsha256;
	get_certificate(server).then(function(cert){
		console.log('got certificate');
		var cert_obj = getCertObject(cert);
		if (! verifyCert(cert_obj)){
			alert("This website cannot be audited by TLSNotary because it presented an untrusted certificate");
			return;
		}
		modulus = getModulus(cert_obj);
		certsha256 = sha256(cert);
		random_uid = Math.random().toString(36).slice(-6);
		//loop prepare_pms 10 times until succeeds
		return new Promise(function(resolve, reject) {
			var tries = 0;
			var loop = function(resolve, reject){
				tries += 1;
				prepare_pms(modulus).then(function(args){
					resolve(args);
				}).catch(function(error){
					console.log('caught error', error);
					if (error != 'PMS trial failed'){
						alert('caught error ' + error);
					}
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
	.then(function(args2){
		return save_session_and_open_html(args2, server);
	})
	.then(function(){
		//testing only
		if (testing){
			callback();
		}
		eachWindow(unloadFromWindow);
		icon = "chrome://tlsnotary/content/icon.png";
		eachWindow(loadIntoWindow);
	})
	.catch(function(err){
	 //TODO need to get a decent stack trace
	 	eachWindow(unloadFromWindow);
		icon =  "chrome://tlsnotary/content/icon.png";
		eachWindow(loadIntoWindow);
		console.log('There was an error: ' + err);
		alert('There was an error: ' + err);
	});
}


//create the final html that prover and verifier will see in the tab and return 
//its path.
function create_final_html(html_with_headers, server_name, is_imported){
	if (typeof(is_imported) === "undefined"){
		is_imported = false;
	}
	var rv = html_with_headers.split('\r\n\r\n');
	var headers = rv[0];
	var html = rv[1]; 
	var localDir = getTLSNdir();
	var time = getTime();
	var imported_str = "";
	if (is_imported){
		imported_str = "-IMPORTED";
	}
	localDir.append(time+'-'+server_name+imported_str); 
	localDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0774);

	var path_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	var raw_response = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
	path_html.initWithPath(localDir.path);
	path_html.append('html.html');
	 //see "Byte order mark"
	return OS.File.writeAtomic(path_html.path, ba2ua([0xef, 0xbb, 0xbf]))
	.then(function(){
		return OS.File.writeAtomic(path_html.path, ba2ua(str2ba(html)));
	})
	.then(function(){
		raw_response.initWithPath(localDir.path);
		raw_response.append('raw.txt');
		return OS.File.writeAtomic(raw_response.path, ba2ua([0xef, 0xbb, 0xbf]));
	})
	.then(function(){
		return OS.File.writeAtomic(raw_response.path, ba2ua(str2ba(html_with_headers)));
	})
	.then(function(){
		return localDir;
	});
}


function save_session_and_open_html(args, server){
	assert (args.length === 18, "wrong args length");
	var cipher_suite = args[0];
	var client_random = args[1];
	var server_random = args[2];
	var pms1 = args[3];
	var pms2 = args[4];
	var server_cert_length = args[5];
	var server_cert = args[6];
	var tlsver = args[7];
	var initial_tlsver = args[8];
	var fullresp_length = args[9];
	var fullresp = args[10];
	var IV_after_finished_length = args[11];
	var IV_after_finished = args[12];
	var waxwing_webnotary_modulus_length = args[13];
	var signature = args[14];
	var commit_hash = args[15];
	var waxwing_webnotary_modulus = args[16];
	var html_with_headers = args[17];

	var commonName = getCertObject(server_cert).commonName;
	var localDir;
	create_final_html(html_with_headers, commonName)
	.then(function(dir){
		localDir = dir;
		var path_tlsn = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		path_tlsn.initWithPath(localDir.path);
		path_tlsn.append(commonName+'.tlsn');
		return OS.File.writeAtomic(path_tlsn.path, ba2ua([].concat(
			str2ba('tlsnotary notarization file\n\n'),
			[0x00, 0x01],
			bi2ba(cipher_suite, {'fixed':2}),
			client_random,
			server_random,
			pms1,
			pms2,
			bi2ba(server_cert_length, {'fixed':3}),
			server_cert,
			tlsver,
			initial_tlsver,
			bi2ba(fullresp_length, {'fixed':8}),
			fullresp,
			bi2ba(IV_after_finished_length, {'fixed':2}),
			IV_after_finished,
			bi2ba(waxwing_webnotary_modulus_length, {'fixed':2}),
			signature,
			commit_hash,
			waxwing_webnotary_modulus
		)));
	})
	.then(function(){
		var final_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		final_html.initWithPath(localDir.path);
		final_html.append('html.html');
		var raw = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		raw.initWithPath(localDir.path);
		raw.append('raw.txt');
		var t = gBrowser.addTab(final_html.path);
		block_urls.push(final_html.path);
		gBrowser.selectedTab = t;
		install_notification(t, commonName, raw.path);
	});
}
	

function verify_tlsn_and_show_html(path){
	OS.File.read(path).then(function(imported_data){
	var data = ua2ba(imported_data);
	var offset = 0;
	if (ba2str(data.slice(offset, offset+=29)) !== "tlsnotary notarization file\n\n"){
		throw('wrong header');
	}
	if(data.slice(offset, offset+=2).toString() !== [0x00, 0x01].toString()){
		throw('wrong version');
	}
	var cs = ba2int(data.slice(offset, offset+=2));
	var cr = data.slice(offset, offset+=32);
	var sr = data.slice(offset, offset+=32);
	var pms1 = data.slice(offset, offset+=24);
	var pms2 = data.slice(offset, offset+=24);
	var cert_len = ba2int(data.slice(offset, offset+=3));
	var cert = data.slice(offset, offset+=cert_len);
	var tlsver = data.slice(offset, offset+=2);
	var tlsver_initial = data.slice(offset, offset+=2);
	var response_len = ba2int(data.slice(offset, offset+=8));
	var response = data.slice(offset, offset+=response_len);
	var IV_len = ba2int(data.slice(offset, offset+=2));
	var IV = data.slice(offset, offset+=IV_len);
	var sig_len = ba2int(data.slice(offset, offset+=2));
	var sig = data.slice(offset, offset+=sig_len);
	var commit_hash = data.slice(offset, offset+=32);
	var notary_pubkey = data.slice(offset, offset+=sig_len);
	assert (data.length === offset, 'invalid tlsn length');
	
	var cert_obj = getCertObject(cert);
	var commonName = cert_obj.commonName;
	//verify cert
	if (!verifyCert(cert_obj)){
		throw ('certificate verification failed');
	}
	var modulus = getModulus(cert_obj);
	//verify commit hash
	if (sha256(response).toString() !== commit_hash.toString()){
		throw ('commit hash mismatch');
	}
	//verify sig
	var signed_data = sha256([].concat(commit_hash, pms2, modulus));
	if (!verify_commithash_signature(signed_data, sig, notary_pubkey)){
		throw('notary signature verification failed');
	}
	//decrypt html and check MAC
	var s = new TLSNClientSession();
	s.__init__();
	s.unexpected_server_app_data_count = response.slice(0,1);
	s.chosen_cipher_suite = cs;
	s.client_random = cr;
	s.server_random = sr;
	s.auditee_secret = pms1.slice(2, 2+s.n_auditee_entropy);
	s.initial_tlsver = tlsver_initial;
	s.tlsver = tlsver;
	s.server_modulus = modulus;
	s.set_auditee_secret();
	s.auditor_secret = pms2.slice(0, s.n_auditor_entropy);
	s.set_auditor_secret();
	s.set_master_secret_half(); //#without arguments sets the whole MS
	s.do_key_expansion(); //#also resets encryption connection state
	s.store_server_app_data_records(response.slice(1));
	s.IV_after_finished = IV;
	s.server_connection_state.seq_no += 1;
	s.server_connection_state.IV = s.IV_after_finished;
	
	var html_with_headers = decrypt_html(s);
	var localDir;
	create_final_html(html_with_headers, commonName, true)
	.then(function(dir){
		localDir = dir;
		var path_tlsn = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		path_tlsn.initWithPath(localDir.path);
		path_tlsn.append(commonName+'.tlsn');
		return OS.File.writeAtomic(path_tlsn.path, imported_data);
	})
	.then(function(){
		var final_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		final_html.initWithPath(localDir.path);
		final_html.append('html.html');
		var raw = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsILocalFile);
		raw.initWithPath(localDir.path);
		raw.append('raw.txt');
		block_urls.push(final_html.path);
		var t = gBrowser.addTab(final_html.path);
		gBrowser.selectedTab = t;
		install_notification(t, commonName, raw.path);
	});		
	});
}

//cert is an array of numbers
//return a cert object 
function getCertObject(cert){
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	var certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	var cert_obj = certdb.constructX509FromBase64(b64encode(cert));
	return cert_obj;
}


//extracts modulus from PEM certificate
function getModulus(cert_obj){
	const nsASN1Tree = "@mozilla.org/security/nsASN1Tree;1";
	const nsIASN1Tree = Ci.nsIASN1Tree;
	var hexmodulus = "";
	
	var certDumpTree = Cc[nsASN1Tree].createInstance(nsIASN1Tree);
	certDumpTree.loadASN1Structure(cert_obj.ASN1Structure);
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


//verify the certificate against FF's certdb
function verifyCert(cert_obj){
	const nsIX509Cert = Ci.nsIX509Cert;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let a = {}, b = {};
	let retval = certdb.verifyCertNow(cert_obj, nsIX509Cert.CERT_USAGE_SSLServerWithStepUp, nsIX509CertDB.FLAG_LOCAL_ONLY, a, b);
	if (retval === 0){ 		//success
		return true;
	}
	else {
		return false;
	}
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

//blocks http request coming from block_tab
var httpRequestBlocker = {
	observe: function (httpChannel, aTopic, aData) {
		if (aTopic !== "http-on-modify-request") return;
		if (!(httpChannel instanceof Ci.nsIHttpChannel)) return;    
		var notificationCallbacks;
		if (httpChannel.notificationCallbacks) {
			notificationCallbacks = httpChannel.notificationCallbacks;
		}
		else if (httpChannel.loadGroup && httpChannel.loadGroup.notificationCallbacks) {
			notificationCallbacks = httpChannel.loadGroup.notificationCallbacks;        
		}
		else return;
		var path = notificationCallbacks.getInterface(Components.interfaces.nsIDOMWindow).top.location.pathname;
		for(var i=0; i < block_urls.length; i++){
			if (block_urls[i] === path){
				console.log('found matching tab, ignoring request');
				httpChannel.cancel(Components.results.NS_BINDING_ABORTED);
			}
		}
	}
};


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


function install_notification(t, commonName, raw_path){
	t.addEventListener("load", function load(){
		console.log('in load event');
		var box = gBrowser.getNotificationBox();
		var priority = box.PRIORITY_INFO_HIGH;
		var message = 'TLSNotary successfully verified that the webpage below was received from '+commonName;
		var icon = 'chrome://tlsnotary/content/icon.png';
		var buttons = [{
			label: 'View raw HTML with HTTP headers',
			accessKey: '',
			callback: function(){
				var nt = gBrowser.addTab(raw_path);
				gBrowser.selectedTab = nt;
				//throwing an error prevents notification from closing
				throw new Error('prevent notification close');
			}
		}];
		setTimeout(function(){
			//without timeout, notifbar fails to show
			box.appendNotification(message, 'tlsn-notif', icon, priority, buttons);
		}, 1000);
		t.removeEventListener("load", load, false);
	}, false);
}


function toggle_offline(){
	window.document.getElementById("goOfflineMenuitem").doCommand();
}

//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
init();


} catch (e){
	script_exception = e;
}
