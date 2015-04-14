var is_chrome = navigator.userAgent.toLowerCase().indexOf('chrome') > -1;
if (!is_chrome){
	if (typeof(win) !== "undefined"){
		var window = win;
	}
}

var global_tlsver = [0x03, 0x02];

var local1 = {"host":"localhost", "port":"10011", "modulus":[215,74,157,189,225,84,124,238,135,250,223,150,83,215,130,154,222,184,43,205,133,160,176,8,52,155,87,117,197,229,246,0,64,184,40,78,129,72,186,146,56,29,45,31,227,143,41,210,158,57,140,144,133,147,160,174,233,4,7,218,170,207,121,87,56,147,149,1,40,240,136,166,62,168,25,83,154,79,37,127,135,161,155,79,86,248,117,255,244,202,254,215,118,139,39,112,242,36,26,109,140,32,247,187,23,71,78,108,189,85,123,144,16,200,167,28,192,13,173,18,251,221,216,215,233,78,151,169,75,96,96,244,15,150,156,24,217,117,71,199,116,184,212,159,5,23,11,146,0,189,46,2,18,149,38,77,236,202,200,113,143,255,46,36,234,204,79,142,182,181,131,30,201,145,86,235,109,18,117,93,36,224,235,70,82,183,39,32,129,78,222,88,46,93,170,78,104,133,26,227,31,252,204,221,255,79,53,221,63,183,116,212,125,102,163,235,213,144,186,11,247,227,8,252,49,53,66,88,13,79,173,124,193,122,240,167,151,154,152,189,223,12,199,34,30,127,244,135,82,176,18,121,8,231,151,93,232,181,29,26,180,92,197,156,201,210,110,100,182,168,88,98,129,69,84,111,144,138,249,47,65,136,245,51,184,233,106,30,7,54,114,242,155,25,127,198,129,252,18,7,161,158,247,69,254,250,38,235,109,21,35,133,105,62,204,182,69,152,237,5,204,102,30,142,184,132,206,188,189,78,75,72,164,216,87,7,154,254,163,163,85,227,154,121,15,98,131,226,67,145,255,135,193,148,218,81,157,152,170,33,70,77,177,183,29,84,117,39,21,53,138,75,21,231,148,149,144,122,52,132,219,35,200,91,228,171,80,212,34,88,60,198,91,193,105,251,100,169,41,68,25,160,131,184,247,199,5,152,47,143,107,7,240,22,56,150,10,204,110,200,179,117,20,147,94,137,207,196,67,94,108,4,56,157,102,176,110,83,62,4,168,64,120,110,23,172,131,100,23,104,19,159,36,152,132,235,137,236,25,233,225,55,239,79,147,72,226,79,39,26,200,214,15,161,43,236,198,235,236,76,19,80,223,28,120,39,15,233,251,181,101,203,202,45,6,180,244,86,211,41,99,108,42,221,215,182,214,10,176,243,99,157]}


var waxwing = {"host":"109.169.23.122", "port":"8080", "modulus":[224,117,88,3,77,22,21,87,102,16,49,34,212,117,228,143,107,119,84,137,127,133,182,197,78,228,53,44,99,148,120,52,229,237,38,170,114,203,155,241,7,125,255,187,163,50,194,175,189,187,104,38,15,60,226,225,9,244,92,172,223,189,152,53,69,71,241,61,26,21,252,130,202,3,95,171,200,91,72,152,2,102,50,15,30,139,63,162,3,1,132,24,30,181,130,215,74,43,209,240,227,13,229,117,70,176,79,82,15,164,189,115,138,228,250,96,88,36,181,185,130,92,255,29,100,245,83,14,96,149,27,3,51,222,17,49,48,151,130,242,107,69,74,47,134,190,233,160,9,202,103,168,33,82,60,227,232,18,47,204,216,119,132,213,234,214,56,141,149,227,113,141,243,219,190,113,233,108,153,36,249,139,217,95,1,124,141,42,233,209,140,167,191,172,249,12,32,5,139,219,80,42,144,108,162,101,90,23,224,71,150,229,227,95,219,194,226,106,238,167,72,37,172,105,219,78,84,99,137,213,72,156,65,216,105,92,163,152,158,195,170,169,200,146,163,233,35,2,75,66,38,108,63,98,197,47,52,242,129,226,220,182,58,34,214,205,79,131,250,136,167,203,130,181,81,85,29,17,153,17,62,157,219,9,178,171,245,214,129,9,92,166,234,230,67,87,132,190,106,16,59,236,49,24,230,93,4,211,222,236,64,246,248,163,5,150,183,208,58,23,73,244,209,10,230,175,56,169,1,160,53,87,154,221,27,135,125,229,77,54,174,178,10,189,249,68,232,56,117,178,130,142,7,142,116,55,124,48,7,254,179,78,162,248,156,35,126,53,238,148,63,152,180,16,237,241,147,246,7,137,126,119,146,49,244,38,197,42,112,84,152,147,58,122,60,26,79,216,111,74,171,183,64,247,245,224,34,237,10,255,167,199,180,189,122,50,230,114,14,180,85,127,155,67,142,202,203,243,130,120,146,117,185,51,100,91,12,198,61,182,157,59,64,127,66,42,36,179,188,219,171,23,129,162,189,90,163,105,56,139,99,43,11,9,162,131,243,65,52,191,154,166,165,250,167,180,190,226,146,127,13,115,0,33,198,134,191,17,100,165,13,251,216,36,61,222,60,59,219,41,6,123,243,182,213,38,109,125,194,176,97,11]}

var oracle1 = {"host":"ec2-52-74-41-76.ap-southeast-1.compute.amazonaws.com", "port":"10011", "modulus":[213,230,13,162,128,103,220,244,203,109,227,136,58,107,119,5,92,108,201,66,39,221,229,66,232,233,138,144,242,111,2,15,81,249,65,168,107,129,52,109,218,100,243,201,89,132,61,161,37,11,153,144,141,173,82,9,90,215,245,82,88,118,228,177,180,90,182,112,233,207,239,82,24,82,26,82,142,166,135,150,198,88,253,24,158,244,86,29,221,211,43,241,186,246,201,252,155,7,121,171,238,177,203,189,33,41,207,142,42,186,183,187,78,42,31,22,43,252,229,91,135,228,57,93,52,75,81,216,67,145,106,215,219,87,163,174,119,47,225,180,164,202,190,186,141,181,141,233,105,179,248,234,33,168,251,103,174,122,242,225,144,90,110,253,22,23,72,121,236,168,81,118,15,2,101,29,185,165,54,27,17,228,213,121,97,10,90,187,155,31,41,66,158,30,63,80,200,229,68,54,79,113,226,133,23,139,146,0,86,166,211,37,92,102,191,196,101,96,95,11,88,242,95,251,138,119,134,228,237,218,96,66,174,36,147,151,122,36,18,34,189,91,253,55,89,195,235,200,48,59,58,154,115,125,2,58,2,29,231,145,15,90,109,214,73,188,40,85,46,148,5,252,180,42,172,10,203,255,26,225,72,174,239,81,56,4,231,33,104,32,32,207,218,94,77,58,191,113,138,250,122,8,9,189,200,173,85,90,182,227,14,9,92,55,189,253,182,114,212,137,77,82,205,155,253,13,78,163,54,249,111,142,126,117,15,206,147,242,129,163,218,84,224,45,70,13,28,174,236,9,2,11,134,131,234,109,86,107,160,173,98,60,212,48,250,181,35,20,237,185,6,231,14,204,213,50,173,160,75,178,98,43,147,135,2,106,56,244,214,203,67,185,135,28,9,219,31,115,224,138,17,227,131,252,44,132,196,240,53,137,62,35,95,230,87,130,61,49,63,41,156,94,193,124,147,226,211,208,59,21,155,27,145,124,12,46,50,141,103,53,65,195,200,95,12,154,150,163,220,94,196,212,63,198,27,4,93,60,34,180,105,2,49,176,113,71,3,148,124,211,31,39,146,233,83,53,8,228,188,14,238,194,247,78,220,22,185,228,196,171,72,232,106,73,21,225,53,13,202,249,218,181,66,89,211,228,105,160,45,17,232,231]}


var chosen_notary = oracle1;



	
//#constants
var md5_hash_len = 16;
var sha1_hash_len = 20;
var aes_block_size = 16;
var tls_ver_1_0 = [3,1];
var tls_ver_1_1 = [3,2];
var tls_versions = [tls_ver_1_0,tls_ver_1_1];
//#record types
var appd = 0x17; //#Application Data
var hs = 0x16; //#Handshake
var chcis = 0x14; //#Change Cipher Spec
var alrt = 0x15; //#Alert
var tls_record_types = [appd,hs,chcis,alrt];
//#handshake types
var h_ch = 0x01; //#Client Hello
var h_sh = 0x02; //#Server Hello
var h_cert = 0x0b; //#Certificate
var h_shd = 0x0e; //#Server Hello Done
var h_cke = 0x10; //#Client Key Exchange
var h_fin = 0x14; //#Finished
var tls_handshake_types = [h_ch,h_sh,h_cert,h_shd,h_cke,h_fin];


/*
The amount of key material for each ciphersuite:
AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes
*/

var tlsn_cipher_suites = [ {47:['AES128',20,20,16,16,16,16]},
                    {53:['AES256',20,20,32,32,16,16]},
                    {5:['RC4SHA',20,20,16,16,0,0]},
                    {4:['RC4MD5',16,16,16,16,0,0]} ];
//#preprocessing: add the total number of bytes in the expanded keys format
//#for each cipher suite, for ease of reference
for(var i=0; i < tlsn_cipher_suites.length; i++){
	var key = Object.keys(tlsn_cipher_suites[i])[0];
	var sum = 0;
	var values = tlsn_cipher_suites[i][key];
	for (var j=1; j<values.length; ++j){
		sum += values[j];
	}
	tlsn_cipher_suites[i][key].push(sum);
}
function get_cs(cs){
	for(var i=0; i < tlsn_cipher_suites.length; i++){
		if (cs === parseInt(Object.keys(tlsn_cipher_suites[i])[0])){
			return tlsn_cipher_suites[i][cs];
		}
	}
	throw("Could not find cs " + cs.toString());
}





function check_complete_records(d){
    /*'''Given a response d from a server,
    we want to know if its contents represents
    a complete set of records, however many.'''
    */
    var l = ba2int(d.slice(3,5));
    if (d.length < (l+5)){
		return false;
	}
    else if(d.length === (l+5)){
		return true;
	}
    else {
		return check_complete_records(d.slice(l+5));
	}
}

function get_xhr(){
	if (is_chrome){
		return new XMLHttpRequest();
	}
	//else firefox addon
	return Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
}

function Socket(name, port){
	this.name = name;
	this.port = port;
	this.sckt = null;
	this.is_open = false;
	this.buffer = [];
}
Socket.prototype.connect = function(){
	//TCPSocket doesnt like to be wrapped in a Promise. We work around by making the
	//promise resolve when .is_open is triggered
	var TCPSocket = Components.classes["@mozilla.org/tcp-socket;1"].createInstance(Components.interfaces.nsIDOMTCPSocket);
	this.sckt = TCPSocket.open(this.name, this.port, {binaryType:"arraybuffer"});
	var that = this; //inside .ondata/open etc this is lost
	this.sckt.ondata = function(event){ 
		//transform ArrayBuffer into number array
		var view = new DataView(event.data);
		var int_array = [];
		for(var i=0; i < view.byteLength; i++){
			int_array.push(view.getUint8(i));
		}
		console.log('ondata got bytes:', view.byteLength);
		that.buffer = [].concat(that.buffer, int_array);
	}
	this.sckt.onopen = function() {
		that.is_open = true;
		console.log('onopen');
	}
	
	var sock = this;
	return new Promise(function(resolve, reject) {
		var total_waited = 0;
		var timeout = function(resolve, reject){
			if ((total_waited / 1000) >= 20){
				reject('socket timed out');
			}
			setTimeout(function(){
				if (!sock.is_open){
					console.log('Another timeout');
					total_waited += 100;
					timeout(resolve, reject);
					return;
				}
				console.log('promise resolved');
				resolve('ready');
			}, 100);
		};
		timeout(resolve, reject);
	});
	
};
Socket.prototype.send = function(data_in){
	//Transform number array into ArrayBuffer
	var sock = this.sckt;
	var ab = new ArrayBuffer(data_in.length);
	var dv = new DataView(ab);
	for(var i=0; i < data_in.length; i++){
		dv.setUint8(i, data_in[i]);
	}
	sock.send(ab, 0, ab.byteLength);
}
Socket.prototype.recv = function(is_handshake){
	if (typeof(is_handshake) === "undefined"){
		is_handshake = false;
	}
	var sock = this;
	return new Promise(function(resolve, reject) {
		console.log('in recv promise');
		var total_waited = 0;
		var timeout_val = 100;
		var tmp_buf = [];
		//keep checking until either timeout or enough data gathered
		var check_recv = function(resolve, reject){
			if ((total_waited / 1000) >= 20){
				reject('socket timed out');
			}
			if (sock.buffer.length === 0){
				console.log('Another timeout in recv');
				total_waited += timeout_val;
				setTimeout(function(){
					check_recv(resolve, reject);
				}, timeout_val);
				return;
			}
			tmp_buf = [].concat(tmp_buf, sock.buffer);
			sock.buffer = [];
			if(! check_complete_records(tmp_buf)){
				console.log("check_complete_records failed");
				setTimeout(function(){
					check_recv(resolve, reject);
				}, timeout_val);
				return;
			}
			//else
			console.log('promise resolved');
			resolve(tmp_buf);
		};
		check_recv(resolve, reject);
	});
}
Socket.prototype.close = function(){
	this.sckt.close();
};


//Socket_proxy is only needed during testing when testing on Chrome
function Socket_proxy(name, port){
	this.name = name;
	this.port = port;
	this.socketport = '7772';
	this.busy = false;
	//this.req = new XMLHttpRequest();
	//this.req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
	this.req = get_xhr();
}
Socket_proxy.prototype.connect = function(){
	//send to backend to open a new connection
	var that = this;
	return new Promise(function(resolve, reject) {
		var loop = function(resolve, reject){
			if (! that.busy){
				resolve('ok');
				return;
			}
			//else busy
			setTimeout(function(){
				loop(resolve, reject);
			}, 100);
			return;
		};
		loop (resolve, reject);
	})
	.then(function(){
		return new Promise(function(resolve, reject) {	
			var req = that.req;
			req.open("HEAD", "http://127.0.0.1:"+that.socketport+"/connect?"+that.name+"&"+that.port, true);
			console.log('sending connect');
			req.onload = function(){
				console.log('connect onload');
				req.abort();
				that.busy = false;
				resolve('success');
			};
			that.busy = true;
			req.send();
		});
	});
};
Socket_proxy.prototype.send = function(data_in){
	var that = this;
	if (that.busy){
		setTimeout(function(){
			that.send.call(that, data_in);
		}, 100);
		return;
	}
	return new Promise(function(resolve, reject) {
		var req = that.req;
		//sending a comma separated array of numbers because we dont want extra base64 code in extension
		req.open("HEAD", "http://127.0.0.1:"+that.socketport+"/send?"+data_in.toString(), true);
		console.log('sending send');
		req.onabort = function(){
			console.log('send abort');
			reject('rejected');
		};
		req.onload = function(){
			req.abort();
			console.log('send onload');
			that.busy = false;
			resolve('success');
		};
		req.send();
	});
};
Socket_proxy.prototype.recv = function(sckt, is_handshake, callbacks, previous_reply){
	var that = this;
	if (that.busy){
		setTimeout(function(){
			that.recv.call(that, sckt, is_handshake, callbacks, previous_reply);
		}, 100);
		return;
	}	
	
	var reply = [];
	if (typeof(previous_reply) !== "undefined"){
		reply = [].concat(reply, previous_reply);
	}
	if (typeof(is_handshake) === "undefined"){
		is_handshake = false;
	}
	
	return new Promise(function(resolve, reject) {
		var req = that.req;
		req.open("HEAD", "http://127.0.0.1:"+that.socketport+"/recv", true);
		req.onerror = function(){
			console.log('xhr error');
			reject('xhr error');
		};
		req.onload = function(){
			console.log('got reply for recv');
			that.busy = false;
			var data = req.getResponseHeader("data");
			req.abort();
			var int_ar = data.split(',');
			//NB: addon sends 'data' with a trailing comma, but chrome removes it 
			for (var i=0; i < int_ar.length; i++){
				reply = [].concat(reply, parseInt(int_ar[i]));
			}
			console.log('in recv onload with bytes:' + reply.length);
			if (is_handshake){
				if(! check_complete_records(reply)){
					console.log("check_complete_records failed");
					that.recv.call(that, sckt, is_handshake, callbacks, reply);
					return;
				}
			}		
			resolve(reply);
		};
		//give the backend some time
		console.log('sending recv');
		req.send();
	});
};
if (is_chrome){
	Socket = Socket_proxy;
}



function send_and_recv(command, data, expected_response){
	return new Promise(function(resolve, reject) {
		var req = get_xhr();
		req.open("HEAD", "http://"+chosen_notary.host+":"+chosen_notary.port, true);
		req.setRequestHeader("Request", command);
		req.setRequestHeader("Data", b64encode(data));
		req.setRequestHeader("UID", random_uid);
		//disable headers which Firefox appends by default
		req.setRequestHeader("Host", "");
		req.setRequestHeader("User-Agent", "");
		req.setRequestHeader("Accept", "");
		req.setRequestHeader("Accept-Language", "");
		req.setRequestHeader("Accept-Encoding", "");
		req.setRequestHeader("Connection", "close");
		var timeout = setTimeout(function(){
			reject ('Timed out waiting for notary server to respond');
		}, 10*1000);
		req.onload = function(){
			clearTimeout(timeout);
			var response = req.getResponseHeader("Response");
			if (response !== expected_response){
				reject('Unexpected response. Expected '+ expected_response + ' but got ' + response);
				return;
			}
			var b64data = req.getResponseHeader("Data");
			var data = b64decode(b64data);
			console.log('got from oracle', response);
			resolve(data);
		};
		console.log('sent to oracle', command);
		req.send();
	});
}


var pms_session;
var rsapms2;
function prepare_pms(modulus, tryno){
	isdefined(modulus);
	if (typeof(tryno) === "undefined"){
		tryno = 1;
	}
	var rs_choice = 'github.com';
	var random_rs_n = 0;
	pms_session = new TLSNClientSession();
	pms_session.__init__({'server':rs_choice, 'ccs':53, 'tlsver':global_tlsver});
	pms_session.server_modulus = [177,212,220,60,175,253,243,78,237,193,103,173,230,203,34,232,183,226,171,40,242,247,220,98,112,8,209,12,175,214,22,106,33,176,54,75,23,13,54,99,4,174,191,234,32,81,149,101,102,242,191,185,77,164,12,41,235,245,21,177,232,53,179,112,16,148,213,27,89,180,38,15,214,131,87,89,157,225,124,9,221,224,19,202,77,111,67,155,205,207,135,58,21,167,133,221,102,131,237,147,12,254,43,109,56,28,121,136,144,207,173,88,24,45,81,209,194,163,242,71,140,111,56,9,185,184,239,76,147,11,203,131,148,135,234,224,163,181,217,123,155,107,15,67,249,202,238,128,13,40,167,118,241,37,244,193,53,60,246,116,173,222,106,51,130,123,220,253,75,118,167,194,238,242,106,191,169,36,166,95,231,46,124,14,219,195,116,115,250,126,198,216,207,96,235,54,86,33,182,193,138,184,36,130,77,120,36,186,233,29,161,138,167,135,190,102,37,105,191,190,59,114,110,79,224,228,133,37,8,177,145,137,184,214,116,101,118,155,44,79,98,31,161,250,58,190,156,36,191,159,202,176,197,192,103,141];
	pms_session.sckt = new Socket(pms_session.server_name, pms_session.ssl_port);
	return pms_session.sckt.connect()
	.then(function(){
		pms_session.send_client_hello();
		return pms_session.get_server_hello();
	})
	.then(function(handshake_objects){
		pms_session.process_server_hello(handshake_objects);
		var comm = 'rcr_rsr_rsname_n';
		var data = [].concat(pms_session.client_random, pms_session.server_random, str2ba(rs_choice).slice(0,5), modulus);
		return send_and_recv(comm, data, "rrsapms_rhmac_rsapms");
	})
	.then(function(reply_data){
		var rrsapms2 = reply_data.slice(0, 256);
		pms_session.p_auditor = reply_data.slice(256, 304);
		rsapms2 = reply_data.slice(304);
		//assert(rsapms2.length === modulus.length, "rsapms2.length === modulus.length");
		return pms_session.complete_handshake(rrsapms2);
	})
	.then(function(response){
		pms_session.sckt.close();
		/*#judge success/fail based on whether a properly encoded 
		#Change Cipher Spec record is returned by the server (we could
		#also check the server finished, but it isn't necessary)*/
		var record_to_find = new TLSRecord();
		record_to_find.__init__(chcis, [0x01], global_tlsver);
		if (response.toString().indexOf(record_to_find.serialized.toString()) < 0){
			console.log("PMS trial failed, retrying. ("+response.toString()+")");
			throw("PMS trial failed");
		}
		return( [pms_session.auditee_secret, pms_session.auditee_padding_secret, rsapms2] );	
	});
}


function negotiate_crippled_secrets(tlsn_session){
    //'''Negotiate with auditor in order to create valid session keys
    //(except server mac is garbage as auditor withholds it)'''
    assert(tlsn_session.handshake_hash_md5 && tlsn_session.handshake_hash_sha);
    tlsn_session.set_auditee_secret();
    var s = tlsn_session;
    var cs_cr_sr_hmacms_verifymd5sha = [].concat(s.chosen_cipher_suite, s.client_random, s.server_random,
									s.p_auditee.slice(0, 24), s.handshake_hash_md5, s.handshake_hash_sha);
    return send_and_recv('cs_cr_sr_hmacms_verifymd5sha', cs_cr_sr_hmacms_verifymd5sha, 'hmacms_hmacek_hmacverify')
    .then(function(reply_data){		
		var chosen_cs = get_cs(tlsn_session.chosen_cipher_suite);
		var expanded_key_len = chosen_cs.slice(chosen_cs.length-1)[0];
		if (reply_data.length != 24+expanded_key_len+12){
			throw('unexpected reply length in negotiate_crippled_secrets');
		}
		var hmacms = reply_data.slice(0, 24);
		var hmacek = reply_data.slice(24, 24 + expanded_key_len);
		var hmacverify = reply_data.slice(24 + expanded_key_len, 24 + expanded_key_len+12);
		tlsn_session.set_master_secret_half({'half':2, 'provided_p_value':hmacms});
		tlsn_session.p_master_secret_auditor = hmacek;
		tlsn_session.do_key_expansion();
		tlsn_session.send_client_finished(hmacverify);
		return tlsn_session.get_server_finished();		
	})
	.then(function(records){
		tlsn_session.process_server_finished(records);
		var rv = tlsn_session.set_handshake_hashes({'server':true});
		var sha_digest2 = rv[0];
		var md5_digest2 = rv[1];
		return send_and_recv('verify_md5sha2', [].concat(md5_digest2, sha_digest2), 'verify_hmac2');
	})
	.then(function(verify_hmac2){	
		 if (!tlsn_session.check_server_ccs_finished(verify_hmac2)){
			throw ("Could not finish handshake with server successfully. Audit aborted");
		}
	});
}



function decrypt_html(tlsn_session){
	console.log("will decrypt cs:", tlsn_session.server_connection_state.cipher_suite);
	var rv = tlsn_session.process_server_app_data_records();
	var plaintext = rv[0];
	var bad_mac = rv[1];
	if (bad_mac) {
		throw("ERROR! Audit not valid! Plaintext is not authenticated.");
	}
	var plaintext_str = ba2str(plaintext);
	var plaintext_dechunked = dechunk_http(plaintext_str);
	var plaintext_gunzipped = gunzip_http(plaintext_dechunked);
	console.log('returning plaintext of length ' + plaintext_gunzipped.length);
	return plaintext_gunzipped;
}


var g_cert;//for testing
function get_certificate(server){
	var probe_session = new TLSNClientSession();
	probe_session.__init__({'server':server, 'tlsver':global_tlsver});
	probe_session.sckt = new Socket(probe_session.server_name,probe_session.ssl_port);
	return probe_session.sckt.connect()
	.then(function(){
		probe_session.send_client_hello();
		return probe_session.get_server_hello();
	})
	.then(function(handshake_objects){
		probe_session.process_server_hello(handshake_objects);
		probe_session.sckt.close();
		g_cert = probe_session.server_certificate.asn1cert;
		return g_cert;
	});
}


function start_audit(modulus, certhash, name, headers, ee_secret, ee_pad_secret, rsapms2){
	var tlsn_session = new TLSNClientSession();
	tlsn_session.__init__({'server':name, 'tlsver':global_tlsver});
	tlsn_session.server_modulus = modulus;
	tlsn_session.server_mod_length = modulus.length;
	tlsn_session.auditee_secret = ee_secret;
	tlsn_session.auditee_padding_secret = ee_pad_secret;
	tlsn_session.enc_second_half_pms = rsapms2;
	tlsn_session.set_enc_first_half_pms();
	tlsn_session.set_encrypted_pms();
	tlsn_session.sckt = new Socket(tlsn_session.server_name, tlsn_session.ssl_port);
	var commit_hash;
	var fullresp;
	var signature;
	var pms2;
	return tlsn_session.sckt.connect().then(function(){
		tlsn_session.send_client_hello();
		return tlsn_session.get_server_hello();
	})
	.then(function(handshake_objects){
		tlsn_session.process_server_hello(handshake_objects);
		console.log("negotiate_crippled_secrets");
		return negotiate_crippled_secrets(tlsn_session);
	})
	.then(function(){
		//#before sending any data to server compare this connection's cert to the
		//#one which FF already validated earlier
		if (sha256(tlsn_session.server_certificate.asn1cert).toString() != certhash.toString()){
			throw('Certificate mismatch');
		}
		var headers_ba = str2ba(headers);
		tlsn_session.build_request(headers_ba);
		console.log("sent request");
		return tlsn_session.sckt.recv(false); //#not handshake flag means we wait on timeout
	})
	.then(function(response){
		tlsn_session.store_server_app_data_records(response);
		tlsn_session.sckt.close();
		//#we return the full record set, not only the response to our request
		//#prefix response with number of to-be-ignored records, 
		//#note: more than 256 unexpected records will cause a failure of audit. Just as well!
		fullresp = [].concat(tlsn_session.unexpected_server_app_data_count, 
						tlsn_session.unexpected_server_app_data_raw, response);
		commit_hash = sha256(fullresp);
		return send_and_recv('commit_hash',commit_hash, 'pms2');
	})
	.then(function(response){
		pms2 = response.slice(0,24);
		signature = response.slice(24);
		var modulus = chosen_notary.modulus;
		var signed_data = sha256([].concat(commit_hash, pms2, tlsn_session.server_modulus));
		console.log('beginning sig verification');
		if (!verify_commithash_signature(signed_data, signature, modulus)){
			throw('Failed to verify notary server signature');
		}
		console.log('finished sig verification');
		tlsn_session.auditor_secret = pms2.slice(0, tlsn_session.n_auditor_entropy);
		tlsn_session.set_auditor_secret();
		tlsn_session.set_master_secret_half(); //#without arguments sets the whole MS
		tlsn_session.do_key_expansion(); //#also resets encryption connection state
	
		//#decrypt and verify mac of server finished as normal
		if (tlsn_session.mac_check_server_finished() !== true){
			throw('Failed to verify MAC for server finished');
		}   
		var plaintext = decrypt_html(tlsn_session);
		return [tlsn_session.chosen_cipher_suite,
				tlsn_session.client_random,
				tlsn_session.server_random,
				tlsn_session.pms1,
				tlsn_session.pms2,
				tlsn_session.server_certificate.asn1cert.length,
				tlsn_session.server_certificate.asn1cert,
				tlsn_session.tlsver,
				tlsn_session.initial_tlsver,
				fullresp.length,
				fullresp,
				tlsn_session.IV_after_finished.length,
				tlsn_session.IV_after_finished,
				chosen_notary.modulus.length,
				signature,
				commit_hash,
				chosen_notary.modulus,
				plaintext];
	});
}


function verify_commithash_signature(commithash, signature, modulus){
	//RSA verification is sig^e mod n, drop the padding and get the last 32 bytes
	var bigint_signature = new BigInteger(ba2hex(signature), 16);
	var bigint_mod = new BigInteger(ba2hex(modulus), 16);
	var bigint_exp = new BigInteger(ba2hex(bi2ba(65537)), 16);
	var bigint_result = bigint_signature.modPow(bigint_exp, bigint_mod);
	var padded_hash = hex2ba(bigint_result.toString(16));
	var hash = padded_hash.slice(padded_hash.length-32);
	if (commithash.toString() === hash.toString()){
		return true;
	}
	else {
		return false;
	}
}



function tls_record_decoder(d){
/*'Given a binary data stream d,
separate it into TLS records and return
as a list of TLSRecord objects. If no
TLS record is found at the start of the stream,
return False. If any additional data is found
at the end of the final record, it is returned
as the second part of the returned tuple.
Note that record length is only validated here
in the decoder.*/
	var records = [];
	var remaining = [];
	if (tls_record_types.indexOf(d[0]) < 0){
		return false;
	}
	while (d){    
		var rt = d[0];
		if (tls_record_types.indexOf(rt) < 0){
			remaining = d;
			break;
		}
		var ver = d.slice(1,3);
		var version_found = false;
		for (var i=0; i<tls_versions.length; i++){
			if (tls_versions[i].toString() === ver.toString()){
				version_found = true;
				break;
			}
		}
		assert(version_found, "Incompatible TLS version");
		var l = ba2int(d.slice(3,5));
		if (d.length < l+5){
			throw("incomplete TLS record");
		}
		var fragment = d.slice(5,5+l);
		d = d.slice(5+l);
		var rec = new TLSRecord();
		rec.__init__(rt, fragment, ver);
		records.push(rec);
	}      
	return [records,remaining];
}


function tls_record_fragment_decoder(t, d, args){
    /*'''Given the record type t and the data fragment d,
    we construct as many objects of that type as we can find
    in the fragment and return them as a list of Python objects.
    If conn is not None, the record fragment is assumed to be 
    encrypted and is decrypted before processing. '''	*/
    
    //#dictionary to allow dynamic decoding of a handshake message in a record fragment   
	var hs_type_map = {};
	hs_type_map[h_ch] = TLSClientHello;
	hs_type_map[h_sh] = TLSServerHello;
	hs_type_map[h_cert] = TLSCertificate;
	hs_type_map[h_cke] = TLSClientKeyExchange;
	hs_type_map[h_fin] = TLSFinished;
	hs_type_map[h_shd] = TLSServerHelloDone;

    var conn = null;
    var ignore_mac = false;
    var plaintext;
    var validity;
    var mac;
    var rv;
    if (typeof(args) !== "undefined"){
		if (typeof(args.conn) !== "undefined"){
			conn = args.conn;
		}
		if (typeof(args.ignore_mac) !== "undefined"){
			ignore_mac = args.ignore_mac;
		}
	}
	hlpos = [];
	if (conn){
		if (ignore_mac){ //means we won't check it now, but store to be checked later
			rv = conn.dtvm(d, t, true);
			validity = rv[0];
			plaintext = rv[1];
			mac = rv[2];
		}
		else {
			rv = conn.dtvm(d, t);
			validity = rv[0];
			plaintext = rv[1];
		}
		if (!validity && !ignore_mac){
			throw("Mac failure");
		}
	}
	else {
		plaintext = d;
	}
	while (plaintext.length){
	 	if (t === hs){
			var hs_types = [];
	 		var hs_types_keys = Object.keys(hs_type_map);
	 		for(var i=0; i < hs_types_keys.length; i++){
				hs_types.push(parseInt(hs_types_keys[i]));
			}
            assert(hs_types.indexOf(plaintext[0]) > -1, "Invalid handshake type");
            constructed_obj = new hs_type_map[plaintext[0]]();
            constructed_obj.__init__({'serialized':plaintext});
        }
        else if (t === appd){
            constructed_obj = new TLSAppData();
            constructed_obj.__init__(plaintext);
		}
        else if (t === alrt){
            constructed_obj = new TLSAlert();
            constructed_obj.__init__({'serialized':plaintext});
		}
        else if (t === chcis){
            constructed_obj   = new TLSChangeCipherSpec();
            constructed_obj.__init__({'serialized':plaintext});
		}
        else{
            throw("Invalid record type");
		}
        hlpos.push(constructed_obj);
        plaintext = constructed_obj.discarded;
	}
    if (conn){ 
	    //#Note this assumes that only ONE encrypted message
	    hlpos[0].encrypted = d;
	    if (ignore_mac){
	        hlpos[0].recorded_mac = mac;
		}
	}
    return hlpos;
}


function TLSRecord(){}
TLSRecord.prototype.__init__ = function(ct, fragment, tlsver){
	this.content_type = ct;
	this.content_version = tlsver;
	if (fragment){
		this.fragment = fragment;
		this._length = this.fragment.length;
		this.serialize();
	}
};
TLSRecord.prototype.serialize = function(){
	var check_contents = this.content_type && this.content_version && this._length && this.fragment;
	assert(check_contents, "Cannot serialize record, data incomplete");
	assert(this.fragment.length == this._length, "Incorrect record length");
	this.serialized = [].concat(this.content_type, this.content_version, bi2ba(this._length, {'fixed':2}), this.fragment);
};



function TLSHandshake(){}
TLSHandshake.prototype.__init__ = function(serialized, handshake_type){
	if (typeof(serialized)==='undefined') serialized = null;
	if (typeof(handshake_type)==='undefined') handshake_type = null;
	this.handshake_type = handshake_type;
	if (serialized){
		this.serialized = serialized;
		assert(this.handshake_type == this.serialized[0], "Mismatched handshake type");
		assert([h_ch,h_sh,h_shd,h_cert,h_cke,h_fin].indexOf(this.handshake_type) > -1, 
			'Unrecognized or unimplemented handshake type');
		this.handshake_record_length = ba2int(this.serialized.slice(1,4));
		if (this.serialized.slice(4).length < this.handshake_record_length){
			throw ('Invalid handshake message length');
		}
		this.discarded = this.serialized.slice(4+this.handshake_record_length);
		/*if (this.discarded){
			console.log ('Info: got a discarded data when constructing',
				   'a handshake message of type: ', this.handshake_type.toString(),
				   ' and discarded length was: ', this.discarded.length);
	   }
	   * */
		//#Note that we do *not* strip handshake headers for the serialized form;
		//#this is a complete, valid handshake message.
		this.serialized = this.serialized.slice(0,4+this.handshake_record_length);
	}
};
TLSHandshake.prototype.serialize = function(){
	if (typeof(this.serialized) === "undefined"){
		this.serialized = [];
	}
	var len = bi2ba(this.serialized.length, {'fixed':3});
	this.serialized = [].concat(this.handshake_type, len, this.serialized);
};



//inheritance
TLSClientHello.prototype = new TLSHandshake();
TLSClientHello.prototype.constructor=TLSClientHello;
TLSClientHello.prototype.parent = TLSHandshake.prototype;
function TLSClientHello(){}
TLSClientHello.prototype.__init__ = function(args){
	var serialized = args.serialized;
	var client_random = args.client_random;
	var cipher_suites = args.cipher_suites;
	var tlsver = args.tlsver;
	var i;
	this.typename = "TLSClientHello";
	//TODO default args here
	if (serialized){
            print ('Not implemented instantiation of client hello', 
                   'with serialization; this is a client-only',
                   ' TLS implementation');
	}
	else {
		if (client_random){
			this.client_random = client_random;
		}
		else {
			var cr = [];
			for(i=0; i<32; i++){cr.push(2);}
			//this.client_random = cr;
			this.client_random = getRandom(32, window);
			
		}
		this.tlsver = tlsver;
		this.serialized = [].concat(this.tlsver, this.client_random, 0);
		this.cipher_suites = cipher_suites;
		this.serialized = [].concat(this.serialized, 0x00, 2*this.cipher_suites.length);
		for (i=0; i<this.cipher_suites.length; i++){
			var cs = this.cipher_suites[i];
			this.serialized = [].concat(this.serialized, 0x00, cs);
		}
		this.serialized = [].concat(this.serialized, 0x01, 0x00); //compression methods - null only 
		//call sod in the context of this instance
		TLSHandshake.prototype.__init__.call(this, null, h_ch);
		TLSHandshake.prototype.serialize.call(this);
	}
};



TLSServerHello.prototype = new TLSHandshake();
TLSServerHello.prototype.constructor=TLSServerHello;
TLSServerHello.prototype.parent = TLSHandshake.prototype;
function TLSServerHello(){}
TLSServerHello.prototype.__init__ = function(args){
	var serialized = args.serialized;
	var server_random = args.server_random;
	var cipher_suites = args.cipher_suites;
	this.typename = "TLSServerHello";
	if (serialized){
		this.parent.__init__(serialized, h_sh);
       	this.tlsver = this.serialized.slice(4,6);
        this.server_random = this.serialized.slice(6,38);
        this.session_id_length = ba2int([].concat(this.serialized[38]));
        var remainder;
        if (this.session_id_length !== 0){
            assert(this.session_id_length == 32,'Server hello contains unrecognized session id format');
            this.session_id = this.serialized.slice(39,71);
            remainder = this.serialized.slice(71);
		}
        else {
            remainder = this.serialized.slice(39);
            this.session_id = null;
		}

      	this.cipher_suite = ba2int(remainder.slice(0,2));
      	var cs_keys = [];
      	for(var i=0; i < tlsn_cipher_suites.length; i++){
			var key = Object.keys(tlsn_cipher_suites[i])[0];
			cs_keys.push(parseInt(key));
		}
        assert(cs_keys.indexOf(this.cipher_suite) > -1, 
        	'Server chosen cipher suite not in TLS Notary allowed list, it was: '+this.cipher_suite.toString());
        assert(remainder.slice(2).toString() === [0x00].toString(), 'Received invalid server hello compression method');
        //#At end of serialized instantiation, we have defined server
        //#random and cipher suite
	}
	else {
		print ("Not implemented instantiation of server hello without serialization; this is a client-only TLS implementation");
	}
};



TLSCertificate.prototype = new TLSHandshake();
TLSCertificate.prototype.constructor=TLSCertificate;
TLSServerHello.prototype.parent = TLSHandshake.prototype;
function TLSCertificate(){}
TLSCertificate.prototype.__init__ = function(args){
	var serialized = args.serialized;
	if (serialized){
		TLSHandshake.prototype.__init__.call(this, serialized, h_cert);
		/*#TODO we are currently reading *only* the first certificate
        #in the list (tlsnotary code compares this with the browser
        #as a re-use of browser PKI). It may be necessary to do a 
        #more detailed parsing.
        #This handshake message has format: hs_cert(1), hs_msg_len(3),
        #certs_list_msg_len(3), [cert1_msg_len(3), cert1, cert_msg_len(3), cert2...]
        #so the first cert data starts at byte position 10 */
        this.cert_len = ba2int(this.serialized.slice(7,10));
        this.asn1cert = this.serialized.slice(10,10+this.cert_len);
        this.typename = "TLSCertificate";
	}
        
    else {
    	print ('Not implemented instantiation of certificate without serialization; this is a client-only TLS implementation');
	}
};



TLSServerHelloDone.prototype = new TLSHandshake();
TLSServerHelloDone.prototype.constructor=TLSServerHelloDone;
TLSServerHelloDone.prototype.parent = TLSHandshake.prototype;
function TLSServerHelloDone(){}
TLSServerHelloDone.prototype.__init__ = function(args){
	var serialized = args.serialized;
	this.typename = "TLSServerHelloDone";
	if (serialized){
		//call parent method in the context of this instance
		TLSHandshake.prototype.__init__.call(this, serialized, h_shd);
	}
	else {
		print ('Not implemented instantiation of server hello done without serialization; this is a client-only TLS implementation');
	}
};


TLSClientKeyExchange.prototype = new TLSHandshake();
TLSClientKeyExchange.prototype.constructor=TLSClientKeyExchange;
TLSClientKeyExchange.prototype.parent = TLSHandshake.prototype;
function TLSClientKeyExchange(){}
TLSClientKeyExchange.prototype.__init__ = function(args){
	var serialized = null;
	var encryptedPMS = null;
	if(typeof(args) !== "undefined"){
		if(typeof(args.serialized) !== "undefined"){
			serialized = args.serialized;
		}
		if(typeof(args.encryptedPMS) !== "undefined"){
			encryptedPMS = args.encryptedPMS;
		}

	}
	this.typename = "TLSClientKeyExchange";
	if (serialized){
		 print ('Not implemented instantiation of client key exchange with serialization; this is a client-only TLS implementation');
	}
	else {
	    if (encryptedPMS){
            this.encryptedPMS = encryptedPMS;
	    }
        //#Note that the encpms is preceded by its 2-byte length
        this.serialized = [].concat(bi2ba(this.encryptedPMS.length, {'fixed':2}), this.encryptedPMS);
        TLSHandshake.prototype.__init__.call(this, null, h_cke);
        TLSHandshake.prototype.serialize.call(this);
	}
};


function TLSChangeCipherSpec(){}
TLSChangeCipherSpec.prototype.__init__ = function(args){
	var serialized = null;
	if (typeof(args) !== "undefined"){
		if (typeof(args.serialized) !== "undefined"){
			serialized = args.serialized;
		}
	}
	if (serialized){
      	this.serialized = serialized;
        assert(this.serialized[0] == 0x01, 'Invalid change cipher spec received');
        this.discarded = this.serialized.slice(1);
        this.serialized = this.serialized[0];
	}
	else {
		this.serialized = [0x01];
	}
	this.typename = "TLSChangeCipherSpec";
};



TLSFinished.prototype = new TLSHandshake();
TLSFinished.prototype.constructor=TLSFinished;
TLSFinished.prototype.parent = TLSHandshake.prototype;
function TLSFinished(){}
TLSFinished.prototype.__init__ = function(args){
	var serialized = null;
	var verify_data = null;
	this.typename = "TLSFinished";
	if (typeof(args) !== "undefined"){
		if (typeof(args.serialized) !== "undefined"){
			serialized = args.serialized;
		}
		if (typeof(args.verify_data) !== "undefined"){
			verify_data = args.verify_data;
		}
	}
	if (serialized){
		TLSHandshake.prototype.__init__.call(this, serialized, h_fin);
		this.validity = null;
		this.verify_data = this.serialized.slice(4);
	}
	else{
		this.serialized = verify_data;
		TLSHandshake.prototype.__init__.call(this, null, h_fin);
		TLSHandshake.prototype.serialize.call(this);
	}
};
TLSFinished.prototype.decrypt_verify_data = function(conn){
    this.encrypted = this.verify_data; //#the encrypted form is kept for later processing
	var rv = conn.dtvm(this.verify_data, hs);
	this.validity = rv[0];
	this.verify_data = rv[1];
};



function TLSAppData(){}
TLSAppData.prototype.__init__ = function(serialized, args){
	var encrypted = false;
	if (typeof(args) !== "undefined"){
		if (typeof(args.encrypted) !== "undefined"){
			encrypted = args.encrypted;
		}
	}
   	/*#App Data is 'transparent' to the Record protocol layer
    #(I borrow this slighly, ahem, opaque language from the 
    #RFC Section 10). This means that there is no notion of 
    #'length of an app data message'. Nor is there any meaning
    #to the concept of 'serialization' in this context, since 
    #there is no structure. However the terminology is kept
    #the same as other record types, for consistency.*/
    this.serialized = serialized;
    this.discarded='';
    this.typename = "TLSAppData";
};
TLSAppData.prototype.decrypt_app_data = function(conn){
	this.serialized = conn.dtvm(this.serialized, appd);
};



function TLSAlert(){}
TLSAlert.prototype.__init__ = function(args){
	var serialized = args.serialized;
	if (serialized){
		this.serialized = serialized;
        this.discarded='';
        this.typename = "TLSAlert";
	}
	else{
        throw ("Alert creation not implemented");
	}
};




function TLSConnectionState(){
	/*Note that this implementation of connection
    state uses the pre-computed expanded keys rather
    than generating the secrets within it. A corollary
    of this is that there is no need for this encapsulation
    for the unencrypted portion of the TLS connection, and
    so this object is only initiated once TLSNotary key
    expansion is performed (after negotiation with auditor).
    Mac failures should be treated as fatal in TLS, but
    for specific cases in TLSNotary, the mac check is delayed,
    hence mac failure is returned as False rather than raising
    an exception.*/
}
TLSConnectionState.prototype.__init__ = function(cipher_suite, expanded_keys, is_client, tlsver){
	/*Provide the cipher suite as defined in the global
	cipher suite list.
	Currently only AES-CBC and RC4 cipher suites are
	supported.
	The format of expanded_keys must be as required
	by the specified cipher suite.
	If mac failures occur they will be flagged but
	decrypted result is still made available.*/
	this.tlsver = tlsver; //either TLS1.0 or 1.1
	var version_found = false;
	for (var i=0; i<tls_versions.length; i++){
		if (tls_versions[i].toString() === this.tlsver.toString()){
			version_found = true;
			break;
		}
	}
	assert(version_found, "Unrecognised or invalid TLS version");
	this.cipher_suite = cipher_suite;
	if (is_client) {
		this.end = 'client';
	}
	else {
		this.end = 'server';
	}
	if (cipher_suite === 4){
		this.mac_algo = 'md5';
	}
	else {
		this.mac_algo = 'sha1';
	}
	if (this.mac_algo === 'md5'){
		this.hash_len = md5_hash_len;
	}
	else {
		this.hash_len = sha1_hash_len;
	}	
	 //set appropriate secrets for state
	this.client_mac_key = expanded_keys[0];
	this.server_mac_key = expanded_keys[1];
	this.client_enc_key = expanded_keys[2];
	this.server_enc_key = expanded_keys[3];
	this.clientIV = expanded_keys[4];
	this.serverIV = expanded_keys[5];
	if (this.end == 'client'){
		this.mac_key = this.client_mac_key;
		this.enc_key = this.client_enc_key;
		this.IV = this.clientIV;
	}
	else{
		this.mac_key = this.server_mac_key;
		this.enc_key = this.server_enc_key;
		this.IV = this.serverIV;
	}
	this.seq_no = 0;
};
TLSConnectionState.prototype.build_record_mac = function(cleartext, record_type){
	var seq_no_bytes = bi2ba(this.seq_no, {'fixed':8});
	assert(this.mac_key, "Failed to build mac; mac key is missing");
	var fragment_len = bi2ba(cleartext.length, {'fixed':2});
	var record_mac = hmac(this.mac_key, [].concat(seq_no_bytes, record_type, this.tlsver, fragment_len, cleartext), this.mac_algo);
	return record_mac;
};
TLSConnectionState.prototype.mte = function(cleartext, rec_type){
	if ([4,5].indexOf(this.cipher_suite) > -1){
		return this.rc4_me(cleartext,rec_type);
	}
	else {
		return this.aes_cbc_mpe(cleartext,rec_type);
	}
};
TLSConnectionState.prototype.dtvm = function(cleartext, rec_type, return_mac){
	//'''Decrypt then verify mac'''
	if (typeof(return_mac) === "undefined"){
		return_mac = false;
	}
	var retval;
	if ([4,5].indexOf(this.cipher_suite) > -1){
		retval = this.rc4_dm(cleartext,rec_type, return_mac);
		return retval;
	}
	else {
		retval = this.aes_cbc_dum(cleartext, rec_type, return_mac);
		return retval;
	}
};
TLSConnectionState.prototype.verify_mac = function(cleartext, rec_type, args){
	var return_mac = false;
	if(typeof(args) !== "undefined"){
		if(typeof(args.return_mac) !== "undefined"){
			return_mac = args.return_mac;
		}
	}
	var len_wo_mac = cleartext.length-this.hash_len; //length without mac
	var received_mac = cleartext.slice(len_wo_mac);
	var check_mac = this.build_record_mac(cleartext.slice(0, len_wo_mac), rec_type);
	this.seq_no += 1;
	var validity = false;
	if (return_mac){
		validity = (received_mac.toString() === check_mac.toString());
		return [validity, cleartext.slice(0, len_wo_mac), received_mac];
	}
	else {
		validity = (received_mac.toString() === check_mac.toString());
		return [validity, cleartext.slice(0, len_wo_mac)];
	}
};
TLSConnectionState.prototype.rc4_me = function(cleartext, rec_type){
	//#mac
	cleartext = [].concat(cleartext, this.build_record_mac(cleartext,rec_type));
	//#encrypt
	//#note: for RC4, the 'IV' is None at the start, 
	//#which tells the RC4 to initialize state
	var rv = rc4_crypt(cleartext, this.enc_key, this.IV);
	var ciphertext = rv[0];
	this.IV = rv[1];
	this.seq_no += 1;   
	return ciphertext; 
};
TLSConnectionState.prototype.rc4_dm = function(ciphertext, rec_type, args){
	var return_mac = args.return_mac;
	//#decrypt
	var rv = rc4_crypt(ciphertext, this.enc_key, this.IV);
	var plaintext = rv[0];
	this.IV = rv[1];
	//#mac check
	return this.verify_mac(plaintext, rec_type, return_mac);
};
TLSConnectionState.prototype.aes_cbc_mpe = function(cleartext, rec_type){
	//#mac
	cleartext = [].concat(cleartext, this.build_record_mac(cleartext,rec_type));
	//#pad
	var padded_cleartext = [].concat(cleartext, get_cbc_padding(cleartext.length));
	var ciphertext = aes_encrypt(padded_cleartext, this.enc_key, this.IV);
	if (this.tlsver.toString() === tls_ver_1_0.toString()){
		this.IV = ciphertext.slice(ciphertext.length-aes_block_size);
	}
	else if (this.tlsver.toString() === tls_ver_1_1.toString()){
		//#the per-record IV is now sent as the start of the fragment
		ciphertext = [].concat(this.IV, ciphertext);
		this.IV = getRandom(aes_block_size, window); //#use a new, random IV for each record
	}
	this.seq_no += 1;
	return ciphertext;
};
TLSConnectionState.prototype.aes_cbc_dum = function(ciphertext, rec_type, return_mac){
	if(typeof(return_mac) === "undefined"){
		return_mac = false;
	}
	//#decrypt
	if (this.tlsver.toString() === tls_ver_1_1.toString()){
		this.IV = ciphertext.slice(0, aes_block_size);
		ciphertext = ciphertext.slice(aes_block_size);
	}
	//#else self.IV already stores the correct IV
	var decrypted = aes_decrypt(ciphertext, this.enc_key, this.IV); 
	if (this.tlsver.toString() === tls_ver_1_0.toString()){
		this.IV = ciphertext.slice(ciphertext.length-aes_block_size);
	}
	//#unpad
	var plaintext = cbc_unpad(decrypted);
	//#mac check
	var retval = this.verify_mac(plaintext, rec_type, {'return_mac':return_mac});
	return retval;
};





function tls_sender(sckt, msg, rec_type, tlsver, conn){
    /*'''Wrap a message in a TLS Record before sending
    If conn argument provided, encrypt the payload
    before sending'''*/
    if (typeof(conn) !== "undefined" && conn !== null){
		msg = conn.mte(msg,rec_type);
	}
    var rec = new TLSRecord();
    rec.__init__(rec_type, msg, tlsver);
    return sckt.send(rec.serialized);
}

function recv_socket(sckt, is_handshake){
	return sckt.recv(sckt, is_handshake);	
}



function TLSNClientSession(){}
TLSNClientSession.prototype.__init__ = function(args){
	if (typeof(args)!=='undefined'){
		var server = args.server;
		var port = args.port;
		var ccs = args.ccs;
		var tlsver = args.tlsver;
		if (typeof(server)==='undefined') server = null;
		if (typeof(port)==='undefined') port = 443;
		if (typeof(ccs)==='undefined') ccs = null;
		if (typeof(tlsver)==='undefined') tlsver = null;
	}
	
    this.server_name = server;
    this.ssl_port = port;
    this.sckt = null;
    this.initial_tlsver = tlsver;
    //#current TLS version may be downgraded
    this.tlsver = tlsver;
    this.n_auditee_entropy = 12;
    this.n_auditor_entropy = 9;
    this.auditor_secret = null;
    this.auditee_secret = null;
    this.auditor_padding_secret = null;
    this.auditee_padding_secret = null;
    this.pms1 = null; //#auditee's
    this.pms2 = null; //#auditor's
    this.enc_first_half_pms = null;
    this.enc_second_half_pms = null;
    this.enc_pms = null;
    //#client hello, server hello, certificate, server hello done,
    //#client key exchange, change cipher spec, finished
    this.handshake_messages = [null, null, null, null, null, null, null];
    this.handshake_hash_sha = null;
    this.handshake_hash_md5 = null;
    this.p_auditor = null;
    this.p_auditee = null;
    this.master_secret_half_auditor = null;
    this.master_secret_half_auditee = null;
    this.p_master_secret_auditor = null;
    this.p_master_secret_auditee = null;
    this.server_mac_key = null;
    this.client_mac_key = null;
    this.server_enc_key = null;
    this.client_enc_key = null;
    this.serverIV = null;
    this.clientIV = null;
    this.server_certificate = null;
    this.server_modulus = null;
    this.server_exponent = 65537;
    this.server_mod_length = null;

    //#array of ciphertexts from each SSL record
    this.server_response_app_data=[];
    
    //#unexpected app data is defined as that received after 
    //#server finished, but before client request. This will
    //#be decrypted, but not included in plaintext result.
    this.unexpected_server_app_data_count = 0;
    this.unexpected_server_app_data_raw = [];
    
    /*#the HMAC required to construct the verify data
    #for the server Finished record
    self.verify_hmac_for_server_finished = None
    
    #for certain testing cases we want to limit the
    #choice of cipher suite to 1, otherwise we use
    #the globally defined standard 4: */
    if (ccs){
		this.offered_cipher_suites = [];
		var cs = {};
		cs[ccs] = get_cs(ccs);
    	this.offered_cipher_suites.push(cs);
    }
    else {
    	this.offered_cipher_suites = tlsn_cipher_suites;
    }
    this.chosen_cipher_suite = ccs;
};

TLSNClientSession.prototype.dump = function(){
//XXX implement this
};

TLSNClientSession.prototype.send_client_hello = function(){	
	var offered_cs_keys = [];
	for (var i=0; i < this.offered_cipher_suites.length; i++){
		var cs = Object.keys(this.offered_cipher_suites[i])[0];
		//cast cs to int, otherwise we'll have strings
		offered_cs_keys.push(parseInt(cs));
	}
	this.client_hello = new TLSClientHello();
	this.client_hello.__init__({'cipher_suites':offered_cs_keys, 'tlsver':this.tlsver});
	this.handshake_messages[0]= this.client_hello.serialized;
	
	tls_sender(this.sckt, this.handshake_messages[0], hs, this.tlsver, null);
}


TLSNClientSession.prototype.get_server_hello = function(){
			/*      #the handshake messages: server hello, certificate, server hello done
        #may be packed in arbitrary groupings into the TLS records, since
        #they are all the same record type (Handshake)            */
        
	var handshake_objects = [];
	var sckt = this.sckt;
	return new Promise(function(resolve, reject) {
		var loop = function(resolve, reject){      
			console.log('get_server_hello next iteration');
			sckt.recv(true).then(function(rspns){
				console.log('returned from sckt.recv with length', rspns.length);
				var rv = tls_record_decoder(rspns);
				var records = rv[0];
				var remaining = rv[1];
				assert(remaining.length === 0, "Server sent spurious non-TLS response");
				if (records.length === 1){
					if(records[0].content_type === alrt){
						reject('Server sent alert ' + records[0].fragment.toString());
						return;
					}
				}
				for(var i=0; i < records.length; i++){
					var decoded = tls_record_fragment_decoder(hs, records[i].fragment);
					handshake_objects = [].concat(handshake_objects, decoded);
				}
				if (handshake_objects.length < 3){
					console.log('get_server_hello handshake_objects.length < 3');
					loop(resolve, reject);
					return;
				}
				//else
				resolve(handshake_objects);
			});
		};
		loop(resolve, reject);
	});
}   
        
    
TLSNClientSession.prototype.process_server_hello = function(handshake_objects){

		var handshake_types=[];
		for (i=0; i<handshake_objects.length; i++){
			var handshake_type = handshake_objects[i].handshake_type;
			handshake_types.push(handshake_type);
		}
		assert(handshake_types.indexOf(h_sh) >= 0 && handshake_types.indexOf(h_cert) >= 0 &&
			handshake_types.indexOf(h_shd) >= 0, 
		   "Server failed to send server hello, certificate, server hello done");
		this.server_hello = handshake_objects[0];
		this.server_certificate = handshake_objects[1];
		this.server_hello_done = handshake_objects[2];
		
		this.handshake_messages[1] = handshake_objects[0].serialized;
		this.handshake_messages[2] = handshake_objects[1].serialized;
		this.handshake_messages[3] = handshake_objects[2].serialized;

		this.client_random = this.client_hello.client_random;
		this.server_random = this.server_hello.server_random;
		this.chosen_cipher_suite = this.server_hello.cipher_suite;
		
		if (this.server_hello.tlsver.toString() !== this.tlsver.toString()){
			if ((this.server_hello.tlsver.toString() === [0x03,0x01].toString()) &&
				(this.tlsver.toString() === [0x03,0x02].toString())){
				/*#server requested downgrade
				#note that this can only happen *before* a TLSConnectionState object is
				#initialised, so the tlsversion used in that object will be synchronised.
				#TODO: error checking to make sure this is the case.*/
				this.tlsver = [0x03,0x01];
			}
			else{
				throw("Failed to negotiate valid TLS version with server");
			}
		}
		//#for 'full' sessions, we can immediately precompute everything except
		//#for finished, including the handshake hashes used to calc the Finished
		if (this.enc_pms){
			this.client_key_exchange = new TLSClientKeyExchange();
			this.client_key_exchange.__init__({'serialized':null, 'encryptedPMS':this.enc_pms});
			this.change_cipher_spec = new TLSChangeCipherSpec();
			this.change_cipher_spec.__init__();
			this.handshake_messages[4] = this.client_key_exchange.serialized;
			this.handshake_messages[5] = this.change_cipher_spec.serialized;
			this.set_handshake_hashes();
		}
};

TLSNClientSession.prototype.get_verify_data_for_finished = function(args){
	var sha_verify = null;
	var md5_verify = null;
	var half = 1;
	var provided_p_value = null;
	var is_for_client = true;
	if(typeof(args.sha_verify) !== "undefined"){
		sha_verify = args.sha_verify;
	}
	if(typeof(args.md5_verify) !== "undefined"){
		md5_verify = args.md5_verify;
	}
	if(typeof(args.half) !== "undefined"){
		half = args.half;
	}
	if(typeof(args.provided_p_value) !== "undefined"){
		provided_p_value = args.provided_p_value;
	}
	if(typeof(args.is_for_client) !== "undefined"){
		is_for_client = args.is_for_client;
	}

	if (! (sha_verify && md5_verify)){
		sha_verify = this.handshake_hash_sha;
		md5_verify = this.handshake_hash_md5;
	}
		
	if (!provided_p_value){
		//#we calculate the verify data from the raw handshake messages
		if (this.handshake_messages.slice(0,6).indexOf(null) > -1){
			print('Here are the handshake messages: ' + this.handshake_messages.slice(0,6).toString());
			throw('Handshake data was not complete, could not calculate verify data');
		}
		var label;
		if (is_for_client){
			label = str2ba('client finished');
		}
		else {
			label = str2ba('server finished');
		}
		var seed = [].concat(md5_verify, sha_verify);
		var ms = [].concat(this.master_secret_half_auditor, this.master_secret_half_auditee);
		//#we don't store the verify data locally, just return it
		return tls_10_prf([].concat(label,seed), {'req_bytes':12,'full_secret':ms})[2];
	}
	//#we calculate based on provided hmac by the other party
	var verify_hmac = this.get_verify_hmac({'sha_verify':sha_verify, 'md5_verify':md5_verify,
    	'half':half, 'is_for_client':is_for_client});
    return xor(provided_p_value.slice(0,12), verify_hmac);
};

TLSNClientSession.prototype.set_handshake_hashes = function(args){
	var server = false;
	if (typeof(args) !== "undefined"){
		if (typeof(args.server) !== "undefined"){
			server = args.server;
		}
	}
      /*  '''An obscure but important detail: the hashes used
    for the server Finished use the *unencrypted* client finished;
    in the current model this is automatic since the TLSFinished objects
    store the verify data unencrypted.'''*/
    var handshake_data = [];
    for(var i=0; i<5; i++){
		handshake_data = handshake_data.concat(this.handshake_messages[i]);
	}
    if (server){
        handshake_data = [].concat(handshake_data, this.handshake_messages[6]);// #client finished
    }
    var handshake_hash_sha = sha1(handshake_data);
    var handshake_hash_md5 = md5(handshake_data);
    if (! server){
        this.handshake_hash_sha = handshake_hash_sha;
        this.handshake_hash_md5 = handshake_hash_md5;
    }
    return [handshake_hash_sha, handshake_hash_md5];
};

TLSNClientSession.prototype.send_client_finished = function(provided_p_value){
       /* '''Creates the client finished handshake message without
	    access to the master secret, but on the P-hash data provided
	    by the auditor. Then receives the server ccs and finished.'''*/
	var verify_data = this.get_verify_data_for_finished({'provided_p_value':provided_p_value, 'half':2});
	this.client_finished = new TLSFinished();
	this.client_finished.__init__({'serialized':null, 'verify_data':verify_data});
	this.handshake_messages[6] = this.client_finished.serialized;
	//#Note that the three messages cannot be packed into one record; 
	//#change cipher spec is *not* a handshake message
	tls_sender(this.sckt, this.handshake_messages[4], hs, this.tlsver);
	tls_sender(this.sckt, this.handshake_messages[5], chcis, this.tlsver);
	tls_sender(this.sckt, this.handshake_messages[6], hs, this.tlsver, this.client_connection_state);
}


TLSNClientSession.prototype.get_server_finished = function(){
	//keep recv'ing more data until we get enough records
	var records = [];
	var sckt = this.sckt;
	return new Promise(function(resolve, reject) {
		var loop = function(resolve, reject){      
			console.log('get_server_finished next iteration');
			sckt.recv(true).then(function(rspns){
				console.log('returned from sckt.recv');
				var rv = tls_record_decoder(rspns);
				var x = rv[0];
				var remaining = rv[1];
				assert(remaining.length === 0, "Server sent spurious non-TLS response");
				records = [].concat(records, x);
				if (records.length < 2){
					console.log('get_server_finished records.length < 2');
					loop(resolve, reject);
					return;
				}
				//else
				resolve(records);
			});
		};
		loop(resolve, reject);
	});
}

		  
	
TLSNClientSession.prototype.process_server_finished = function(records){
	var i,x;
     /*   #this strange-looking 'filtering' approach is based on observation
    #in practice of CCS being repeated (and possible also Finished, although I don't remember)*/
    var sccs = null;
    for(i=0; i<records.length; i++){
		x=records[i];
		if(x.content_type === chcis){
			sccs = x;
			break;
		}
	}
    this.server_ccs = tls_record_fragment_decoder(chcis, sccs.fragment)[0];
    var sf = null;
    for(i=0; i<records.length; i++){
		x=records[i];
		if(x.content_type == hs){
			sf = x;
			break;
		}
	}
    this.server_finished = tls_record_fragment_decoder(hs, sf.fragment,
        {'conn':this.server_connection_state, 'ignore_mac':true})[0];
    assert(this.server_finished.handshake_type === h_fin, "Server failed to send Finished");
    //#store the IV immediately after decrypting Finished; this will be needed
    //#by auditor in order to replay the decryption
    this.IV_after_finished = this.server_connection_state.IV;

    if (records.length > 2){
        //#we received extra records; are they app data? if not we have bigger problems..
        for(i=0; i < records.length; i++){
			x = records[i];
            if ([chcis,hs].indexOf(x.content_type) > -1){
            	continue;
         	}
            if (x.content_type !== appd){
                //#this is too much; if it's an Alert or something, we give up.
                throw("Received unexpected TLS record before client request.");
			}
            //#store any app data records, in sequence, prior to processing all app data.
            this.server_response_app_data = [].concat(this.server_response_app_data, tls_record_fragment_decoder(appd,x.fragment));
            //#We have to store the raw form of these unexpected app data records, since they will
            //#be needed by auditor.
            this.unexpected_server_app_data_raw = [].concat(this.unexpected_server_app_data_raw, x.serialized);// #the full record serialization (otw bytes)
            this.unexpected_server_app_data_count += 1; //#note: each appd record contains ONE appd message
        }
	}
};

TLSNClientSession.prototype.complete_handshake = function(rsapms2){
       /* '''Called from prepare_pms(). For auditee only,
    who passes the second half of the encrypted
    PMS product (see TLSNotary.pdf under documentation).'''*/
    this.set_auditee_secret();
    this.set_master_secret_half(); //#default values means full MS created
    this.do_key_expansion();
    this.enc_second_half_pms = rsapms2;
    this.set_enc_first_half_pms();
    this.set_encrypted_pms();
    this.client_key_exchange = new TLSClientKeyExchange();
    this.client_key_exchange.__init__({'encryptedPMS':this.enc_pms});
    this.handshake_messages[4] = this.client_key_exchange.serialized;
    this.change_cipher_spec = new TLSChangeCipherSpec();
    this.change_cipher_spec.__init__();
    this.handshake_messages[5] = this.change_cipher_spec.serialized;
    this.set_handshake_hashes();

    var client_verify_data = this.get_verify_data_for_finished({'sha_verify':this.handshake_hash_sha,
        'md5_verify':this.handshake_hash_md5, 'half':1});
    
    this.client_finished = new TLSFinished();
    this.client_finished.__init__({'verify_data':client_verify_data});
    this.handshake_messages[6] = this.client_finished.serialized;
    //#Note that the three messages cannot be packed into one record; 
    //#change cipher spec is *not* a handshake message
    tls_sender(this.sckt, this.handshake_messages[4], hs, this.tlsver)
    tls_sender(this.sckt, this.handshake_messages[5], chcis, this.tlsver); 
	tls_sender(this.sckt, this.handshake_messages[6], hs, this.tlsver, this.client_connection_state);
	return this.sckt.recv(true);
}
    


TLSNClientSession.prototype.set_encrypted_pms = function(){
    assert(this.enc_first_half_pms && this.enc_second_half_pms && this.server_modulus,
    	'failed to set enc_pms, first half was: ' + this.enc_first_half_pms.toString() +
        ' second half was: ' + this.enc_second_half_pms.toString() + ' modulus was: ' +
        this.server_modulus.toString());
    var bigint_pms1 = new BigInteger(ba2hex(this.enc_first_half_pms), 16);
	var bigint_pms2 = new BigInteger(ba2hex(this.enc_second_half_pms), 16);
	var bigint_mod = new BigInteger(ba2hex(this.server_modulus), 16);
    var bigint_pms =  bigint_pms1.multiply(bigint_pms2).mod(bigint_mod);
    var resulthex = bigint_pms.toString(16);
	this.enc_pms = hex2ba(resulthex);
    return this.enc_pms;
};

TLSNClientSession.prototype.set_enc_first_half_pms = function(){
    assert(this.server_modulus && !this.enc_first_half_pms);
    var ones_length = 23;
    var trailing_zeroes = [];
    var i;
    for (i=0; i < (24-2-this.n_auditee_entropy); ++i){
		trailing_zeroes.push(0);
	} 
    this.pms1 = [].concat(this.initial_tlsver, this.auditee_secret, trailing_zeroes);
	var ones = [];
	for (i=0; i<ones_length; i++){
		ones.push(1);
	}
	var tailzeroes = [];
	for (i=0; i<23; i++){
		tailzeroes.push(0);
	}
	var base = [].concat(0x02, ones, this.auditee_padding_secret, 0x00, this.pms1, tailzeroes, 0x01);
	var bigint_base = new BigInteger(ba2hex(base), 16);
	var bigint_mod = new BigInteger(ba2hex(this.server_modulus), 16);
	var bigint_exp = new BigInteger(ba2hex(bi2ba(this.server_exponent)), 16);
	var bigint_result = bigint_base.modPow(bigint_exp, bigint_mod);
	var resultba = hex2ba(bigint_result.toString(16));
	var padding_len = this.server_modulus.length - resultba.length;
	for(i=0; i < padding_len; i++){ //zero-pad 
		resultba = [].concat(0x00, resultba);
	}
	this.enc_first_half_pms = resultba;
	assert (this.enc_first_half_pms.length === this.server_modulus.length, "this.enc_first_half_pms.length === tlsn_session.server_mod_length");
};

TLSNClientSession.prototype.set_auditee_secret = function(){
    /*'''Sets up the auditee's half of the preparatory
    secret material to create the master secret. Note
    that according to the RFC, the tls version prepended to the
    premaster secret must be that used in the client hello message,
    not the negotiated/downgraded version set by the server hello. 
    See variable tlsver_ch.'''*/
    var tlsver_ch = this.initial_tlsver;
    var cr = this.client_random;
    var sr = this.server_random;
    assert(cr && sr,"one of client or server random not set");
    if (!this.auditee_secret){
        this.auditee_secret = getRandom(this.n_auditee_entropy, window);
        //this.auditee_secret = [1,2,3,4,5,6,7,8,9,10,11,12];
    }
    if (!this.auditee_padding_secret){
        this.auditee_padding_secret = getRandom(15, window);
        //this.auditee_padding_secret = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    }
    var label = str2ba('master secret');
    var seed = [].concat(cr,sr);
    var trailing_zeroes = [];
    for (var i=0; i < (24-2-this.n_auditee_entropy); ++i){
		trailing_zeroes.push(0);
	}
    this.pms1 = [].concat(tlsver_ch, this.auditee_secret, trailing_zeroes);
    this.p_auditee = tls_10_prf([].concat(label, seed),{'first_half':this.pms1})[0];
    //#encrypted PMS has already been calculated before the audit began
    return this.p_auditee;
};

//-------------------NOT IN USE BY THE AUDITEE---------------
TLSNClientSession.prototype.set_enc_second_half_pms = function(){
    assert(this.server_modulus);
    var ones_length = 103+ba2int(this.server_mod_length)-256;
    var trailing_zeroes = [];
    for (var i=0; 24-this.n_auditor_entropy-1; ++i){
		trailing_zeroes.push(0);
	}
    this.pms2 = [].concat(this.auditor_secret, trailing_zeroes, 0x01);
///XXX JS mod exp
    this.enc_second_half_pms = pow( ba2int('\x01'+('\x01'*(ones_length))+
		this.auditor_padding_secret+ ('\x00'*25)+this.pms2), this.server_exponent,
		this.server_modulus );
};

TLSNClientSession.prototype.set_auditor_secret = function(){
    /*'''Sets up the auditor's half of the preparatory
    secret material to create the master secret, and
    the encrypted premaster secret.
    'secret' should be a bytearray of length n_auditor_entropy'''*/
    var cr = this.client_random;
    var sr = this.server_random;
    assert(cr && sr, "one of client or server random not set");
    if (!this.auditor_secret){
        this.auditor_secret = getRandom(this.n_auditor_entropy, window);
        //this.auditor_secret = [1,2,3,4,5,6,7,8,9];
    }
    if (!this.auditor_padding_secret){
        this.auditor_padding_secret = getRandom(15, window);
        //this.auditor_padding_secret = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    }
    var label = str2ba('master secret');
    var seed = [].concat(cr,sr);
    var trailing_zeroes = [];
    for (var i=0; i < (24-this.n_auditor_entropy-1); ++i){
		trailing_zeroes.push(0);
	}
    this.pms2 = [].concat(this.auditor_secret, trailing_zeroes, 0x01);
    this.p_auditor = tls_10_prf([].concat(label,seed), {'second_half':this.pms2})[1];
    return this.p_auditor;
};

TLSNClientSession.prototype.set_master_secret_half = function(args){
	var half = 1;
	var provided_p_value = null;
	if (typeof(args) !== "undefined"){
		if (typeof(args.half) !== "undefined"){
			half = args.half;
		}
		if (typeof(args.provided_p_value) !== "undefined"){
			provided_p_value = args.provided_p_value;
		}
	}
    //#non provision of p value means we use the existing p
    //#values to calculate the whole MS
    if (!provided_p_value){
        this.master_secret_half_auditor = xor(this.p_auditee.slice(0,24), this.p_auditor.slice(0,24));
        this.master_secret_half_auditee = xor(this.p_auditee.slice(24), this.p_auditor.slice(24));
        return [].concat(this.master_secret_half_auditor, this.master_secret_half_auditee);
    }
    assert([1,2].indexOf(half) > -1, "Must provide half argument as 1 or 2");
    //#otherwise the p value must be enough to provide one half of MS
    assert(provided_p_value.length === 24, "Wrong length of P-hash value for half MS setting.");
    if (half === 1){
        this.master_secret_half_auditor = xor(this.p_auditor.slice(0,24), provided_p_value);
        return this.master_secret_half_auditor;
    }
    else{
        this.master_secret_half_auditee = xor(this.p_auditee.slice(24), provided_p_value);
        return this.master_secret_half_auditee;
    }
};


//------------------Not in use by the auditee. Can be removed
TLSNClientSession.prototype.get_p_value_ms = function(ctrprty){
       /* '''Provide a list of keys that you want to 'garbageize' so as to hide
        that key from the counterparty, in the array 'garbage', each number is
        an index to that key in the cipher_suites dict        
        '''*/
	var garbage = args.garbage;
    assert(this.server_random && this.client_random && this.chosen_cipher_suite, 
    	"server random, client random or cipher suite not set.");
    var label = str2ba('key expansion');
    var seed = [].concat(this.server_random, this.client_random);
    var chosen_cs = get_cs(this.chosen_cipher_suite);
    var expkeys_len = chosn_cs[chosen_cs.length-1];
    var i;
    if (ctrprty == 'auditor'){
        this.p_master_secret_auditor = tls_10_prf([].concat(label, seed), 
        	{'req_bytes':expkeys_len, 'first_half':this.master_secret_half_auditor})[0];
    }
    else{
        this.p_master_secret_auditee = tls_10_prf([].concat(label, seed),
        	{'req_bytes':expkeys_len, 'second_half':this.master_secret_half_auditee})[1];
    }

    var tmp;
    if (ctrprty=='auditor'){
    	tmp = this.p_master_secret_auditor;
	}
    else {
    	tmp = this.p_master_secret_auditee;
	}
	for(var j=0; j < garbage.length; j++){
		var k = garbage[j];
    	var start = 0;
        if (k==1){
            start = 0;
		}
        else{
        	for(i=1; i<k; ++i){
        		start += get_cs(this.chosen_cipher_suite)[i];
			}
		}
        var end = 0;
        for(i=1; i<k+1; ++i){
			end += get_cs(this.chosen_cipher_suite)[i];
		}
        var tmp2 = [].concat(tmp.slice(0,start), getRandom(end-start, window), tmp.slice(end));
        tmp = tmp2;
    }
    return tmp;
};

TLSNClientSession.prototype.do_key_expansion = function(){
        /*'''A note about partial expansions:
        Often we will have sufficient information to extract particular
        keys, e.g. the client keys, but not others, e.g. the server keys.
        This should be handled by passing in garbage to fill out the relevant
        portions of the two master secret halves. TODO find a way to make this
        explicit so that querying the object will only give real keys.
        '''*/

    var cr = this.client_random;
    var sr = this.server_random;
    var cs = this.chosen_cipher_suite;
    assert(cr && sr && cs," need client and server random and cipher suite");
    var label = str2ba('key expansion');
    var seed = [].concat(sr, cr);
    //#for maximum flexibility, we will compute the sha1 or md5 hmac
    //#or the full keys, based on what secrets currently exist in this object
    var chosen_cs = get_cs(cs);
    var expkeys_len = chosen_cs[chosen_cs.length-1];
    if (this.master_secret_half_auditee){
        this.p_master_secret_auditee = tls_10_prf([].concat(label, seed),
        	{'req_bytes':expkeys_len, 'second_half':this.master_secret_half_auditee})[1];
    }
    if (this.master_secret_half_auditor){
        this.p_master_secret_auditor = tls_10_prf([].concat(label,seed),
        	{'req_bytes':expkeys_len, 'first_half':this.master_secret_half_auditor})[0];
    }

    var key_expansion;
    if (this.master_secret_half_auditee && this.master_secret_half_auditor){
        key_expansion = tls_10_prf([].concat(label, seed),
        	{'req_bytes':expkeys_len, 
        	'full_secret':[].concat(this.master_secret_half_auditor, this.master_secret_half_auditee)})[2];
    }
    else if(this.p_master_secret_auditee && this.p_master_secret_auditor){
        key_expansion = xor(this.p_master_secret_auditee, this.p_master_secret_auditor);
    }
    else{
        throw ('Cannot expand keys, insufficient data');
    }

    //#we have the raw key expansion, but want the keys. Use the data
    //#embedded in the cipherSuite dict to identify the boundaries.
    var key_accumulator = [];
    var ctr=0;
    var i;
    for(i=0; i<6; ++i){
        var keySize = get_cs(cs)[i+1];
        if (keySize === 0){
            key_accumulator.push(null);
        }
        else{
            key_accumulator.push(key_expansion.slice(ctr,ctr+keySize));
        }
        ctr += keySize;
    }

    this.client_mac_key = key_accumulator[0];
    this.server_mac_key = key_accumulator[1];
    this.client_enc_key = key_accumulator[2];
    this.server_enc_key = key_accumulator[3];
    this.clientIV = key_accumulator[4];
    this.serverIV = key_accumulator[5];
    /*#we now have sufficient information to initialise client and server
    #connection state. NOTE: Since this wipes/restarts the encryption 
    #connection state, a call to do_key_expansion automatically restarts
    #the session.*/
    this.client_connection_state = new TLSConnectionState();
    this.client_connection_state.__init__(cs, key_accumulator, true, this.tlsver);
    this.server_connection_state = new TLSConnectionState();
    this.server_connection_state.__init__(cs, key_accumulator, false, this.tlsver);
    var keys = [];
    for(i=0; i<key_accumulator.length; ++i){
    	if(key_accumulator[i] !== null){
			keys = [].concat(keys, key_accumulator[i]);
		}
    }
    return keys;
};

TLSNClientSession.prototype.get_verify_hmac = function(args){
	var sha_verify = args.sha_verify;
	var md5_verify = args.md5_verify;
	var half = args.half;
	var is_for_client = args.is_for_client;
    //'''returns only 12 bytes of hmac'''
    var label;
    if (is_for_client){
    	label = str2ba('client finished');
	}
    else {
    	label = str2ba('server finished');
	}
    var seed = [].concat(md5_verify, sha_verify);
    if (half==1){
        return tls_10_prf([].concat(label,seed),
        	{'req_bytes':12, 'first_half':this.master_secret_half_auditor})[0];
    }
    else{
        return tls_10_prf([].concat(label, seed),
        	{'req_bytes':12, 'second_half':this.master_secret_half_auditee})[1];
    }
};

TLSNClientSession.prototype.check_server_ccs_finished = function(provided_p_value){
	isdefined(provided_p_value);
    //#verify the verify data:
    var rv = this.set_handshake_hashes({'server':true});
    var sha_verify = rv[0];
    var md5_verify = rv[1];
    var verify_data_check = this.get_verify_data_for_finished(
    	{'sha_verify':sha_verify, 'md5_verify':md5_verify,
		'provided_p_value':provided_p_value, 'half':2, 'is_for_client':false});
    assert(this.server_finished.verify_data.toString() == verify_data_check.toString(),
           "Server Finished record verify data is not valid.");
    return true;
};

TLSNClientSession.prototype.build_request = function(cleartext){
    /*'''Constructs the raw bytes to send over TCP
    for a given client request. Implicitly the request
    will be less than 16kB and therefore only 1 SSL record.
    This can in principle be used more than once.'''*/
    this.tls_request = new TLSAppData();
    this.tls_request.__init__(cleartext);
    tls_sender(this.sckt, this.tls_request.serialized, appd, this.tlsver, this.client_connection_state);
};

TLSNClientSession.prototype.store_server_app_data_records = function(response){
    //#extract the ciphertext from the raw records as a list
    //#for maximum flexibility in decryption
    var rv = tls_record_decoder(response);
    var recs = rv[0];
    var remaining = rv[1];
    assert(remaining.length === 0, "Server sent spurious non-TLS data");
    for(var i=0; i<recs.length; i++){
		var rec = recs[i];
		var decoded = tls_record_fragment_decoder(rec.content_type, rec.fragment); 
        this.server_response_app_data = [].concat(this.server_response_app_data, decoded);
    }
    //#what has been stored is a list of TLSAppData objects in which
    //#the .serialized property is still encrypted.
};



TLSNClientSession.prototype.mac_check_server_finished = function(){
	/*
        #Note server connection state has been reset after do_key_expansion
        #(which was done to correct server mac key), so state is initialised
        #correctly).'''
        */
    var rv = this.server_connection_state.dtvm(this.server_finished.encrypted, hs);
	var validity = rv[0];
	var plaintext = rv[1];
	//#now sequence number and IV are correctly initialised for the app data
	return validity;
};

TLSNClientSession.prototype.process_server_app_data_records = function(){
   /*'''Using the encrypted records in self.server_response_ciphertexts, 
    containing the response from
    the server to a GET or POST request (the *first* request after
    the handshake), this function will process the response one record
    at a time. Each of these records is decrypted and reassembled
    into the plaintext form of the response. The plaintext is returned
    along with the number of record mac failures (more than zero means
    the response is unauthenticated/corrupted).
    '''*/

    assert(this.server_response_app_data.length > 0, 
    	"Could not process the server response, no ciphertext found.");
    var plaintexts = [];
    var bad_record_mac = 0;   

	for(var i=0; i<this.server_response_app_data.length; ++i){
    	var ciphertext = this.server_response_app_data[i];
    	var rt;
        if (ciphertext.typename === "TLSAppData"){
            rt = appd;
		}
        else if (ciphertext.typename === "TLSAlert"){
            rt = alrt;
		}
        else{
            throw ("Server response contained unexpected record type: ",
            	ciphertext.typename);
        }
        var validity, plaintext;
        var rv = this.server_connection_state.dtvm(ciphertext.serialized, rt);
        validity = rv[0];
        plaintext = rv[1];
        if (validity !== true){ 
            bad_record_mac += 1;
        }
        //#plaintext is only included if it's appdata not alerts, and if it's 
        //#not part of the ignored set (the set that was delivered pre-client-request)
        if (rt== appd && i>this.unexpected_server_app_data_count-1){
            plaintexts = [].concat(plaintexts, plaintext);
        }
	}
    return [plaintexts, bad_record_mac];
};



function get_cbc_padding(data_length){
	var req_padding = aes_block_size - data_length % aes_block_size;
	var padding = [];
	for (var i=0; i<req_padding; i++){
		padding.push(req_padding-1);
	}
    return padding;
}


function cbc_unpad(pt){
	 /*   '''Given binary string pt, return
    unpadded string, raise fatal exception
    if padding format is not valid'''
    */
    var pad_len = pt[pt.length-1];
    //#verify the padding
    var padding = pt.slice(pt.length-pad_len-1, pt.length-1);
    for (var i=0; i<padding.length; i++){
		if(padding[i] !== pad_len){
			throw ("Invalid CBC padding.");
		}
	}
    return pt.slice(0, pt.length-(pad_len+1));   	
}


function aes_encrypt(padded_cleartext, enc_key, IV){
	var ct = CryptoJS.enc.Hex.parse(ba2hex(padded_cleartext));
	var key = CryptoJS.enc.Hex.parse(ba2hex(enc_key));
	var iv = CryptoJS.enc.Hex.parse(ba2hex(IV));
	var enc_obj = CryptoJS.AES.encrypt(ct, key, {iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding});
	return wa2ba(enc_obj.ciphertext.words);
}


//decrypt but leave the cbc padding intact
function aes_decrypt(ciphertext, enc_key, IV){
	var ct = CryptoJS.enc.Hex.parse(ba2hex(ciphertext));
	var key = CryptoJS.enc.Hex.parse(ba2hex(enc_key));
	var iv = CryptoJS.enc.Hex.parse(ba2hex(IV));
	var cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: ct});
	var decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding}); 
	return wa2ba(decrypted.words);
}



function rc4_crypt(data, key, state){
	if (typeof(state) === 'undefined'){
		state = null;
	}
	  /*  """RC4 algorithm.
    Symmetric, so performs encryption and decryption
    'state', if passed, is a tuple of three values,
    box (a bytearray), x and y (integers), allowing
    restart of the algorithm from an intermediate point.
    This is necessary since stream ciphers
    in TLS use the final state of the cipher at the end
    of one record to initialise the next record (see RFC 2246)."""*/
    var x = 0, y = 0;
    var box = [];
    var t;
    var i;
    if (!state){
        for(i=0; i<256; i++){
			box[i]=i;
		}
        for(i=0; i<256; i++){	
            x = ((x + box[i] + key[i % key.length]) % 256);
            t = box[i];
            box[i] = box[x];
            box[x] = t;
        }
        x = y = 0;
    }
    else{
        box = state.slice(0, 256);
        x = state[256];
        y = state[257];
    }
        
    var out = [];
    for(i=0; i<data.length; i++){
    	var onebyte = data[i];
        x = (x + 1) % 256;
        y = ((y + box[x]) % 256);
        t = box[x];
        box[x] = box[y];
        box[y] = t;
        out.push( onebyte ^ box[(box[x] + box[y]) % 256] );
    }
    var out_state = [].concat(box, x, y);
    return [out, out_state];
}

function rc4_state_to_bytearray(state){
	var box = state[0];
	var x = state[1];
	var y = state[2];
	var box = [].concat(box, x,y);
	return box;
}




       
function tls_10_prf(seed, args){
    /*'''
    Calculates all or part of the pseudo random function PRF
    as defined in the TLS 1.0 RFC 2246 Section 5. If only first_half or
    second_half are provided, then the appropriate HMAC is returned
    as the first or second element of the returned tuple respectively.
    If both are provided, the full result of PRF is provided also in
    the third element of the returned tuple.
    For maximum clarity, variable names correspond to those used in the RFC.
    Notes:
    The caller should provide one or other but not both of first_half and
    second_half - the alternative is to provide full_secret. This is because
    the algorithm for splitting into two halves as described in the RFC,
    which varies depending on whether the secret length is odd or even,
    cannot be correctly deduced from two halves.
    '''*/
    var x;
    var i;
    var req_bytes = args.req_bytes;
    var first_half = args.first_half;
    var second_half = args.second_half;
    var full_secret = args.full_secret;
	if (typeof(req_bytes)==='undefined') req_bytes = 48;
	if (typeof(first_half)==='undefined') first_half = null;
	if (typeof(second_half)==='undefined') second_half = null;
	if (typeof(full_secret)==='undefined') full_secret = null;
    //#sanity checks, (see choices of how to provide secrets under 'Notes' above)
	if (!first_half && !second_half && !full_secret){
        throw("Error in TLSPRF: at least one half of the secret is required.");
	}
    if ((full_secret && first_half) || (full_secret && second_half)){
        throw("Error in TLSPRF: both full and half secrets should not be provided.");
	}
    if (first_half && second_half){
        throw("Error in TLSPRF: please provide the secret in the parameter full_secret.");
	}    
    var P_MD5 = null;
    var P_SHA_1 = null;
    var PRF = null;

    //split the secret into two halves if necessary
    if (full_secret){
        var L_S = full_secret.length;
        var L_S1, L_S2;
        L_S1 = L_S2 = Math.ceil(L_S/2);
        first_half = full_secret.slice(0, L_S1);
        second_half = full_secret.slice(L_S2);
	}

    /*#To calculate P_MD5, we need at most floor(req_bytes/md5_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of md5_hash_len(16), we will use
    #0 bytes of the final iteration, otherwise we will use 1-15 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.*/
    var A;
    if (first_half){
        A=[hmac(first_half,seed,'md5')];
        for(i=1; i<Math.floor(req_bytes/md5_hash_len)+1; i++){
            A.push(hmac(first_half, A[A.length-1],'md5'));
        }

        var md5_P_hash = [];
        for(i=0; i<A.length; i++){
        	x = A[i];
            md5_P_hash = [].concat(md5_P_hash, hmac(first_half, [].concat(x,seed), 'md5'));
		}

        P_MD5 = md5_P_hash.slice(0, req_bytes);
	}

    /*#To calculate P_SHA_1, we need at most floor(req_bytes/sha1_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of sha1_hash_len(20), we will use
    #0 bytes of the final iteration, otherwise we will use 1-19 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.*/
    if (second_half){
        A=[hmac(second_half, seed, 'sha1')];
        for(i=1; i<Math.floor(req_bytes/sha1_hash_len)+1; i++){
            A.push(hmac(second_half, A[A.length-1], 'sha1'));
    	}

        var sha1_P_hash = [];
        for(i=0; i<A.length; i++){
        	x = A[i];
            sha1_P_hash = [].concat(sha1_P_hash, hmac(second_half, [].concat(x, seed), 'sha1'));
		}

        P_SHA_1 = sha1_P_hash.slice(0, req_bytes);
    }

    if (full_secret){
        PRF = xor(P_MD5, P_SHA_1);
    }

    return [P_MD5, P_SHA_1, PRF];
}
