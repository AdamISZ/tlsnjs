function assert(condition, message) {
    if (!condition) {
        throw message || "Assertion failed";
    }
}

function ba2int(bytearray){
	//TODO find a bigint JS lib
	
}

function print(){//Log to console}
function hexlify(bytearray){//imitate binascii.hexlify}
	
function getRandom(number){
	return window.crypto.getRandomValues(new Uint8Array(number))
}
	
//#constants
var md5_hash_len = 16
var sha1_hash_len = 20
var aes_block_size = 16
var tls_ver_1_0 = [3,1]
var tls_ver_1_1 = [3,2]
var tls_versions = [tls_ver_1_0,tls_ver_1_1]
//#record types
var appd = 0x17 //#Application Data
var hs = 0x16 //#Handshake
var chcis = 0x14 //#Change Cipher Spec
var alrt = 0x15 //#Alert
var tls_record_types = [appd,hs,chcis,alrt]
//#handshake types
var h_ch = 0x01 //#Client Hello
var h_sh = 0x02 //#Server Hello
var h_cert = 0x0b //#Certificate
var h_shd = 0x0e //#Server Hello Done
var h_cke = 0x10 //#Client Key Exchange
var h_fin = 0x14 //#Finished
var tls_handshake_types = [h_ch,h_sh,h_cert,h_shd,h_cke,h_fin]


/*
The amount of key material for each ciphersuite:
AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes
*/

var tlsn_cipher_suites =  {47:['AES128',20,20,16,16,16,16],\
                    53:['AES256',20,20,32,32,16,16],\
                    5:['RC4SHA',20,20,16,16,0,0],\
                    4:['RC4MD5',16,16,16,16,0,0]}
//#preprocessing: add the total number of bytes in the expanded keys format
//#for each cipher suite, for ease of reference
for(key in tlsn_cipher_suites){
	let sum = 0;
	let values = tlsn_cipher_suites[key];
	for (let i=1; values.length; ++i){
		sum += values[i];
	}
	tlsn_cipher_suites[key].push(sum)
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
	let records = []
	let remaining = null
	if (tls_record_types.indexOf(d[0]) < 0){
		return false}
	while (d){    
		let rt = d[0]
		if (tls_record_types.indexOf(rt) < 0){
			remaining = d
			break}
		let ver = d.slice(1,3)
		assert(tls_versions.indexOf(ver) > -1, "Incompatible TLS version")
		let l = ba2int(d.slice(3,5))
		if (d.length < l+5){
			throw("incomplete TLS record")}
		let fragment = d.slice(5,5+l)
		d = d.slice(5+l)
		records.push(TLSRecord(rt, {'tlsver':ver, 'f':fragment}))
	}      
	return [records,remaining]
}


function tls_record_fragment_decoder(t, d, args){
    '''Given the record type t and the data fragment d,
    we construct as many objects of that type as we can find
    in the fragment and return them as a list of Python objects.
    If conn is not None, the record fragment is assumed to be 
    encrypted and is decrypted before processing. '''	
	let conn = args['conn']
	let ignore_mac = args['ignore_mac']
	hlpos = []
	if (conn){
		if (ignore_mac){ //means we won't check it now, but store to be checked later
			rv = conn.dtvm(d, t, {return_mac:true})
			validity = rv[0], plaintext = rv[1], mac = rv[2]}
		else {
			rv = conn.dtvm(d, t)
			validity = rv[0], plaintext = rv[1]}
		if (!validity && !ignore_mac){
			throw("Mac failure")}
	}
	while (plaintext.length){
	 	if (t == hs){
	 		let hs_types = []; for(key in hs_type_map){hs_types.push(key)}
            assert(hs_type_map.indexOf(plaintext[0]) > 0, "Invalid handshake type")
            constructed_obj = new hs_type_map[plaintext[0]]()
            constructed_obj.__init__({'serialized':plaintext})
        }
        else if (t == appd){
            constructed_obj = new TLSAppData()
            constructed_obj.__init__({'serialized':plaintext})}
        else if (t == alrt){
            constructed_obj = new TLSAlert()
            constructed_obj.__init__({'serialized':plaintext})}
        else if (t == chcis){
            constructed_obj   = new TLSChangeCipherSpec()
            constructed_obj.__init__({'serialized':plaintext})}
        else{
            throw("Invalid record type")}
        hlpos.push(constructed_obj)
        plaintext = constructed_obj.discarded
	}
    if (conn){ 
	    //#Note this assumes that only ONE encrypted message
	    hlpos[0].encrypted = d 
	    if (ignore_mac){
	        hlpos[0].recorded_mac = mac}
	}
    return hlpos 
}


function TLSRecord(){}
TLSRecord.prototype.__init__ = function(ct, args){
	f = args['f']
	tlsver = args['tlsver']
	this.content_type = ct
	this.content_version = tlsver
	if (f){
		this.fragment = f
		this._length = this.fragment.length
		this.serialize()
	}
}
TLSRecord.prototype.serialize = function(){
	let check_contents = this.content_type && this.content_version && this._length && this.fragment
	assert(check_contents, "Cannot serialize record, data incomplete")
	assert(this.fragment.length == this._length, "Incorrect record length")
	this.serialized = [].concat(this.content_type, this.content_version, bi2ba(this._length,fixed=2), this.fragment)
}



function TLSHandshake(){}
TLSHandshake.prototype.__init__ = function(serialized, handshake_type){
	if (typeof(serialized)==='undefined') serialized = null
	if (typeof(handshake_type)==='undefined') handshake_type = null
	this.handshake_type = handshake_type
	if (serialized){
		this.serialized = serialized
		assert(self.handshake_type == self.serialized[0], "Mismatched handshake type")
		assert([h_ch,h_sh,h_shd,h_cert,h_cke,h_fin].indexOf(self.handshake_type) > -1, 
			'Unrecognized or unimplemented handshake type')
		this.handshake_record_length = ba2int(this.serialized.slice(1,4))
		if (this.serialized.slice(4).length < self.handshake_record_length){
			throw ('Invalid handshake message length')}
		this.discarded = this.serialized.slice(4+this.handshake_record_length)
		if (this.discarded){
			print ('Info: got a discarded data when constructing',
				   'a handshake message of type: ', hexlify(self.handshake_type),
				   ' and discarded length was: ', this.discarded.length)}
		#Note that we do *not* strip handshake headers for the serialized form;
		#this is a complete, valid handshake message.
		this.serialized = this.serialized.slice(0,4+this.handshake_record_lengt)
	}
}
TLSHandshake.prototype.serialize = function(){
	 this.serialized = [].concat(this.handshake_type, bi2ba(this.serialized.length,fixed=3), this.serialized)
}



//inheritance
TLSClientHello.prototype = new TLSHandshake();
TLSClientHello.prototype.constructor=TLSClientHello;
TLSClientHello.prototype.parent = TLSHandshake.prototype;
function TLSClientHello(){}
TLSClientHello.prototype.__init__ = function(args){
	serialized = args['serialized']
	client_random = args['client_random']
	cipher_suites = args['cipher_suites']
	tlsver = args['tlsver']
	//TODO default args here
	 if (serialized){
            print ('Not implemented instantiation of client hello', 
                   'with serialization; this is a client-only',
                   ' TLS implementation')}
	else {
		if (client_random){
			this.client_random = client_random;}
		else {
			let cr_time = bi2ba(gettime() //TODO here <---)
			this.client_random = [].concat(cr_time, getRandom(28))}
		this.tlsver = tlsver
		this.serialized = [].concat(this.tlsver, this.client_random, 0) 
		this.cipher_suites = cipher_suites
		this.serialized.concat([0, 2*this.cipher_suites.length])
		for(cs in this.cipher_suites){
			this.serialized.concat(0, cs)}
		this.serialized.concat(1,0) //compression methods - null only 
		this.parent.__init__(null, h_ch)
		this.parent.serialize()
	}
}



TLSServerHello.prototype = new TLSHandshake();
TLSServerHello.prototype.constructor=TLSServerHello;
TLSServerHello.prototype.parent = TLSHandshake.prototype;
function TLSServerHello(){}
TLSServerHello.prototype.__init__ = function(args){
	serialized = args['serialized']
	server_random = args['server_random']
	cipher_suites = args['cipher_suites']
	if (serialized){
		this.parent.__init__(serialized, h_sh)
       	this.tlsver = this.serialized.slice(4,6)
        this.server_random = this.serialized.slice(6,38)
        this.session_id_length = ba2int(this.serialized[38])
        let remainder;
        if (this.session_id_length != 0){
            assert(this.session_id_length == 32,'Server hello contains unrecognized session id format')
            this.session_id = this.serialized.slice(39,71)
            remainder = this.serialized.slice(71)}
        else {
            remainder = self.serialized[39:]
            self.session_id = null}

      	this.cipher_suite = ba2int(remainder.slice(0,2))
      	let tlsn_cipher_suites_keys;
      	for(key in tlsn_cipher_suites){tlsn_cipher_suites_keys.push(key)}
        assert(tlsn_cipher_suites_keys.indexOf(this.cipher_suite) > 0, 
        	'Server chosen cipher suite not in TLS Notary allowed list, it was: '+this.cipher_suite.toString())
        assert(remainder.slice(2) == 0x00, 'Received invalid server hello compression method')
        //#At end of serialized instantiation, we have defined server
        //#random and cipher suite
	}
	else {
		print ('Not implemented instantiation of server hello without serialization; 
			this is a client-only TLS implementation')}
}



TLSCertificate.prototype = new TLSHandshake();
TLSCertificate.prototype.constructor=TLSCertificate;
TLSServerHello.prototype.parent = TLSHandshake.prototype;
function TLSCertificate(){}
TLSCertificate.prototype.__init__ = function(args){
	let serialized = args['serialized']
	if (serialized){
		this.parent.__init__(serialized, h_cert)
		/*#TODO we are currently reading *only* the first certificate
        #in the list (tlsnotary code compares this with the browser
        #as a re-use of browser PKI). It may be necessary to do a 
        #more detailed parsing.
        #This handshake message has format: hs_cert(1), hs_msg_len(3),
        #certs_list_msg_len(3), [cert1_msg_len(3), cert1, cert_msg_len(3), cert2...]
        #so the first cert data starts at byte position 10 */
        this.cert_len = ba2int(this.serialized.slice(7,10))
        this.asn1cert = this.serialized.slice(10,10+this.cert_len)}
    else {
    	print ('Not implemented instantiation of certificate without serialization; 
    		this is a client-only TLS implementation')}
}



TLSServerHelloDone.prototype = new TLSHandshake();
TLSServerHelloDone.prototype.constructor=TLSServerHelloDone;
TLSServerHelloDone.prototype.parent = TLSHandshake.prototype;
function TLSServerHelloDone(){}
TLSServerHelloDone.prototype.__init__ = function(args){
	let serialized = args['serialized']
	if (serialized){
		this.parent.__init__(serialized, h_shd)}
	else {
		print ('Not implemented instantiation of server hello done without serialization; 
			this is a client-only TLS implementation')}
}


TLSClientKeyExchange.prototype = new TLSHandshake();
TLSClientKeyExchange.prototype.constructor=TLSClientKeyExchange;
TLSClientKeyExchange.prototype.parent = TLSHandshake.prototype;
function TLSClientKeyExchange(){}
TLSClientKeyExchange.prototype.__init__ = function(args){
	let serialized = args['serialized']
	let encryptedPMS = args['encryptedPMS']
	if (serialized){
		 print ('Not implemented instantiation of client key exchange with serialization; 
		 	this is a client-only TLS implementation')}
	else {
		//XXX idk what to do here
	    if (type(encryptedPMS) == type(long())){
            this.encryptedPMS = bi2ba(encryptedPMS) //#TODO zero byte bug?
	    }
        //#Note that the encpms is preceded by its 2-byte length
        this.serialized = [].concat(bi2ba(this.encryptedPMS.length,fixed=2), this.encryptedPMS)
        this.parent.__init__(null, h_cke)
        this.parent.serialize()
	}
}


function TLSChangeCipherSpec(){}
TLSChangeCipherSpec.prototype.__init__ = function(serialized){
	let serialized = args['serialized']
	if (serialized){
      	this.serialized = serialized
        assert(this.serialized[0] == 0x01, 'Invalid change cipher spec received')
        this.discarded = this.serialized.slice(1)
        this.serialized = this.serialized[0]
	}
	else {
		self.serialized = 0x01
	}
}



TLSFinished.prototype = new TLSHandshake();
TLSFinished.prototype.constructor=TLSFinished;
TLSFinished.prototype.parent = TLSHandshake.prototype;
function TLSFinished(){}
TLSFinished.prototype.__init__ = function(args){
	let serialized = args['serialized']
	let verify_data = args['verify_data']
	if (serialized){
		this.parent.__init__(serialized, h_fin)
		this.validity = null
		this.verify_data = this.serialized.slice(4)
	}
	else{
		this.serialized = verify_data
		this.parent.__init__(null, h_fin)
		this.parent.serialize()
	}
}
TLSFinished.prototype.decrypt_verify_data = function(conn){
    this.encrypted = this.verify_data //#the encrypted form is kept for later processing
	[this.validity, this.verify_data] = conn.dtvm(this.verify_data, hs)
}



function TLSAppData(){}
TLSAppData.prototype.__init__ = function(args){
	let serialized = args['serialized']
	let encrypted = args['encrypted']
   	/*#App Data is 'transparent' to the Record protocol layer
    #(I borrow this slighly, ahem, opaque language from the 
    #RFC Section 10). This means that there is no notion of 
    #'length of an app data message'. Nor is there any meaning
    #to the concept of 'serialization' in this context, since 
    #there is no structure. However the terminology is kept
    #the same as other record types, for consistency.*/
    this.serialized = serialized
    this.discarded=''
}
TLSAppData.prototype.decrypt_app_data = function(conn){
	this.serialized = conn.dtvm(this.serialized, {'rec_type':appd})
}



function TLSAlert(){}
TLSAlert.prototype.__init__ = function(args){
	let serialized = args['serialized']
	if (serialized){
		this.serialized = serialized
        this.discarded=''
	}
	else{
		//#TODO - do we need to issue alerts?
        print ("Alert creation not implemented")
	}
}




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
TLSConnectionState.prototype.__init__ = function(cipher_suite, expanded_keys, is_client, args){
	no_enc = args['no_enc']
	tlsver = args['tlsver']
	/*Provide the cipher suite as defined in the global
	cipher suite list.
	Currently only AES-CBC and RC4 cipher suites are
	supported.
	The format of expanded_keys must be as required
	by the specified cipher suite.
	If mac failures occur they will be flagged but
	decrypted result is still made available.*/
	this.tlsver = tlsver //either TLS1.0 or 1.1
	assert(tls_versions.indexOf(this.tlsver) > 0), "Unrecognised or invalid TLS version")
	this.cipher_suite = cipher_suite
	if (is_client) {
		this.end = 'client'}
	else {
		this.end = 'server'}
	if (cipher_suite == 4){
		this.mac_algo = 'md5'}
	else {
		this.mac_algo = 'sha1'}
	if (this.mac_algo == 'md5'){
		this.hash_len = md5_hash_len}
	else {
		this.hash_len = sha1_hash_len}
	if (no_enc){
		/*special case - mac only processing, we don't need IV or
		enc keys, so 'expanded_keys' is just the mac_key*/
		this.mac_key = expanded_keys
	}
	else {
		 //set appropriate secrets for state
		[this.client_mac_key, this.server_mac_key, this.client_enc_key, this.server_enc_key,
		 this.clientIV, this.serverIV] = expanded_keys
		if (this.end == 'client'){
			[this.mac_key, this.enc_key, this.IV] = 
			[this.client_mac_key, this.client_enc_key, this.clientIV]
		}
		else{
			[this.mac_key, this.enc_key, this.IV] = 
			[this.server_mac_key, this.server_enc_key, this.serverIV]
		}
	}
	this.seq_no = 0
}
TLSConnectionState.prototype.build_record_mac = function(cleartext, record_type){
	let seq_no_bytes = bi2ba(this.seq_no, fixed=8)
	assert(this.mac_key, "Failed to build mac; mac key is missing")
	let fragment_len = bi2ba(cleartext.length, fixed=2)
	//TODO HMAC
	let record_mac = hmac.new(self.mac_key, [].concat(seq_no_bytes, record_type, this.tlsver, fragment_len,cleartext), this.mac_algo).digest()
	return record_mac
}
TLSConnectionState.prototype.mte = function(cleartext, rec_type){
	if ([4,5].indexOf(this.cipher_suite) > 0){
		this.rc4_me(cleartext,rec_type)}
	else {
		this.aes_cbc_mpe(cleartext,rec_type)}
}
TLSConnectionState.prototype.dtvm = function(cleartext, rec_type, args){
	//'''Decrypt then verify mac'''
	return_mac = args['return_mac']
	if ([4,5].indexOf(this.cipher_suite) > 0){
		this.rc4_dm(cleartext,rec_type, return_mac)}
	else {
		this.aes_cbc_dum(cleartext,rec_type, return_mac)}
}
TLSConnectionState.prototype.verify_mac = function(cleartext, rec_type, args){
	let return_mac = args['return_mac']
	let received_mac = cleartext.slice(0,-this.hash_len)
	let check_mac = this.build_record_mac(cleartext.slice(0,-this.hash_len), rec_type)
	this.seq_no += 1
	if (return_mac){
		return [received_mac==check_mac, cleartext.slice(0,-self.hash_len),received_mac]}
	else {
		return [received_mac==check_mac, cleartext.slice(0, -self.hash_len)]}
}
TLSConnectionState.prototype.rc4_me = function(cleartext, rec_type){
	//#mac
	cleartext = [].concat(cleartext, this.build_record_mac(cleartext,rec_type))
	//#encrypt
	//#note: for RC4, the 'IV' is None at the start, 
	//#which tells the RC4 to initialize state
	rv = rc4_crypt(cleartext, this.enc_key, this.IV)
	let ciphertext = rv[0], this.IV = rv[1]
	this.seq_no += 1   
	return ciphertext 
}
TLSConnectionState.prototype.rc4_dm = function(cleartext, rec_type, args){
	let return_mac = args['return_mac']
	//#decrypt
	rv = rc4_crypt(ciphertext, this.enc_key, this.IV)
	let plaintext = rv[0], this.IV = rv[1]
	//#mac check
	return this.verify_mac(plaintext, rec_type, return_mac)  
}
TLSConnectionState.prototype.aes_cbc_mpe = function(cleartext, rec_type){
	//#mac
	cleartext = [].concat(cleartext, this.build_record_mac(cleartext,rec_type))
	//#pad
	//TODO figure out what to do
}
TLSConnectionState.prototype.aes_cbc_mpe = function(ciphertext, rec_type, args){
	let return_mac = args['return_mac']
	//TODO decrypt and check mac
}



//#dictionary to allow dynamic decoding of a handshake message in a record fragment   
hs_type_map = {h_ch:TLSClientHello,h_sh:TLSServerHello,h_cert:TLSCertificate,\
            h_cke:TLSClientKeyExchange,h_fin:TLSFinished,h_shd:TLSServerHelloDone}  



function tls_sender(sckt, msg, rec_type, args){
    /*'''Wrap a message in a TLS Record before sending
    If conn argument provided, encrypt the payload
    before sending'''*/
	let conn = args['conn']
	let tlsver = args['tlsver']
    if (conn){
        msg = conn.mte(msg,rec_type)
    }
    let rec = TLSRecord(rec_type, {'f':msg, 'tlsver':tlsver})
    sckt.send(rec.serialized)
}


function TLSNClientSession(){}
TLSNClientSession.prototype.__init__ = function(args){
	let server = args['server']
	let port = args['port']
	let ccs = args['ccs']
	let tlsver = args['tlsver']
	if (typeof(server)==='undefined') server = null;
	if (typeof(port)==='undefined') port = 443;
	if (typeof(ccs)==='undefined') ccs = null;
	if (typeof(tlsver)==='undefined') tlsver = null;
	
    this.server_name = server
    this.ssl_port = port
    this.initial_tlsver = tlsver
    //#current TLS version may be downgraded
    this.tlsver = tlsver
    this.n_auditee_entropy = 12
    this.n_auditor_entropy = 9
    this.auditor_secret = null
    this.auditee_secret = null
    this.auditor_padding_secret = null
    this.auditee_padding_secret = null
    this.pms1 = null //#auditee's
    this.pms2 = null //#auditor's
    this.enc_first_half_pms = null
    this.enc_second_half_pms = null
    this.enc_pms = null
    //#client hello, server hello, certificate, server hello done,
    //#client key exchange, change cipher spec, finished
    this.handshake_messages = [null, null, null, null, null null, null]
    this.handshake_hash_sha = null
    this.handshake_hash_md5 = null
    this.p_auditor = null
    this.p_auditee = null
    this.master_secret_half_auditor = null
    this.master_secret_half_auditee = null
    this.p_master_secret_auditor = null
    this.p_master_secret_auditee = null
    this.server_mac_key = null
    this.client_mac_key = null
    this.server_enc_key = null
    this.client_enc_key = null
    this.serverIV = null
    this.clientIV = null
    this.server_certificate = null
    this.server_modulus = null
    this.server_exponent = 65537
    this.server_mod_length = null

    //#array of ciphertexts from each SSL record
    this.server_response_app_data=[]
    
    //#unexpected app data is defined as that received after 
    //#server finished, but before client request. This will
    //#be decrypted, but not included in plaintext result.
    this.unexpected_server_app_data_count = 0
    this.unexpected_server_app_data_raw = ''
    
    /*#the HMAC required to construct the verify data
    #for the server Finished record
    self.verify_hmac_for_server_finished = None
    
    #for certain testing cases we want to limit the
    #choice of cipher suite to 1, otherwise we use
    #the globally defined standard 4: */
    if (ccs){
    	this.offered_cipher_suites = {ccs:tlsn_cipher_suites[ccs]}
    }
    else {
    	this.offered_cipher_suites = tlsn_cipher_suites
    }
    this.chosen_cipher_suite = ccs
}
TLSNClientSession.prototype.dump = function(){
//XXX implement this
}
TLSNClientSession.prototype.start_handshake = function(sckt){
	let offered_cipher_suites_keys = []
	for(key in this.offered_cipher_suites){offered_cipher_suites_keys.push(key)}
	this.client_hello = new TLSClientHello()
	this.client_hello.__init__({'cipher_suites':offered_cipher_suites_keys, 'tlsver':this.tlsver})
	this.handshake_messages[0]= this.client_hello.serialized
	tls_sender(sckt, this.handshake_messages[0], hs,{'tlsver':self.tlsver})
	/*      #the handshake messages: server hello, certificate, server hello done
        #may be packed in arbitrary groupings into the TLS records, since
        #they are all the same record type (Handshake)            */
	let handshake_objects=[]
	while (handshake_objects.length < 3){
		let rspns = recv_socket(sckt,True)
		let rv = tls_record_decoder(rspns)
		records = rv[0], remaining = rv[1]
		assert(!remaining, "Server sent spurious non-TLS response")
		for(rec in records){
			handshake_objects.concat(tls_record_fragment_decoder(hs, rec.fragment))}
	}
	let handshake_types=[]
	for(x in handshake_objects) {handshake_types.push(x.handshake_type)}
	assert(handshake_types.indexOf(h_sh) > 0 && handshake_types.indexOf(h_cert) > 0 &&
		handshake_types.indexOf(h_shd) > 0, 
	   "Server failed to send server hello, certificate, server hello done")
	[this.server_hello, this.server_certificate, this.server_hello_done] = handshake_objects
	
	this.handshake_messages[1] = handshake_objects[0].serialized
	this.handshake_messages[2] = handshake_objects[1].serialized
	this.handshake_messages[3] = handshake_objects[2].serialized

	this.client_random = this.client_hello.client_random
	this.server_random = this.server_hello.server_random
	this.chosen_cipher_suite = this.server_hello.cipher_suite
	
	if (this.server_hello.tlsver.toString() != this.tlsver.toString()){
		if (this.server_hello.tlsver.toString() == [3,1].toString() &&
			this.tlsver.toString == [3,2].toString()){
			#server requested downgrade
			#note that this can only happen *before* a TLSConnectionState object is
			#initialised, so the tlsversion used in that object will be synchronised.
			#TODO: error checking to make sure this is the case.
			this.tlsver = [3,1]}
		else{
			throw("Failed to negotiate valid TLS version with server")}
	}
	//#for 'full' sessions, we can immediately precompute everything except
	//#for finished, including the handshake hashes used to calc the Finished
	if (this.enc_pms){
		this.client_key_exchange = new TLSClientKeyExchange()
		this.client_key_exchange.__init__({'serialized':null, 'encryptedPMS':this.enc_pms})
		this.change_cipher_spec = new TLSChangeCipherSpec()
		this.change_cipher_spec.__init__()
		this.handshake_messages[4] = this.client_key_exchange.serialized
		this.handshake_messages[5] = this.change_cipher_spec.serialized
		this.set_handshake_hashes()}
}
TLSNClientSession.prototype.get_verify_data_for_finished = function(args){
	let sha_verify = args['sha_verify']
	let md5_verify = args['md5_verify']
	let half = args['half']
	let provided_p_value = args['provided_p_value']
	let is_for_client = args['is_for_client']
	
	if (! (sha_verify and md5_verify)){
		[sha_verify, md5_verify] = [this.handshake_hash_sha, this.handshake_hash_md5]}
		
	if (!provided_p_value){
		//#we calculate the verify data from the raw handshake messages
		if (this.handshake_messages.slice(0,6).indexOf(null) > -1{
			print('Here are the handshake messages: ' + this.handshake_messages.slice(0,6).toString())
			throw('Handshake data was not complete, could not calculate verify data')}
		let label;
		if (is_for_client){
			label = 'client finished'}
		else {
			label = 'server finished'}
		let seed = [].concat(md5_verify,sha_verify)
		let ms = [].concat(this.master_secret_half_auditor, this.master_secret_half_auditee)
		//#we don't store the verify data locally, just return it
		return tls_10_prf([].concat(label,seed), {'req_bytes':12,'full_secret':ms})[2]
	}
	//#we calculate based on provided hmac by the other party
    return xor(provided_p_value.slice(0,12), 
    	this.get_verify_hmac({'sha_verify':sha_verify, 'md5_verify':md5_verify,
    	'half':half, 'is_for_client':is_for_client}) 
}
TLSNClientSession.prototype.set_handshake_hashes = function(args){
	let server = args['server']
      /*  '''An obscure but important detail: the hashes used
    for the server Finished use the *unencrypted* client finished;
    in the current model this is automatic since the TLSFinished objects
    store the verify data unencrypted.'''*/
    let handshake_data = this.handshake_messages.slice(0,5)
    if (server){
        handshake_data.concat(this.handshake_messages[6])// #client finished
    }
    let handshake_hash_sha = sha1(handshake_data)
    let handshake_hash_md5 = md5(handshake_data)
    if (not server){
        [this.handshake_hash_sha, this.handshake_hash_md5] = [handshake_hash_sha, handshake_hash_md5]
    }
    return [handshake_hash_sha, handshake_hash_md5]
}
TLSNClientSession.prototype.send_client_finished = function(sckt, provided_p_value){
       /* '''Creates the client finished handshake message without
	    access to the master secret, but on the P-hash data provided
	    by the auditor. Then receives the server ccs and finished.'''*/
	let verify_data = this.get_verify_data_for_finished({'provided_p_value':provided_p_value, 'half':2})
	this.client_finished = new TLSFinished()
	this.client_finished.__init__({'serialized':null, 'verify_data':verify_data})
	this.handshake_messages[6] = this.client_finished.serialized
	//#Note that the three messages cannot be packed into one record; 
	//#change cipher spec is *not* a handshake message
	tls_sender(sckt, this.handshake_messages[4], hs, {'tlsver':this.tlsver})
	tls_sender(sckt, this.handshake_messages[5], chcis, {'tlsver':this.tlsver}) 
	//#client finished must be sent encrypted       
	tls_sender(sckt, this.handshake_messages[6], hs,{'conn':this.client_connection_state, 'tlsver':self.tlsver})
	let records=[]
    while (records.length < 2){ //#conceivably, might want an extra timeout for naughty servers!?
        let rspns = recv_socket(sckt,True)
        let rv = tls_record_decoder(rspns)
        let x = rv[0], let remaining = rv[1]
        assert(!remaining, "Server sent spurious non-TLS response")
        records.concat(x)
    }
     /*   #this strange-looking 'filtering' approach is based on observation
    #in practice of CCS being repeated (and possible also Finished, although I don't remember)*/
    let sccs = null;
    for(x in records){if(x.content_type == chcis){sccs = x}}
    this.server_ccs = tls_record_fragment_decoder(chcis, sccs.fragment)[0]
    let sf = null;
    for(x in records){if(x.content_type == hs){sf = x}}    
    this.server_finished = tls_record_fragment_decoder(hs, sf.fragment,
        {'conn':this.server_connection_state, 'ignore_mac':true})[0]
    assert(this.server_finished.handshake_type == h_fin, "Server failed to send Finished")
    //#store the IV immediately after decrypting Finished; this will be needed
    //#by auditor in order to replay the decryption
    this.IV_after_finished = this.server_connection_state.IV

    if (records.length > 2){
        //#we received extra records; are they app data? if not we have bigger problems..
        for(x in records){
            if ([chcis,hs].indexOf(x.content_type) > -1){
            	continue
         	}
            if (x.content_type != appd){
                //#this is too much; if it's an Alert or something, we give up.
                throw("Received unexpected TLS record before client request.")}
            //#store any app data records, in sequence, prior to processing all app data.
            this.server_response_app_data.concat(tls_record_fragment_decoder(appd,x.fragment))
            //#We have to store the raw form of these unexpected app data records, since they will
            //#be needed by auditor.
            this.unexpected_server_app_data_raw.concat(x.serialized)// #the full record serialization (otw bytes)
            this.unexpected_server_app_data_count += 1 //#note: each appd record contains ONE appd message
        }
	}
}
TLSNClientSession.prototype.complete_handshake = function(sckt, rsapms2){
       /* '''Called from prepare_pms(). For auditee only,
    who passes the second half of the encrypted
    PMS product (see TLSNotary.pdf under documentation).'''*/
    this.set_auditee_secret()
    this.set_master_secret_half() //#default values means full MS created
    this.do_key_expansion()
    this.enc_second_half_pms = ba2int(rsapms2)
    this.set_enc_first_half_pms()
    this.set_encrypted_pms()
    this.client_key_exchange = new TLSClientKeyExchange()
    this.client_key_exchange.__init__({'encryptedPMS':self.enc_pms})
    this.handshake_messages[4] = this.client_key_exchange.serialized
    this.change_cipher_spec = new TLSChangeCipherSpec()
    this.change_cipher_spec.__init__()
    this.handshake_messages[5] = this.change_cipher_spec.serialized
    this.set_handshake_hashes()

    let client_verify_data = this.get_verify_data_for_finished({'sha_verify':self.handshake_hash_sha,
        'md5_verify':self.handshake_hash_md5, 'half':1})
    
    this.client_finished = new TLSFinished()
    this.client_finished.__init__({'verify_data':client_verify_data})
    this.handshake_messages[6] = this.client_finished.serialized
    //#Note that the three messages cannot be packed into one record; 
    //#change cipher spec is *not* a handshake message
    tls_sender(sckt, this.handshake_messages[4], hs, {'tlsver':self.tlsver})
    tls_sender(sckt, this.handshake_messages[5], chcis, {'tlsver':self.tlsver}) 
    //#client finished must be sent encrypted
    tls_sender(sckt, this.handshake_messages[6], hs, {'conn':self.client_connection_state, 'tlsver':self.tlsver})
    return recv_socket(sckt,True)
}
TLSNClientSession.prototype.set_encrypted_pms = function(){
    assert(this.enc_first_half_pms && this.enc_second_half_pms && this.server_modulus,
    	'failed to set enc_pms, first half was: ' + this.enc_first_half_pms.toString() +
        ' second half was: ' + this.enc_second_half_pms.toString() + ' modulus was: ' +
        this.server_modulus.toString())
    this.enc_pms =  this.enc_first_half_pms * this.enc_second_half_pms % this.server_modulus
    return this.enc_pms
}
TLSNClientSession.prototype.set_enc_first_half_pms = function(){
    assert(this.server_modulus && !this.enc_first_half_pms)
    let ones_length = 23
    let trailing_zeroes = []
    for (let i=0; 24-2-this.n_auditee_entropy; ++i){trailing_zeroes.push(0)}       
    this.pms1 = [].concat(this.initial_tlsver, this.auditee_secret, trailing_zeroes)
	///XXX find how to do mod exp in JS
    this.enc_first_half_pms = pow(ba2int('\x02'+('\x01'*(ones_length))+\
    self.auditee_padding_secret+'\x00'+self.pms1 +'\x00'*23 + '\x01'), self.server_exponent, self.server_modulus)
}
TLSNClientSession.prototype.set_auditee_secret = function(){
    /*'''Sets up the auditee's half of the preparatory
    secret material to create the master secret. Note
    that according to the RFC, the tls version prepended to the
    premaster secret must be that used in the client hello message,
    not the negotiated/downgraded version set by the server hello. 
    See variable tlsver_ch.'''*/
    tlsver_ch = init.initial_tlsver
    let cr = init.client_random
    let sr = init.server_random
    assert(cr && sr,"one of client or server random not set")
    if (!this.auditee_secret){
        this.auditee_secret = getRandom(self.n_auditee_entropy)             
    }
    if (!this.auditee_padding_secret){
        this.auditee_padding_secret = getRandom(15)
    }
    let label = 'master secret'
    let seed = [].concat(cr,sr)
    let trailing_zeroes = []
    for (let i=0; 24-2-this.n_auditee_entropy; ++i){trailing_zeroes.push(0)}  
    this.pms1 = [].concat(tlsver_ch, this.auditee_secret, trailing_zeroes)
    this.p_auditee = tls_10_prf([].concat(label+seed),{'first_half':this.pms1})[0]
    //#encrypted PMS has already been calculated before the audit began
    return self.p_auditee
}
TLSNClientSession.prototype.set_enc_second_half_pms = function(){
    assert(this.server_modulus)
    let ones_length = 103+ba2int(this.server_mod_length)-256
    let trailing_zeroes = []
    for (let i=0; 24-self.n_auditor_entropy-1; ++i){trailing_zeroes.push(0)}  
    this.pms2 = [].concat(this.auditor_secret, trailing_zeroes, 0x01)
///XXX JS mod exp
    this.enc_second_half_pms = pow( ba2int('\x01'+('\x01'*(ones_length))+\
    self.auditor_padding_secret+ ('\x00'*25)+self.pms2), self.server_exponent, self.server_modulus )
}
TLSNClientSession.prototype.set_auditor_secret = function(){
    /*'''Sets up the auditor's half of the preparatory
    secret material to create the master secret, and
    the encrypted premaster secret.
    'secret' should be a bytearray of length n_auditor_entropy'''*/
    let cr = this.client_random
    let sr = this.server_random
    assert(cr && sr, "one of client or server random not set")
    if (!this.auditor_secret){
        this.auditor_secret = getRandom(this.n_auditor_entropy)
    }
    if (!this.auditor_padding_secret){
        this.auditor_padding_secret = getRandom(15)
    }
    let label = 'master secret'
    let seed = [].concat(cr,sr)
    let trailing_zeroes = []
    for (let i=0; 24-this.n_auditor_entropy-1; ++i){trailing_zeroes.push(0)}  
    this.pms2 = [].concat(this.auditor_secret, trailing_zeroes, 0x01)
    this.p_auditor = tls_10_prf([].concat(label,seed),{'second_half':this.pms2})[1]
    return self.p_auditor
}
TLSNClientSession.prototype.set_master_secret_half = function(args){
	let half = args['half']
	let provided_p_value = args['provided_p_value']
    //#non provision of p value means we use the existing p
    //#values to calculate the whole MS
    if (!provided_p_value){
        this.master_secret_half_auditor = xor(this.p_auditee.slice(0,24), this.p_auditor.slice(0,24))
        this.master_secret_half_auditee = xor(this.p_auditee.slice(24), this.p_auditor.slice(24))
        return [].concat(this.master_secret_half_auditor, this.master_secret_half_auditee)
    }
    assert([1,2].indexOf(half) > -1, "Must provide half argument as 1 or 2")
    //#otherwise the p value must be enough to provide one half of MS
    assert(provided_p_value.length==24, "Wrong length of P-hash value for half MS setting.")
    if (half == 1){
        this.master_secret_half_auditor = xor(this.p_auditor.slice(0,24), provided_p_value)
        return this.master_secret_half_auditor
    }
    else{
        this.master_secret_half_auditee = xor(this.p_auditee.slice(24), provided_p_value)
        return this.master_secret_half_auditee 
    }
}
TLSNClientSession.prototype.get_p_value_ms = function(ctrprty){
       /* '''Provide a list of keys that you want to 'garbageize' so as to hide
        that key from the counterparty, in the array 'garbage', each number is
        an index to that key in the cipher_suites dict        
        '''*/
	let garbage = args['garbage']
    assert(this.server_random && this.client_random && this.chosen_cipher_suite, 
    	"server random, client random or cipher suite not set.")
    let label = 'key expansion'
    let seed = [].concat(this.server_random, this.client_random)
    let chosen_cs = tlsn_cipher_suites[this.chosen_cipher_suite]
    let expkeys_len = chosen_cs[chosen_cs.length-1]        
    if (ctrprty == 'auditor'){
        this.p_master_secret_auditor = tls_10_prf([].concat(label, seed), 
        	{'req_bytes':expkeys_len, 'first_half':this.master_secret_half_auditor})[0]
    }
    else{
        this.p_master_secret_auditee = tls_10_prf([].concat(label, seed),
        	{'req_bytes':expkeys_len, 'second_half':this.master_secret_half_auditee})[1]
    }

    let tmp 
    if (ctrprty=='auditor'){
    	tmp = this.p_master_secret_auditor}
    else {
    	tmp = this.p_master_secret_auditee}
    for(k in garbage){
    	let start = 0
        if (k==1){
            start = 0}
        else{
        	for(let i=1; i<k; ++i){
        		start += tlsn_cipher_suites[this.chosen_cipher_suite][i]}
        let end = 0
        for(let i=1; i<k+1; ++i){
        		end += tlsn_cipher_suites[this.chosen_cipher_suite][i]}
        //#ugh, python strings are immutable, what's the elegant way to do this?
        let tmp2 = [].concat(tmp.slice(0,start), getRandom(end-start), tmp.slice(end))
        tmp = tmp2
    }
    return tmp
}
TLSNClientSession.prototype.do_key_expansion = function(ctrprty){
        /*'''A note about partial expansions:
        Often we will have sufficient information to extract particular
        keys, e.g. the client keys, but not others, e.g. the server keys.
        This should be handled by passing in garbage to fill out the relevant
        portions of the two master secret halves. TODO find a way to make this
        explicit so that querying the object will only give real keys.
        '''*/

    let cr = this.client_random
    let sr = this.server_random
    let cs = this.chosen_cipher_suite
    assert(cr && sr && cs," need client and server random and cipher suite")
    let label = 'key expansion'
    let seed = [].concat(sr, cr)
    //#for maximum flexibility, we will compute the sha1 or md5 hmac
    //#or the full keys, based on what secrets currently exist in this object
    let chosen_cs = tlsn_cipher_suites[cs]
    let expkeys_len = chosen_cs[chosen_cs.length-1]
    if (this.master_secret_half_auditee){
        this.p_master_secret_auditee = tls_10_prf([].concat(label, seed),
        	{'req_bytes':expkeys_len, 'second_half':this.master_secret_half_auditee})[1]
    }
    if (this.master_secret_half_auditor){
        this.p_master_secret_auditor = tls_10_prf([].concat(label,seed),
        	{'req_bytes':expkeys_len, 'first_half':self.master_secret_half_auditor})[0]
    }

    let key_expansion
    if (this.master_secret_half_auditee && this.master_secret_half_auditor){
        key_expansion = tls_10_prf([].concat(label, seed),
        	{'req_bytes':expkeys_len, 
        	'full_secret':[].concat(this.master_secret_half_auditor, this.master_secret_half_auditee})[2]
    }
    else if(this.p_master_secret_auditee && this.p_master_secret_auditor){
        key_expansion = xor(this.p_master_secret_auditee, this.p_master_secret_auditor)
    }
    else{
        throw ('Cannot expand keys, insufficient data')
    }

    //#we have the raw key expansion, but want the keys. Use the data
    //#embedded in the cipherSuite dict to identify the boundaries.
    let key_accumulator = []
    let ctr=0
    for(let i=0; i<6; ++i){
        let keySize = tlsn_cipher_suites[cs][i+1]
        if (keySize == 0){
            key_accumulator.push(None)
        }
        else{
            key_accumulator.push(key_expansion.slice(ctr,ctr+keySize))
        }
        ctr += keySize
    }

    [this.client_mac_key, this.server_mac_key, this.client_enc_key,
        this.server_enc_key, this.clientIV, this.serverIV] = key_accumulator
    /*#we now have sufficient information to initialise client and server
    #connection state. NOTE: Since this wipes/restarts the encryption 
    #connection state, a call to do_key_expansion automatically restarts
    #the session.*/
    self.client_connection_state = new TLSConnectionState()
    self.client_connection_state.__init__(cs, key_accumulator, True, False, {'tlsver':this.tlsver})
    self.server_connection_state = new TLSConnectionState()
    self.server_connection_state.__init__(cs, key_accumulator, False, False, {'tlsver':this.tlsver})
    let keys = []
    for(let i=0; i<key_accumulator.length; ++i){
    	if(key_accumulator[i] != null){keys.concat(key_accumulator[i])}
    }
    return keys
}
TLSNClientSession.prototype.get_verify_hmac = function(args){
	let sha_verify = args['sha_verify']
	let md5_verify = args['md5_verify']
	let half = args['half']
	let is_for_client = args['is_for_client']
    //'''returns only 12 bytes of hmac'''
    let label
    if (is_for_client){
    	label = 'client finished'}
    else {
    	label = 'server finished'}
    let seed = [].concat(md5_verify, sha_verify)
    if (half==1){
        return tls_10_prf([].concat(label,seed),
        	{'req_bytes':12, 'first_half':this.master_secret_half_auditor})[0]
    }
    else{
        return tls_10_prf([].concat(label, seed),
        	{'req_bytes':12, 'second_half':this.master_secret_half_auditee})[1]              
    }
}
TLSNClientSession.prototype.check_server_ccs_finished = function(provided_p_value){
    //#verify the verify data:
    let sha_verify, md5_verify     
    [sha_verify, md5_verify] = this.set_handshake_hashes({'server':true})
    let verify_data_check = this.get_verify_data_for_finished(
    	{'sha_verify':sha_verify, 'md5_verify':md5_verify,
		'provided_p_value':provided_p_value, 'half':2, 'is_for_client':false})
    assert(this.server_finished.verify_data.toString() == verify_data_check.toString(),
           "Server Finished record verify data is not valid.")
    return true
}
TLSNClientSession.prototype.build_request = function(sckt, cleartext){
    /*'''Constructs the raw bytes to send over TCP
    for a given client request. Implicitly the request
    will be less than 16kB and therefore only 1 SSL record.
    This can in principle be used more than once.'''*/
    this.tls_request = new TLSAppData()
    this.tls_request.__init__(cleartext)
    tls_sender(sckt, this.tls_request.serialized, appd, 
    	{'conn':this.client_connection_state, 'tlsver':this.tlsver})
}
TLSNClientSession.prototype.store_server_app_data_records = function(response){
    //#extract the ciphertext from the raw records as a list
    //#for maximum flexibility in decryption
    let recs, remaining
    [recs, remaining] = tls_record_decoder(response)
    assert(!remaining, "Server sent spurious non-TLS data")
    for(rec in recs){
        this.server_response_app_data.concat(
        	tls_record_fragment_decoder(rec.content_type,rec.fragment))    
    }
    //#what has been stored is a list of TLSAppData objects in which
    //#the .serialized property is still encrypted.
}
TLSNClientSession.prototype.get_ciphertexts = function(){
//XXX DO we need this in JS only?
}
TLSNClientSession.prototype.mac_check_plaintexts = function(plaintexts){
    /*'''for use with aes-js; given the plaintext
    output from decryption, we check the macs of the plaintext
    records. To do this a special non-encryption form of the
    ConnectionState is built which only checks macs.''' */
    let mac_stripped_plaintext = ''
    //#build a dummy connection state with null encryption
    //#and run each plaintext through, checking the mac each time
    let dummy_connection_state = new TLSConnectionState()
    dummy_connection_state.__init__(this.chosen_cipher_suite, this.server_mac_key, 
		{'is_client':false, 'no_enc':true, 'tlsver':this.tlsver})
    let validity, fintext
    [validity, fintext] = dummy_connection_state.verify_mac(
    	[].concat(this.server_finished.serialized, this.server_finished.recorded_mac), hs)


    if (!validity){
        throw ("Server finished mac check failed")}
    //#NB Note the verify data was verified earlier, no need to do it again here
    for(let i=0; i<plaintexts.length; ++i){
    	let pt = plaintexts[i]
    	let rt
    	if (this.server_response_app_data[i].constructor == TLSAppData){
    		rt = appd}
        else if (this.server_response_app_data[i].constructor == TLSAlert){
            rt = alrt}
        else{
            print ("Info: Got an unexpected record type in the server response: " +
            	this.server_response_app_data[i].constructor.toString())
        }
        let [validity, stripped_pt] = dummy_connection_state.verify_mac(pt, rt)
        assert(validity==true, "Fatal error - invalid mac, data not authenticated!")
        
        //#plaintext is only included if it's appdata not alerts, and if it's 
        //#not part of the ignored set (the set that was delivered pre-client-request)            
        if (rt==appd && i > this.unexpected_server_app_data_count-1){
            mac_stripped_plaintext += stripped_pt
        }
        else if (rt==alrt){
            print ("Info: alert received, decrypted: ", stripped_pt.toString())
        }
    }
    return mac_stripped_plaintext
}
TLSNClientSession.prototype.mac_check_server_finished = function(plaintexts){
//XXX is needed?
}
TLSNClientSession.prototype.process_server_app_data_records = function(args){
   /*'''Using the encrypted records in self.server_response_ciphertexts, 
    containing the response from
    the server to a GET or POST request (the *first* request after
    the handshake), this function will process the response one record
    at a time. Each of these records is decrypted and reassembled
    into the plaintext form of the response. The plaintext is returned
    along with the number of record mac failures (more than zero means
    the response is unauthenticated/corrupted).
    '''*/
	let is_for_auditor = args['is_for_auditor']

    let bad_record_mac = 0
    if (!is_for_auditor){
        //#decrypt and verify mac of server finished as normal
        if (this.mac_check_server_finished() != true){
            bad_record_mac += 1
        }
    }
    else{
        //#auditor needs to reset the state of the server_connection_state
        //#without actually processing the server finished (he doesn't have it)
        this.server_connection_state.seq_no += 1
        this.server_connection_state.IV = this.IV_after_finished
    }
        
    assert(this.server_response_app_data.length, 
    	"Could not process the server response, no ciphertext found.")
    let plaintexts = ''

	for(let i=0; i<this.server_response_app_data.length; ++i){
    	let ciphertext = this.server_response_app_data[i]
    	let rt
        if (ciphertext.constructor == TLSAppData){
            rt = appd}
        else if (ciphertext.constructor == TLSAlert){
            rt = alrt}
        else{
            throw ("Server response contained unexpected record type: ",
            	ciphertext.constructor.toString())
        }
        let [validity, plaintext] = this.server_connection_state.dtvm(ciphertext.serialized, rt)
        if (validity!=true){ 
            bad_record_mac += 1
        }
        //#plaintext is only included if it's appdata not alerts, and if it's 
        //#not part of the ignored set (the set that was delivered pre-client-request)
        if (rt== appd && i>this.unexpected_server_app_data_count-1){
            plaintexts += plaintext
        }
    return [plaintexts, bad_record_mac]
}

function get_cbc_padding(data_length){}
function cbc_unpad(pt){}
function rc4_crypt(data, key, args){}
function rc4_state_to_bytearray(state){}




       
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
    let req_bytes = args['req_bytes']
    let first_half = args['first_half']
    let second_half = args['second_half']
    let full_secret = args['full_secret']
	if (typeof(req_bytes)==='undefined') req_bytes = 48;
	if (typeof(first_half)==='undefined') req_bytes = null;
	if (typeof(second_half)==='undefined') req_bytes = null;
	if (typeof(full_secret)==='undefined') req_bytes = null;
    //#sanity checks, (see choices of how to provide secrets under 'Notes' above)
	if (!first_half && !second_half && !full_secret){
        throw("Error in TLSPRF: at least one half of the secret is required.")}
    if (full_secret && first_half) || (full_secret && second_half){
        throw("Error in TLSPRF: both full and half secrets should not be provided.")}
    if (first_half && second_half){
        throw("Error in TLSPRF: please provide the secret in the parameter full_secret.")}
        
    let P_MD5, P_SHA_1, PRF = null;

    //split the secret into two halves if necessary
    if (full_secret){
        let L_S = len(full_secret)
        let L_S1 = L_S2 = int(math.ceil(L_S/2))
        first_half = full_secret[:L_S1]
        second_half = full_secret[L_S2:]
	}

    /*#To calculate P_MD5, we need at most floor(req_bytes/md5_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of md5_hash_len(16), we will use
    #0 bytes of the final iteration, otherwise we will use 1-15 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.*/
    if (first_half){
        A=[hmac.new(first_half,seed,md5).digest()]
        for i in range(1,int(req_bytes/md5_hash_len)+1):
            A.append(hmac.new(first_half,A[len(A)-1],md5).digest())

        md5_P_hash = ''
        for x in A:
            md5_P_hash += hmac.new(first_half,x+seed,md5).digest()

        P_MD5 = md5_P_hash[:req_bytes]
	}

    /*#To calculate P_SHA_1, we need at most floor(req_bytes/sha1_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of sha1_hash_len(20), we will use
    #0 bytes of the final iteration, otherwise we will use 1-19 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.*/
    if (second_half){
        A=[hmac.new(second_half,seed,sha1).digest()]
        for i in range(1,int(req_bytes/sha1_hash_len)+1):
            A.append(hmac.new(second_half,A[len(A)-1],sha1).digest())

        sha1_P_hash = ''
        for x in A:
            sha1_P_hash += hmac.new(second_half,x+seed,sha1).digest()

        P_SHA_1 = sha1_P_hash[:req_bytes]
    }

    if (full_secret){
        PRF = xor(P_MD5,P_SHA_1)
    }

    return [P_MD5, P_SHA_1, PRF]
}



function tls_record_fragment_decoder(t,d, args){
	/*Given the record type t and the data fragment d,
    we construct as many objects of that type as we can find
    in the fragment and return them as a list of Python objects.
    If conn is not None, the record fragment is assumed to be 
    encrypted and is decrypted before processing. */
	conn = args['conn']
	ignore_mac = args['ignore_mac']
	hlpos = []
	if (conn){
		if (ignore_mac){ //means we won't check it now, but store to be checked later
			rv = conn.dtvm(d,t,return_mac=True)
			validity = rv[0], plaintext = rv[1], mac = rv[2]
		}
		
	}
	
	
}











