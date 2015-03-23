importScripts("chrome://tlsnotary/content/CryptoJS/components/core.js")
importScripts("chrome://tlsnotary/content/CryptoJS/components/evpkdf.js")
importScripts("chrome://tlsnotary/content/CryptoJS/components/enc-base64.js")
importScripts("chrome://tlsnotary/content/CryptoJS/components/sha1.js")
importScripts("chrome://tlsnotary/content/CryptoJS/components/hmac.js")
importScripts("chrome://tlsnotary/content/CryptoJS/components/cipher-core.js")
importScripts("chrome://tlsnotary/content/CryptoJS/components/aes.js")
importScripts("chrome://tlsnotary/content/CryptoJS/components/pad-nopadding.js")
importScripts("chrome://tlsnotary/content/tlsn.js")
importScripts("chrome://tlsnotary/content/tlsn_utils.js")

onmessage = function(e) {
	console.log('got message in worker', e.data);
	var session = e.data;
	var tlsn_session = new TLSNClientSession();
	tlsn_session.server_response_app_data = session.server_response_app_data;
	tlsn_session.unexpected_server_app_data_count = session.unexpected_server_app_data_count;
	var sf = new TLSFinished();
	sf.encrypted = session.sfencrypted;
	var scs = new TLSConnectionState();
	scs.cipher_suite = session.cipher_suite;
	scs.enc_key = session.enc_key;
	scs.IV = session.IV;
	scs.hash_len = session.hash_len;
	scs.seq_no = session.seq_no;
	scs.mac_key = session.mac_key;
	scs.tlsver = session.tlsver;
	scs.mac_algo = session.mac_algo;
	tlsn_session.server_connection_state = scs;
	tlsn_session.server_finished = sf;
	console.log("worker: before process_server_app_data_records");
	var rv = tlsn_session.process_server_app_data_records();
	console.log("worker: finished process_server_app_data_records");
	postMessage(rv);
}
