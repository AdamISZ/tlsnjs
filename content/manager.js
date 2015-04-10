//root directory of managed files
var tlsn_dir = getTLSNdir().path;
//array of existing files
var tlsn_files = [];
var tlsn_lmdates = [];


function addNewRow(filename,lm_date,verified,verifier,html_link){
    var table = document.getElementById("myTableData");
    var rowCount = table.rows.length;
    var row = table.insertRow(rowCount);
    row.insertCell(0).innerHTML = filename;
    row.insertCell(1).innerHTML = lm_date;
    if (verified){
	tbi = 'UNINITIALISED';
    }
    else {
        tbi = 'NO';
    }
    row.insertCell(2).innerHTML = tbi;
    row.insertCell(3).innerHTML = verifier;
    row.insertCell(4).innerHTML = html_link;
}

function clearTable(){
   var table = document.getElementById("myTableData");
   table.innerHTML = "<html:tr> \
<html:td>Filename</html:td> \
        <html:td><html:b>Last modified</html:b></html:td> \
        <html:td><html:b>Verified</html:b></html:td> \
	<html:td><html:b>Verifier identity</html:b></html:td> \
	<html:td><html:b> html </html:b></html:td> </html:tr>";
}

//reloads whole file table, refreshing contents
function loadManager() {
	clearTable();
   tlsn_files = [];
   tlsn_lmdates = [];	
  let iterator = new OS.File.DirectoryIterator(tlsn_dir);
   //Iterate through the directory
  let promise = iterator.forEach(
    function onEntry(entry) {
	tlsn_files.push(entry);
	
	let promise2 = OS.File.stat(entry.path);
	promise2.then(
	function onSuccess(info) { // |info| is an instance of |OS.File.Info|
	    console.log("last mod time: " + info.lastModificationDate);
	    tlsn_lmdates.push(info.lastModificationDate);
	},
	function onFailure(reason) {
	  console.log("File access failure");
	})
    }
  );
  
  // Finally, close the iterator
  promise.then(
    function onSuccess() {
      iterator.close();
      for ( i=0; i < tlsn_files.length; i++){
        //sanity check; all files here should be directories;
	//if the user has placed any other files there, ignore them.
	if (!tlsn_files[i].isDir){
	    console.log("entry was not a directory");
	    continue;
	}
	//build file path  of *.tlsn within the directory
	var tlsn_file = get_filename_from_basename(tlsn_files[i].name);
	if (!tlsn_file){
		console.log("tlsn file was missing from directory: "+dirname);
	}
	else {
		addNewRow(tlsn_files[i].name,tlsn_lmdates[i],false,'tlsnotarygroup',"none");
	}
	verifyEntry(tlsn_files[i].name);
      }
      
    },
    function onFailure(reason) {
      iterator.close();
      throw reason;
    }
  ); 
    console.log("Page load finished");
 
}

function updateRow(basename, col, newval){
	//TODO update multiple columns
	var table = document.getElementById("myTableData");
	var index = -1;
	for (i =0; i < tlsn_files.length; i++){
		if (tlsn_files[i].name == basename){
			index = i;
		}
	}
	if (index == -1){
		console.log("No such row: "+basename);
		return;
	}
	row = table.rows[index+1];
	cell = row.cells[col];
	cell.innerHTML = newval;
}

function get_filename_from_basename(basename){
	var filename;
	if (basename.match("-IMPORTED$")=="-IMPORTED"){
	    filename = basename.slice(0,-"-IMPORTED".length);
	}
	else {
	    filename = basename;
	}
	var tlsn_file = OS.Path.join(tlsn_dir, basename, filename+'.tlsn');
	//TODO stat the file to see if it exists
	return tlsn_file;
}

function verifyEntry(basename){
	var path = OS.Path.join(tlsn_dir, basename, basename+'.tlsn');
	console.log("using path: "+path);
	var html;
	html = OS.File.read(path).then(function(imported_data){
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
	x =  decrypt_html(s);
	//console.log("got x: "+x);
	updateRow(basename,2,"<html:img src='chrome://tlsnotary/content/check.png' height='30' width='30' ></html:img> Valid");
	console.log("Pubkey: "+ba2hex(notary_pubkey));
	updateRow(basename,3,"tlsnotarygroup"); //TODO: pretty print pubkey?
	updateRow(basename,4,"<html:a href = 'file:///" + OS.Path.join(tlsn_dir,basename,"page.html") + "'> View  </html:a>");
	}).catch(function(error){
	console.log("Got this error: "+ error);
	updateRow(basename,2,"<html:img src='chrome://tlsnotary/content/cross.png' height='30' width='30' ></html:img> Not verified: "+ error);
	updateRow(basename,3,"none");
	updateRow(basename,4,"none");
	});
	
}
