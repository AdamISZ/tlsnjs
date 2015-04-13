//root directory of managed files
var tlsn_dir = getTLSNdir().path;
//array of existing files
var tlsn_files = [];
var tlsn_lmdates = [];


function importTLSNFiles(){
	main.verify();
	loadManager();
}
function addNewRow(filename,imported,verified,verifier,html_link){
    var tbody = document.getElementById("myTableData").getElementsByTagName('tbody')[0];
    var rowCount = tbody.rows.length;
    var row = tbody.insertRow(rowCount);
    row.insertCell(0).innerHTML = filename;
    if (!imported){
	row.insertCell(1).innerHTML = "mine";
    }
    else {
	row.insertCell(1).innerHTML = "IMPORTED";
	}
    if (verified){
	tbi = 'UNINITIALISED';
    }
    else {
        tbi = 'NO';
    }
    row.insertCell(2).innerHTML = tbi;
    row.insertCell(3).innerHTML = verifier;
    row.insertCell(4).innerHTML = html_link;
    button_html = "<button id='"+filename+"' title='permanently remove this set of files from disk' onclick='deleteFile(event.target)'>Delete</button>";
    row.insertCell(5).innerHTML = button_html;
}

function deleteFile(basename){
	var r = confirm("This will remove the entire directory:"+basename.id+", including html. Are you sure?");
	if (r){
	    OS.File.removeDir(OS.Path.join(tlsn_dir,basename.id));
	    loadManager();
	}
}

function clearTable(){
   var table = document.getElementById("myTableData");
   table.innerHTML = "<thead> \
    <tr> \
        <th title='date file was created and site name of the page' scope='col' abbr='Filename'>File details</th> \
        <th title='mine if the file was created by you, imported otherwise' scope='col' abbr='Date'>Mine/imported</th> \
        <th title='whether the addon verifies that the contents are signed correctly' scope='col' abbr='Verified'>Verified</th> \
	<th title='the identity of the verifying notary server' scope='col' abbr='Verifier'>Verifier</th> \
	<th title='links to the html file on disk which is verified to come from the given site; raw shows the file in text' scope='col' abbr='Html'>View Html</th> \
	<th title='permanently remove this notarized file from your system' scope='col' abbr='Delete'> </th> \
    </tr>	\
    </thead> \
    <tbody> \
	</tbody>";
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
	
	//Not used at the moment; may be useful to sanity check modification date?
	let promise2 = OS.File.stat(entry.path);
	promise2.then(
	function onSuccess(info) { // |info| is an instance of |OS.File.Info|
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
	let imported = false;
	if (tlsn_files[i].name.match("-IMPORTED$")=="-IMPORTED"){ imported = true;}
	addNewRow(tlsn_files[i].name,imported,false,'tlsnotarygroup',"none");
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
	var tbody = document.getElementById("myTableData").getElementsByTagName('tbody')[0];
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
	row = tbody.rows[index];
	cell = row.cells[col];
	cell.innerHTML = newval;
}

function get_filename_from_basename(basename){
	var filename;
	if (basename.match("-IMPORTED$")=="-IMPORTED"){
		//note: in the absence of some kind of key signing,
		//there can only be an artificial distinction between
		//'my' files and imported ones
	    filename = basename.slice(0,-"-IMPORTED".length);
	}
	else {
	    filename = basename;
	}
	//filename now has no "IMPORTED" suffix, strip timestamp
	filename = filename.slice(20);
	//TODO check it looks like a real name, check it exists
	return OS.Path.join(tlsn_dir, basename, filename+'.tlsn');
}

function verifyEntry(basename){
	fn = get_filename_from_basename(basename);
	var path = OS.Path.join(tlsn_dir, basename, fn);	
	OS.File.read(path).then( function(imported_data){
	verify_tlsn(imported_data);
	}).then(function (){
	updateRow(basename,2,"<img src='chrome://tlsnotary/content/check.png' height='30' width='30' ></img> Valid");
	//console.log("Pubkey: "+ba2hex(notary_pubkey));
	updateRow(basename,3,"tlsnotarygroup"); //TODO: pretty print pubkey?
	var html_link = getTLSNdir()
	html_link.append(basename);
	html_link.append('html.html');
	block_urls.push(html_link.path);
	updateRow(basename,4,"<a href = 'file://" + html_link.path + "'> view  </a> ,\
	<a href = 'file://" + OS.Path.join(tlsn_dir,basename,"raw.txt") + "'> raw  </a>");
	}).catch( function(error){
	updateRow(basename,2,"<img src='chrome://tlsnotary/content/cross.png' height='30' width='30' ></img> Not verified: "+ error);
	updateRow(basename,3,"none");
	updateRow(basename,4,"none");
	});	
}
