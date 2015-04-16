//root directory of managed files
var tlsn_dir = getTLSNdir().path;
//array of existing files
var tlsn_files = []; //subdirectories of TLSNotary directory
//keys are directory names (which have fixed format 
//timestamp-server name), values are [tlsn OS.File object, boolean imported, table row index]:
var tdict ={}; 
var tloaded = false;

function importTLSNFiles(){
	main.verify();
	loadManager();
}

function tableRefresher(){
    if (!tloaded){
	setTimeout(tableRefresher,500);
	return;
    }
    //table is ready to be drawn
    for (var d in tdict){
	addNewRow(tdict[d][0],d,tdict[d][1],'tlsnotarygroup',"none");
	verifyEntry(d, tdict[d][0].path);
    }
    tloaded = false; //wait for next change
    setTimeout(tableRefresher, 500);
}

function doRename(t){
    var new_name = window.prompt("Enter a new name for the notarization file:");
    if (!new_name.endsWith(".tlsn")){
	new_name = new_name + ".tlsn";
    }
    console.log("t.id is: "+t.id);
    basename = OS.Path.basename(t.id);
    original_path = t.id;
    basedir = OS.Path.dirname(t.id);
    //rename file on disk
    OS.File.move(original_path,OS.Path.join(basedir,new_name));
    loadManager();
}

function doSave(t){
    filename = tdict[t.id][0].path;
    saveTLSNFile(filename);
    //no need to reload here
}

function addNewRow(fileEntry, dirname, imported,verified,verifier,html_link){
    let sname = dirname.substr(20);
    if (imported){ sname = sname.slice(0,-9);}
    tstamp = dirname.substr(0,19);
    var tbody = document.getElementById("myTableData").getElementsByTagName('tbody')[0];
    var rowCount = tbody.rows.length;
    var row = tbody.insertRow(rowCount); 
    tdict[dirname].push(rowCount); //sets the row index of this entry
    row.insertCell(0).innerHTML =  fileEntry.name.slice(0,-5) + 
    " <button id='" + fileEntry.path + "' style='float: right;' onclick='doRename(event.target)'> Rename </button>" +
    " <button id='" + dirname + "' style='float: right;' onclick='doSave(event.target)'> Export </button>";
    row.insertCell(1).innerHTML = tstamp + ' , ' + sname;
    if (!imported){
	row.insertCell(2).innerHTML = "mine";
    }
    else {
	row.insertCell(2).innerHTML = "imported";
	}
    if (verified){
	tbi = 'UNINITIALISED';
    }
    else {
        tbi = 'NO';
    }
    row.insertCell(3).innerHTML = tbi;
    row.insertCell(4).innerHTML = verifier;
    row.insertCell(5).innerHTML = html_link;
    button_html = "<button id='"+dirname+"' title='permanently remove this set of files from disk' onclick='deleteFile(event.target)'>Delete</button>";
    row.insertCell(6).innerHTML = button_html;
}


function deleteFile(basename){
	var r = confirm("This will remove the entire directory:"+basename.id+", including html. Are you sure?");
	if (r){
	    OS.File.removeDir(OS.Path.join(tlsn_dir,basename.id));
	    loadManager();
	}
}

function clearTable(){
   tdict = {}
   var table = document.getElementById("myTableData");
   table.innerHTML = "<thead> \
    <tr> \
	<th title='Name of notarization file; click Rename to change the name to something more descriptive' scope='col' abbr='File'>File</th> \
        <th title='date file was created and site name of the page' scope='col' abbr='Filename'>Creation date , server name</th> \
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
   clearTable(); //resets tdict also 
   tlsn_files = [];
   tloaded = false;
  let iterator = new OS.File.DirectoryIterator(tlsn_dir);
  let promise = iterator.forEach(
    function onEntry(entry) {
	if (!entry.isDir){
	    console.log("entry was not a directory, ignored:"+entry.path);
	}
	else {
	    tlsn_files.push(entry);	    
	}    
    }
  );
  
  promise.then(
    function onSuccess() {
      iterator.close();
      for (var i=0; i < tlsn_files.length; i++){
	let imported = false;
	if (tlsn_files[i].name.match("-IMPORTED$")=="-IMPORTED"){ 
	    imported = true;
	}
	var iterator2 = new OS.File.DirectoryIterator(tlsn_files[i].path);
	
	let promise2 = iterator2.forEach(
	function (entry2) {  
	    if (entry2.path.endsWith(".tlsn")){
		dirname = OS.Path.basename(OS.Path.dirname(entry2.path));
		tdict[dirname]=[entry2, imported];
		if (Object.keys(tdict).length == tlsn_files.length){
		    tloaded = true;
		}
	   }
	});
	promise2.then(
	   function() {
	    iterator2.close();
      } ,
    function (reason) {
      iterator2.close();
      throw reason;
    }
     );
    }
}, function onFailure(reason){
    iterator.close();
    throw reason;
    });
}

function updateRow(basename, col, newval){
	//TODO update multiple columns
	var tbody = document.getElementById("myTableData").getElementsByTagName('tbody')[0];
	var index = tdict[basename][2];
	row = tbody.rows[index];
	cell = row.cells[col];
	cell.innerHTML = newval;
}

function verifyEntry(basename, path){
	console.log("About to read a file with path: "+path);
	OS.File.read(path).then( function(imported_data){
	verify_tlsn(imported_data);
	}).then(function (){
	updateRow(basename,3,"<img src='chrome://tlsnotary/content/check.png' height='30' width='30' ></img> Valid");
	//console.log("Pubkey: "+ba2hex(notary_pubkey));
	updateRow(basename,4,"tlsnotarygroup"); //TODO: pretty print pubkey?
	var html_link = getTLSNdir();
	html_link.append(basename);
	html_link.append('html.html');
	block_urls.push(html_link.path);
	updateRow(basename,5,"<a href = 'file://" + html_link.path + "'> view  </a> ,\
	<a href = 'file://" + OS.Path.join(tlsn_dir,basename,"raw.txt") + "'> raw  </a>");
	}).catch( function(error){
	updateRow(basename,3,"<img src='chrome://tlsnotary/content/cross.png' height='30' width='30' ></img> Not verified: "+ error);
	updateRow(basename,4,"none");
	updateRow(basename,5,"none");
	});	
}

tableRefresher();