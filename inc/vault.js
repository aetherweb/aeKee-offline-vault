// Base level of iterations when generating encryption key
var encIts = 9753;

// Internal global vars
var saltthepass = SaltThePass;
var encryptingNow = false;

function validateEmail(val) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(val);
}

function cryptOverlay(switchon, msg)
{
	if (switchon)
	{
		document.getElementById('overlaymsg').innerHTML = msg;
		document.getElementById('overlay').style.display = 'table';
	}
	else
	{
		document.getElementById('overlay').style.display = 'none';
	}
}

var lastSysMsg = '';
function doSysMsg(msg)
{
	lastSysMsg = msg;
	try {
		var s = document.getElementById('sysmsgs');
		var date = dDateTime();
		s.innerHTML = date + ' ' + msg + '<br />\n' + s.innerHTML;
	} catch (err) {}
}

function dDateTime(timestamp)
{
	if (timestamp === null) { timestamp = timeStamp(); }
	var d = new Date(timestamp);
	return d.getFullYear()+'-'+pad(d.getMonth(),2)+'-'+pad(d.getDate(),2)+' '+pad(d.getHours(),2)+':'+pad(d.getMinutes(),2)+':'+pad(d.getSeconds(),2);
}

function cryptOverlayOff()
{
	cryptOverlay(false);
}

function pad(num, size)
{ 
	return ('000000000' + num).substr(-size); 
}

var md5 = function(value) {
    return CryptoJS.MD5(value).toString();
}

var ripemd160 = function(value) {
    return CryptoJS.RIPEMD160(value).toString();	
}

var sha256 = function(value) {
    return CryptoJS.SHA256(value).toString();	
}

var sha512 = function(value) {
    return CryptoJS.SHA512(value).toString();	
}

var sha3 = function(value) {
    return CryptoJS.SHA3(value).toString();	
}

var hmacsha3 = function(value) {
    return CryptoJS.HmacSHA3(value).toString();	
}


function aeDecrypt(data, pass, user)
{
	decry = '';
	try {
	// 1. Let's get the salt
  	salt = data.substring(0,32);
  	data = data.substring(32,data.length);

  	// 2. Let's make a decent pass and iv from their u and p
	pi = getPBKDF2PS(pass, user, salt);

	// 3. Decrypt with these values then
	cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: CryptoJS.enc.Hex.parse(data)});
	var decrypted = CryptoJS.AES.decrypt(cipherParams, CryptoJS.enc.Hex.parse(pi['pass']), { iv: CryptoJS.enc.Hex.parse(pi['iv']), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });

	decry = decrypted.toString(CryptoJS.enc.Utf8);
	} catch (err) {}
	return decry;	
}

function aeCrypt(data, pass, user)
{
	// this is crypt only, not hmac. it guarantees confidentiality
	// but not integrity. As such it's a little quicker and produces
	// smaller output than a full encrypt+mac
	encry = '';
	try {
	// 1. Let's make a salt
  	salt = CryptoJS.lib.WordArray.random(16).toString();
  	
  	// 2. Let's make a decent pass and iv from their u and p
	pi = getPBKDF2PS(pass, user, salt);
	
	// 3. Encrypt with these values then
	var encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(data), CryptoJS.enc.Hex.parse(pi['pass']), { iv: CryptoJS.enc.Hex.parse(pi['iv']), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
 });
	encry = salt+encrypted.ciphertext;
	} catch (err) {}
	return encry;
}

function getPBKDF2PS(pass, user, salt)
{
	pass = strToHexPad(pass + salt, 1024);
	user = strToHexPad(user, 256);
	its  = 1000;
	pbkd = CryptoJS.PBKDF2(CryptoJS.enc.Hex.parse(pass), CryptoJS.enc.Hex.parse(user), { keySize: 256/32, iterations: its, hasher:CryptoJS.algo.SHA256 });
	// split result into the _actual_ pass and salt for the encryption
	pbkd = pbkd.toString();
	var pi = [];
	pi['pass'] = strPad(pbkd.substring(0,pbkd.length/2),64);
	pi['iv']   = strPad(pbkd.substring(pbkd.length/2, pbkd.length),32);
	return pi;
}

function strPad(val, length)
{
	if (val.length>length) { val = val.substring(0,length); }
	if (val.length<length) 
	{
		while (val.length<length)
		{
			val = val + '0';
		}
		val = val.substring(0,length);
	}
	return val;	
}


function strToHexPad(val, length)
{
	val = toHex(val);
	if (val.length>length) { val = val.substring(0,length); }
	if (val.length<length) 
	{
		while(val.length<length)
		{
			val = val + '0';
		}
		val = val.substring(0,length);
	}
	return val;
}

function toHex(str) {
	var hex = '';
	for(var i=0;i<str.length;i++) {
		hex += ''+str.charCodeAt(i).toString(16);
	}
	return hex.toLowerCase();
}

function getAESkey(salt)
{
	var sp = document.getElementById('sp').value;
	var its     = encIts + getMpItMod(sp);
	var encpp   = CryptoJS.PBKDF2(sp, salt, { keySize: 512/32, iterations: its });
	return encpp.toString();
}

function getMpItMod(mp)
{
  var sum = 0;
  mp.split('').forEach(function(alphabet) {
      sum += alphabet.charCodeAt(0) - 64;
  });
  return sum;
}

function getKeKm(salt)
{
  var kekm   = {ke:'',km:''};
  if (theusername.length === 0) { theusername = genUsername(); }
  var encpp  = getAESkey(theusername+salt);
  var ke     = encpp.substring(0,encpp.length/2);
  var km     = encpp.substring(encpp.length/2,encpp.length);
  kekm['ke'] = CryptoJS.enc.Base64.parse(ke);
  kekm['km'] = CryptoJS.enc.Base64.parse(km);
  return kekm;
}

function genUsername()
{
    var rnd = CryptoJS.lib.WordArray.random(16).toString();
    return saltthepass.saltthepass('sha3', rnd, '', '').substring(0,30);
}

function encryptAndMac(message)
{
  err = 'unknown error';
  try {
    var ivl = 22;

    // generate a random iv
    var rnd     = CryptoJS.lib.WordArray.random(16).toString();
    var ivs = saltthepass.saltthepass('sha3', rnd, '', '').substring(0,ivl);
    var iv      = CryptoJS.enc.Base64.parse(ivs);

    // if at this point the value in 'theusername' is the master
    // password, change this now
    if (input_sp.value == theusername) { theusername = genUsername(); }

    // get the keys (passing the iv additionally as a salt modifier)
    var kekm = getKeKm(ivs);
   
    // encrypt this.
    var encrypted = CryptoJS.AES.encrypt(message, kekm['ke'], {
				iv: iv,
				mode: CryptoJS.mode.CBC,
				padding: CryptoJS.pad.Pkcs7
			});

    //Calculate HMAC of iv + encrypted...
    var HMAC = CryptoJS.HmacSHA256(ivs+encrypted.toString(), kekm['km']);

    // Final encrypted concatenation...
    return ivs + encrypted.toString() + HMAC.toString();
  } catch (err) {
	alert('Encryption failed '+err);
  }
  return '';
}

function decryptMacAnd(message)
{
  try {
    var ivl = 22; // initialisation vector string length
    var hml = 64; // hmac vector string length

    // determine the iv
    var ivs = message.substring(0,ivl);
    var iv  = CryptoJS.enc.Base64.parse(ivs);

    // we _need_ a username so if none is present in the encrypted
    // data, assume master passwd as theusername for legacy vault
    // data.
	if (theusername.length === 0) { theusername = input_sp.value; }

    // get the keys (passing the iv additionally as a salt modifier)
    var kekm = getKeKm(ivs);

    // strip and keep the hmac off the end
    var hmac = message.substring(message.length-hml, message.length);
    var message = message.substring(ivl,message.length-hml);

    //Calculate HMAC of iv + encrypted...
    var HMAC = CryptoJS.HmacSHA256(ivs+message, kekm['km']);

    if (hmac == HMAC.toString())
    {
      // continue to decrypt the message then!
      decrypted = CryptoJS.AES.decrypt(message, kekm['ke'], {
      		iv: iv,
		    mode: CryptoJS.mode.CBC, 
			padding: CryptoJS.pad.Pkcs7
      	});
      decrypted = decrypted.toString(CryptoJS.enc.Utf8);

	  return decrypted;  
    }
    else
    {
      throw 'HMAC verification failed.';
    }
  }
  catch (err) { doSysMsg(err); }
  return '';
}

var encUn = ''; var theusername = '';
document.addEventListener('DOMContentLoaded',function()
{
	// attach handlers //
	input_sp = document.getElementById("sp");
	input_sp.addEventListener("keyup", stp);
	input_sp.addEventListener("blur", function(){ uncry(input_sp); });

	input_d = document.getElementById("d");
	input_d.addEventListener("keyup", function(){ uns(input_d); });
	input_d.addEventListener("focus", function(){ dFocus(); });
	input_d.addEventListener("blur", function(){ dBlur(); });

	input_u = document.getElementById("u");
	input_u.addEventListener("keyup", stp);
	input_u.addEventListener("focus", function(){hideSugs();uFocus();});
	input_u.addEventListener("blur", uBlur);

	input_l = document.getElementById("l");
	input_l.addEventListener("change", stp);

	input_sfx = document.getElementById('sfx');
	input_sfx.addEventListener("keyup", stp);

	input_pwx = document.getElementById('pwx');
	input_pwx.addEventListener("keyup", stp);

	input_cmt = document.getElementById('cmt');
	input_cmt.addEventListener("keyup", function(){logChange(input_cmt);});

	input_snote = document.getElementById('snote');
	input_snote.addEventListener("keyup", function(){logChange(input_snote);});

	input_vaultdata = document.getElementById('vaultdata');
	input_vaultdata.addEventListener("blur", vaultDataChange);

	// vault data available in local storage?
	if (typeof(Storage) !== "undefined")
	{
		if (localStorage.vaultdata && localStorage.vaultdata.length>0)
		{
		   input_vaultdata.value = localStorage.vaultdata;
		   doSysMsg('Vaultdata loaded from browser local storage. Do not rely on this - copy, paste and save (and back up) your vaultdata!');
		}
	} 
	else
	{
	    // Sorry! No Web Storage support..
	}

	// attempt to load up vault data from content of textarea now...
	vaultDataChange();

	// End attach handlers
});


function vaultDataChange()
{
	try
	{
		// two possible vault formats - one includes a 'theusername'
		// value on line 1 and vault data line 2. This is the format
		// of a full aeKee vault. If creating a new vault or
		// 'theusername' is absent, the master password will be
		// used in its place for encrypt/decrypt.
		var lines = input_vaultdata.value.split(/\n/);
		if (lines.length == 2)
		{
			if (encUn != lines[1].trim())
			{
				encUn = lines[1].trim(); // loaded from the vault textarea
				// theusername comes from the first line in the vault data
				theusername = lines[0].trim();

				// reset all fields - data has changed
				clearAll();
			}
		}
		else
		{
			if (encUn != input_vaultdata.value)
			{
				theusername = '';
				encUn = input_vaultdata.value;

				// reset all fields - data has changed
				clearAll();
			}
		}
	}
	catch (err)
	{
	}
}


var timeOut; var clipTimeOut; var len = 19;
var uns_array = []; var marker = false;
var unsaved_changes = false;
var uns_loadtime_count = 0;

// Save last state for data collision avoidance
var oencUn = encUn;

// Browser determination for some functionality differences
// Opera 8.0+
var isOpera = (!!window.opr && !!opr.addons) || !!window.opera || navigator.userAgent.indexOf(' OPR/') >= 0;

// Firefox 1.0+
var isFirefox = typeof InstallTrigger !== 'undefined';
// Safari 3.0+ "[object HTMLElementConstructor]" 
var isSafari = /constructor/i.test(window.HTMLElement) || (function (p) { return p.toString() === "[object SafariRemoteNotification]"; })(!window['safari'] || safari.pushNotification);
// Internet Explorer 6-11
var isIE = /*@cc_on!@*/false || !!document.documentMode;
// Edge 20+
var isEdge = !isIE && !!window.StyleMedia;
// Chrome 1+
var isChrome = !!window.chrome && !!window.chrome.webstore;
// Blink engine detection
var isBlink = (isChrome || isOpera) && !!window.CSS;

if (!isIE)
{
	var btncp = document.getElementById('copyButton');
	btncp.disabled = false;
	btncp.className = 'bua';
	btncp.title = 'Copy auto-generated password to clipboard.';
}

// comparison to see if anything needs saving
var uns_array_serialized;
function stp()
{
  // Do not run this during encryption process
  if (encryptingNow)
  {
    // wait!
  }
  else
  {
    sp  = document.getElementById('sp').value;
    d   = document.getElementById('d').value;
    u   = document.getElementById('u').value;
    c   = document.getElementById('cmt').value;
    sfx = document.getElementById('sfx').value;
    n   = document.getElementById('snote').value;
    pwx = document.getElementById('pwx').value;
    t  = sp+d+u+sfx; st = '';
    if (t.length>0)
    {
      s  = saltthepass.saltthepass('sha3',sp,d,u+sfx);
      st = '';
      if (sp.length>0)
      {
        st = saltthepass.saltthepass('sha3',sp,'','');
        st = st.substring(0,5);
      }
    }
    else
    {
      s = '';
    }

    // length work...
    l  = document.getElementById("l");

    try
    {
      lv = l.options[l.selectedIndex].value;
    }
    catch (err)
    {
      // default
      lv = '19';
    }

    // no symbols in base pw?
	// s = s.replace(/[\W_]+/g,"");

    // if they added suffix then take that length off requested one?
    // NO!
   	//lv = lv - pwx.length;
	if ((lv === '0') || (lv>=6)) { len = lv; } else { len = 19; }

    try {
      s = s.substring(0,len);
    }
    catch (err) { }
   
    document.getElementById('copyTarget').value = s + pwx;
    document.getElementById('stShow').innerHTML = st + "("+getMpItMod(sp)+")";
    
    upUpBtn();
    clearTimeout(timeOut);
    clearTimeout(clipTimeOut);
    var minutes = 60;
    somethingChanged = true;
    timeOut = setTimeout(idleFunc, minutes*60*1000);
  }
}

var somethingChanged = false;
function datachangecheck()
{
	// only do this if we have valid data loaded and the d field
	// is not focused and the u field is not focused.
	// AND something has changed since we last did it
	if (marker && !dFocused && !uFocused && somethingChanged && !encryptingNow && !updatingUN)
	{
		somethingChanged = false;
	    d   = document.getElementById('d').value;
	    u   = document.getElementById('u').value;
	    if (
	    	(d.trim().length>0) 
	    	&&
	    	!islistall(d.trim())
	    	&& 
	    	(u.trim().length>0) 
	       )
	    {
		    c   = document.getElementById('cmt').value;
		    sfx = document.getElementById('sfx').value;
		    n   = document.getElementById('snote').value;
		    pwx = document.getElementById('pwx').value;

			l   = document.getElementById("l");
			lv  = l.options[l.selectedIndex].value;
			ls  = ''; //unused

		    // Save all current values in the local uns_array and if there is a change, make the save button red and set the global unsaved_changes variable. To do this we're going to have to find this item in the uns_arry or add it if it doesn't exist then make a comparison json and see. ONLY do this if there is some other value set than u and n - ANY thing.
		    if ((sfx.length+c.length+lv.length+n.length+pwx.length)>0)
		    {
			    updateUnsItem(d,u,sfx,c,lv,ls,n,pwx);

			    // update stringify version of this for later comparison to
			    // know if we need a save
			    uns_array_serialized_check = JSON.stringify(uns_array);

			    if (uns_array_serialized != uns_array_serialized_check)
			    {
			    	if (!unsaved_changes)
			    	{
				    	unsaved_changes = true;
				    	upUpBtn();
				    }
			    }
			    else
			    {
			    	if (unsaved_changes)
			    	{
				    	unsaved_changes = false;
				    	upUpBtn();
				    }
			    }
			}
		}
	}
	else
	{
		//if (pdatpdatingUN) { console.log('updating UN now'); }
	}
}

function logChange(obj)
{
	somethingChanged = true;
}

function updateUnsItem(d,u,x,c,l,s,n,pwx)
{
	if ((d.length > 0) && (u.length > 0) && !islistall(d))
	{
		var foundit = false;
		var count = 0;
       
		for (var key in uns_array)
		{ 
			count++;
			ud = uns_array[key][0];
	        //unss = uns_array[key][1].split("|||");
	        uu = uns_array[key][1]; // uname
	        uc = uns_array[key][2]; // comment
	        ul = uns_array[key][3]; // length
	        us = uns_array[key][4]; // unused
	        ux = uns_array[key][5]; // salt
	        un = uns_array[key][6]; // snote
	        up = uns_array[key][7]; // pwxtra
	        
	        if ((ud.trim().toLowerCase() == d.trim().toLowerCase()) 
	        	  && 
	        	(uu.trim().toLowerCase() == u.trim().toLowerCase())
	        	)
	        {
	        	foundit = true;
	        	if ((ul != l) || (us != s) || (ux != x) || (uc != c) || (un != n) || (up != pwx))
	        	{
	        		uns_array[key][1] = u.trim();
	        		uns_array[key][2] = c.trim();
	        		uns_array[key][3] = l.trim();
	        		uns_array[key][4] = s.trim();
	        		uns_array[key][5] = x.trim();
	        		uns_array[key][6] = n.trim();
	        		uns_array[key][7] = pwx.trim();
	        		//uns_array[key][8] = creation date
	        		uns_array[key][9] = timeStamp(); // last mod
	        	}
	        	break;
	        }
	    }
	    if (!foundit)
	    {
	    	count++;
	    	// new, add it
			uns_array.push([d, u, c, l, s, x, n, pwx, timeStamp(), timeStamp()]);
	    }

	    // update title count
	    updateTitleCount(count-1);
	}
}

function timeStamp()
{
	var ts;
	try 
	{
		ts = Date.now();
	}
	catch (err) {}
	if (!ts) 
	{
    	ts = new Date().getTime();
    }
    return ts;
}

function hideSugs()
{
	// Hide suggestions
	document.getElementById('unmatch').innerHTML = '';
}

function upUpBtn()
{
	svb = document.getElementById('updateButton');
	if (marker && unsaved_changes)
	{
		svb.disabled = false;
		svb.className = 'bua btnupda';
	}
	else
	{
		svb.disabled = true;
		svb.className = 'bua btnupd';
	}
}

function idleFunc()
{
	if (unsaved_changes)
	{
		// do something?
	}
	else
	{
	  document.getElementById("sp").value = '';
	  stp();
	  document.getElementById("stShow").value = ' ';
	  uncry_mphash = '';
	  document.getElementById('unmatch').innerHTML = '';
	  uns_array.length = 0;
	  updateTitleCount(0);
	}
}

function doLun(key)
{
  document.getElementById('d').value     = uns_array[key][0];
  document.getElementById('u').value     = uns_array[key][1];
  document.getElementById('cmt').value   = uns_array[key][2];
  document.getElementById('l').value     = uns_array[key][3];
  document.getElementById('sfx').value   = uns_array[key][5];
  document.getElementById('snote').value = uns_array[key][6];
  document.getElementById('pwx').value   = uns_array[key][7];

  // determine and display item creation / mod date
  var created  = uns_array[key][8];
  var modified = uns_array[key][9];

  doSysMsg("Item created: "+dDateTime(created)+" - Last modified: "+dDateTime(modified));

  // We could save the data of this event but if we do so it
  // appears to the user there's unsaved changes in the array
  // when in fact there are not.

  if (isFirefox)
  {
  	// ff still shows placeholders!
	document.getElementById('u').focus();
	document.getElementById('cmt').focus();
	document.getElementById('sfx').focus();
	document.activeElement.blur();
  }
  document.getElementById('unmatch').innerHTML = '';
  stp();
}

function delLun(d,u,i)
{
  var result = confirm("Delete " + d + ' ' + u + '?');
  if (result)
  {
    //Logic to delete the item
    document.getElementById('lun'+i).style.display = 'none';

    // del from local array
    for (var key in uns_array)
    {
		if ((uns_array[key][0].toLowerCase().trim() == d.toLowerCase().trim())
		   &&
		  (uns_array[key][1].toLowerCase().trim() == u.toLowerCase().trim()))
		{
			uns_array[key] = null;
			break;
		}
    }
    cleanUns();

    // update title count
    updateTitleCount(uns_array.length-1);

    // Save updated uns...
    saveUNS();
  }
}

function updateTitleCount(count)
{
	if (count > 0)
	{
		document.getElementById('vtitletitle').innerHTML = "AEKEE VAULT ("+count+")";
	}
	else
	{
		document.getElementById('vtitletitle').innerHTML = "AEKEE VAULT";
	}
}

var ilav = ''; var ilah = ''; 
function islistall(v)
{
	if (v == ilav) 
	{ 
		h = ilah; 
	}
	else
	{
		h = sha256('salt777'+v);
		ilav = v;
		ilah = h;
	}
	if (h == '41c704a59c4dc3ef0091d8263d996a091a2c1291c2442bdcf50ef815c6f9220b')
	{
		return true;
	}
	else
	{
		return false;
	}
}

var alunkeys = [];
function uns(obj)
{
	// display usernames matching this d,u or c value.
	// Only if there's been a recent check on logged 
	// in status!
	if (!encryptingNow)
	{
		und = document.getElementById('unmatch');
		while (und.firstChild) {
			und.removeChild(und.firstChild);
		}
		
		i = 1;
		if (obj.value.length > 2)
		{
	  		alunkeys = [];
	    	for (var key in uns_array) 
	    	{
	    		try 
	    		{
			    	//document.getElementById('snote').value += uns_array[key][0] +'\n';
			      	if  (
							(
								(uns_array[key][0].toLowerCase().indexOf(obj.value.toLowerCase())>=0)
								||
								(uns_array[key][1].toLowerCase().indexOf(obj.value.toLowerCase())>=0)
								||
								(uns_array[key][2].toLowerCase().indexOf(obj.value.toLowerCase())>=0)
								||
								islistall(obj.value)
							)
				            &&
				            (uns_array[key][0] != 'z.Z.z.Marker')
			         	)
				    {
				        // load link
				        //l = uns_array[key][1].split("|||");
				        lun   = uns_array[key][1].trim(); // username
				        c     = uns_array[key][2].trim(); // comment
				        lll   = uns_array[key][3].trim(); // length
				        ls    = uns_array[key][4].trim(); // spare
				        x     = uns_array[key][5].trim(); // x salt
				        snote = uns_array[key][6].trim(); // snote
				        px    = uns_array[key][7].trim(); // pwd suffix


				        if (c.length > 0) { c = ' (' + c + ')'; }

						addUn(und, i, key, uns_array[key][0], lun ,c);

				        i=i+1;
				    }
				}
				catch (err)
				{
					console.log(err);
				}
		    }
		}
		else
		{

		}

		// Now update the stp
		stp();
  	}
}

function addUn(p,i,k,d,lun,c)
{
	// the outer div
	var ndiv = document.createElement('div');
	ndiv.setAttribute("id", "lun"+i);
	ndiv.className = 'un';
	ndiv.innerHtml = '#';

	var load = document.createElement('a');
	load.setAttribute("href", '#');
	load.addEventListener("click", function(){ doLun(k);});
	load.innerHTML = d + ': ' + lun + c;

	var dele = document.createElement('button');
	dele.className = 'dl';
	dele.setAttribute('tabindex', '-1');
	dele.addEventListener('click', function(){delLun(d,lun,i);});
	dele.innerHTML = 'X';
	
	ndiv.appendChild(load);
	ndiv.appendChild(dele);

	p.appendChild(ndiv);
}

function doAlunKeys()
{
	for (var i in alunkeys)
	{
		document.getElementById('alun'+i).addEventListener("click", function(){ doLun('+alunkeys[i]+'); });
	}
}

var show = false; var autohide;
function showHide()
{
  clearTimeout(autohide);
  if (show)
  {
    document.getElementById('showButton').innerHTML = 'SHOW';
    document.getElementById('ctDiv').className = 'hide';
    document.getElementById('copyTarget').className = 'hide';
    show = false;
  }
  else
  {
    document.getElementById('showButton').innerHTML = 'HIDE';
    document.getElementById('ctDiv').className = 'show';
    document.getElementById('copyTarget').className = 'show';
    show = true;
    autohide = setTimeout(showHide, 10000);
  }
}

var updatingUN = false;
function updateUN()
{
	if (marker && !encryptingNow && !updatingUN)
	{
		updatingUN = true;
		saveUNS();
	}
}

var dosaveUNStimeout;
function saveUNS()
{
  cryptOverlay(true,'Encrypt->HMAC->Save');
  try { clearTimeout(dosaveUNStimeout); } catch (err) {}
  dosaveUNStimeout = setTimeout(doSaveUNS, 250);
}

function doSaveUNS()
{
  struns = ''; count = 0; addmark = true;
  for (var key in uns_array)
  {
    count = count + 1;
    if (uns_array[key][0] == 'z.Z.z.Marker') { addmark = false; }
  }
  if (addmark)
  {
  	uns_array[key+1] == ['z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker'];
  }
  encrypted = encryptAndMac(JSON.stringify(uns_array));

  // if the size of data isn't massively different from what
  // last loaded then go ahead sans confirm
  no_need_confirm = true;
  if ((uns_loadtime_count - uns_array.length) > 1)
  {
  	no_need_confirm = false;
  }

  if ((encrypted.length>0) && (no_need_confirm || confirm('About to save ' + (count-1) + ' records. OK?')))
  {
  	var d = encodeURIComponent(encrypted);
  	var o = encodeURIComponent(encUn);
 
	// update vaultdata textarea content. Take care if 'theusername' is the 
	// master password
	if (theusername == input_sp.value)
	{
		input_vaultdata.value = encrypted;
	}
	else
	{
		input_vaultdata.value = theusername + '\n' + encrypted;
	}

    // Attempt to store this in local storage if we can
    doLocalStorage('vaultdata',input_vaultdata.value);
    
    // update local crypt...
    encUn = encrypted;

    // We now have the problem of needing to update the mtime locally

    // update local un array comparison
    uns_array_serialized = JSON.stringify(uns_array);
	unsaved_changes = false;
	upUpBtn();

	// close off
	saveResponse();
  }
  else
  {
  	updatingUN = false;
  }
  cryptOverlay(false);
}

function doLocalStorage(name,val)
{
	if (typeof(Storage) !== "undefined") 
	{
	    localStorage.setItem(name, val);
	    doSysMsg('Vaultdata saved to browser local storage - it should re-load automatically when you refresh this page. Do not rely on this - copy, paste and save (and back up) your vaultdata!');
	} 
	else
	{
	    // Sorry! No Web Storage support..
	}
}

function saveResponse()
{
	// save response should have the new mtime in it!
	updatingUN = false;
	doSysMsg('Vault data updated below. You need to save it.');
}

var in_dfocus = false;
var dFocused  = false;
function dFocus()
{
	dFocused = true;
	if (isEdge || isIE)
	{
		// effin' IE ffs.
		clearFields();
	}
	else if (isFirefox) 
  	{
  		// clipboard clearing affects this in FF
  		clearFields();
  	}
  	else
  	{
		if (!in_dfocus)
		{
			in_dfocus = true;
			clearFields();
			in_dfocus = false;
		}
	}
}

function dBlur()
{
	dFocused = false;
}

var uFocused = false;
function uFocus()
{
	uFocused = true;
}

function uBlur()
{
	uFocused = false;
}

function clearAll()
{
  document.getElementById("sp").value = '';
  uncry_mphash = '';
  document.getElementById('stShow').innerHTML = '';
  uns_array.length = 0;
  updateTitleCount(0);
  clearFields();
}

function clearFields()
{
  document.getElementById("unmatch").innerHTML = '';
  document.getElementById("d").value = '';
  document.getElementById("u").value = '';
  document.getElementById("sfx").value = '';
  document.getElementById("l").value = '';
  document.getElementById("cmt").value = '';
  document.getElementById("snote").value = '';
  document.getElementById("pwx").value = '';
  document.getElementById("copyTarget").value = ' ';
  upUpBtn();
}

function copyToClipboard(elem)
{
    var succeed = false;
    try
    {
		if (!isIE)
		{
		    var isInput = elem.tagName === "INPUT" || elem.tagName === "TEXTAREA";
		    var origSelectionStart, origSelectionEnd;
		    if (isInput)
		    {
		        origSelectionStart = elem.selectionStart;
		        origSelectionEnd = elem.selectionEnd;
		    
			    var currentFocus = document.activeElement;
			    elem.focus();
			    elem.setSelectionRange(0, elem.value.length);
			    
			    // copy the selection
			    try {
			        succeed = document.execCommand("copy");
			    } catch(e) {
			        succeed = false;
			    }

			    // restore original focus
			    try { currentFocus.focus(); } catch (err) {}

		        // restore prior selection
		        elem.setSelectionRange(origSelectionStart, origSelectionEnd);
			}
		    // Wipe fields other than top one
		    clearFields();
		}
	}
	catch (err)
	{
		//console.log(err);
	}

    return succeed;
}

// keep track of last uncry mp in a strong but quick hash to avoid re-unenc when not needed
var uncry_mphash = '';
function uncry(obj)
{
  if (obj.value.length > 0)
  {
  	// Might need to update the vault data
  	vaultDataChange();

    // save a quick hash
    qh = saltthepass.saltthepass('sha3',obj.value,'','');
    if (qh == uncry_mphash)
    {
      // no change do not bother redecrypting
    }
    else
    {
      // save updated cry hash then
      uncry_mphash = qh;

      // reset marker
      marker = false;

      // Blank fields
      clearFields();

      // Erase local array data
      uns_array.length = 0;      

      // Reset clip timeout
      clearTimeout(clipTimeOut);

      // And do it...
      encryptingNow = true;
      cryptOverlay(true,'HMAC->Decrypt->Decode');
      setTimeout(doUncry, 250);
    } // end of re-decrypt phase
  }
  else
  {
    marker = false;
    uncry_mphash = '';
    uns_array.length = 0;
  }
}

function doUncry()
{
	uns_array.length = 0;
	try
	{
		if (encUn.length === 0)
		{
			marker = true;
			uns_array[0] = ['z.Z.z.Marker', 'z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker','z.Z.z.Marker'];
		}
		else
		{
			var decrypted = decryptMacAnd(encUn);

			// do we have a valid JSON string?
			try 
			{
			  uns_array = JSON.parse(decrypted);
			  cleanUns();
			} 
			catch (err) 
			{ 
				console.log(err); 
			}

			// OK?
			if ((uns_array.length > 0) && (decrypted.match(/z.Z.z.Marker/)))
			{
				// no we're looking good. Assume marker??
				marker = true;
			}
		}

		// update stringify version of this for later comparison to
		// know if we need a save  	  	
		uns_array_serialized = JSON.stringify(uns_array);

	}
	catch (err) 
	{
		console.log(err); 
	}

	// Hide the message
	encryptingNow = false;
	cryptOverlay(false);
	doSysMsg('Decrypting complete.');

	// Change padlock and title text
	if (marker)
	{
		updateTitleCount((uns_array.length-1).toString());
	}
	else
	{
		document.getElementById('vtitletitle').innerHTML = "AEKEE VAULT";
	}

	// record how many uns we just found
	uns_loadtime_count = uns_array.length;
}

function cleanUns()
{
	var newuns = []; var i = 0;
	for (var key in uns_array)
	{
		if (uns_array[key] != null)
		{
			newuns[i] = uns_array[key];
			i++;
		}
	}
	uns_array = newuns;
}

document.getElementById("copyButton").addEventListener("click", function() 
{
    copyToClipboard(document.getElementById("copyTarget"));
});
document.getElementById("updateButton").addEventListener("click", function() {
    updateUN();
});
document.getElementById("showButton").addEventListener("click", function() {
    showHide();
});
document.getElementById("clearButton").addEventListener("click", function() {
    clearFields();
});

window.addEventListener("beforeunload", function (e) 
{
	if (unsaved_changes)
	{
	    var confirmationMessage = 'You have made some changes in this vault. '
	                            + 'If you leave before saving, your changes will be lost.';

	    (e || window.event).returnValue = confirmationMessage; //Gecko + IE
	    return confirmationMessage; //Gecko + Webkit, Safari, Chrome etc.
	}
});

document.onkeydown = function(e) 
{
    if ((e.metaKey || e.ctrlKey) && e.key == 's') {
        // save, if we can?
        if (unsaved_changes)
        {
        	updateUN();	
        }
        return false;
    }
};

// start the auto save warning timer
setInterval(datachangecheck,500);
