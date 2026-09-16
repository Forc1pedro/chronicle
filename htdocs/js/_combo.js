/* Copyright (c) PixlCore.com, MIT License. https://github.com/jhuckaby/Cronicle */
/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;   /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = "";  /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s)    { return rstr2hex(rstr_md5(str2rstr_utf8(s))); }
function b64_md5(s)    { return rstr2b64(rstr_md5(str2rstr_utf8(s))); }
function any_md5(s, e) { return rstr2any(rstr_md5(str2rstr_utf8(s)), e); }
function hex_hmac_md5(k, d)
  { return rstr2hex(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_md5(k, d)
  { return rstr2b64(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_md5(k, d, e)
  { return rstr2any(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc").toLowerCase() == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of a raw string
 */
function rstr_md5(s)
{
  return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
}

/*
 * Calculate the HMAC-MD5, of a key and some data (raw strings)
 */
function rstr_hmac_md5(key, data)
{
  var bkey = rstr2binl(key);
  if(bkey.length > 16) bkey = binl_md5(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
  return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var i, j, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. All remainders are stored for later
   * use.
   */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
  var remainders = Array(full_length);
  for(j = 0; j < full_length; j++)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[j] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binl(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (i%32);
  return output;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */
function binl_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);
}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/**
 * JavaScript Object Oriented Programming Framework
 * Author: Joseph Huckaby
 **/

var Namespace = {
	// simple namespace support for classes
	create: function(path, container) {
		// create namespace for class
		if (!container) container = window;
		while (path.match(/^(\w+)\.?/)) {
			var key = RegExp.$1;
			path = path.replace(/^(\w+)\.?/, "");
			if (!container[key]) container[key] = {};
			container = container[key];
		}
		return container;
	},
	prep: function(name, container) {
		// prep namespace for new class
		if (!container) container = window;
		if (name.match(/^(.+)\.(\w+)$/)) {
			var path = RegExp.$1;
			name = RegExp.$2;
			container = Namespace.create(path, container);
		}
		return { container: container, name: name };
	}
};

var Class = {
	// simple class factory
	create: function(name, members) {
		// generate new class with optional namespace
		assert(name, "Must pass name to Class.create");
		if (!members) members = {};
		members.__name = name;
		members.__parent = null;

		var ns = Namespace.prep(name);
		var container = ns.container;
		name = ns.name;

		if (!members.__construct) members.__construct = function() {};
		container[name] = members.__construct;

		var static_members = members.__static;
		if (static_members) {
			for (var key in static_members) {
				container[name][key] = static_members[key];
			}
		}

		container[name].prototype = members;
	},
	subclass: function(parent, name, members) {
		// subclass an existing class
		assert(parent, "Must pass parent class to Class.subclass");
		assert(name, "Must pass name to Class.subclass");
		if (!members) members = {};
		members.__name = name;
		members.__parent = parent.prototype;

		var ns = Namespace.prep(name);
		var container = ns.container;
		var subname = ns.name;

		if (members.__construct) {
			// explicit subclass constructor
			container[subname] = members.__construct;
		}
		else {
			// inherit parent's constructor
			var code = parent.toString();
			var args = code.substring( code.indexOf("(")+1, code.indexOf(")") );
			var inner_code = code.substring( code.indexOf("{")+1, code.lastIndexOf("}") );
			eval('members.__construct = container[subname] = function ('+args+') {'+inner_code+'};');
		}

		var static_members = members.__static;
		if (static_members) {
			for (var key in static_members) {
				container[subname][key] = static_members[key];
			}
		}

		container[subname].prototype = {};
		for (var key in parent.prototype) container[subname].prototype[key] = parent.prototype[key];
		for (var key in members) container[subname].prototype[key] = members[key];
	},
	add: function(obj, members) {
		// add members to an existing class
		for (var key in members) obj.prototype[key] = members[key];
	},
	require: function() {
		// make sure classes are loaded
		for (var idx = 0, len = arguments.length; idx < len; idx++) {
			assert( !!eval('window.' + arguments[idx]) );
		}
		return true;
	}
};

Class.extend = Class.subclass;
Class.set = Class.add;

if (!window.assert) window.assert = function(fact, msg) {
	// very simple assert
	if (!fact) {
		console.log("ASSERT FAILURE: " + msg);
		return alert("ASSERT FAILED!  " + msg);
	}
	return fact;
}

/*
	JavaScript XML Library
	Plus a bunch of object utility functions
	
	Usage:
		var myxml = '<?xml version="1.0"?><Document>' + 
			'<Simple>Hello</Simple>' + 
			'<Node Key="Value">Content</Node>' + 
			'</Document>';
		var parser = new XML({ text: myxml, preserveAttributes: true });
		var tree = parser.getTree();
		tree.Simple = "Hello2";
		tree.Node._Attribs.Key = "Value2";
		tree.Node._Data = "Content2";
		tree.New = "I added this";
		alert( parser.compose() );
	
	Copyright (c) 2004 - 2007 Joseph Huckaby
*/

var indent_string = "\t";
var xml_header = '<?xml version="1.0"?>';
var sort_args = null;
var re_valid_tag_name  = /^\w[\w\-\:]*$/;

function XML(args) {
	// class constructor for XML parser class
	// pass in args hash or text to parse
	if (!args) args = '';
	if (isa_hash(args)) {
		for (var key in args) this[key] = args[key];
	}
	else this.text = args || '';
	
	this.tree = {};
	this.errors = [];
	this.piNodeList = [];
	this.dtdNodeList = [];
	this.documentNodeName = '';
	
	this.patTag.lastIndex = 0;
	if (this.text) this.parse();
}

XML.prototype.preserveAttributes = false;

XML.prototype.patTag = /([^<]*?)<([^>]+)>/g;
XML.prototype.patSpecialTag = /^\s*([\!\?])/;
XML.prototype.patPITag = /^\s*\?/;
XML.prototype.patCommentTag = /^\s*\!--/;
XML.prototype.patDTDTag = /^\s*\!DOCTYPE/;
XML.prototype.patCDATATag = /^\s*\!\s*\[\s*CDATA/;
XML.prototype.patStandardTag = /^\s*(\/?)([\w\-\:\.]+)\s*(.*)$/;
XML.prototype.patSelfClosing = /\/\s*$/;
XML.prototype.patAttrib = new RegExp("([\\w\\-\\:\\.]+)\\s*=\\s*([\\\"\\'])([^\\2]*?)\\2", "g");
XML.prototype.patPINode = /^\s*\?\s*([\w\-\:]+)\s*(.*)$/;
XML.prototype.patEndComment = /--$/;
XML.prototype.patNextClose = /([^>]*?)>/g;
XML.prototype.patExternalDTDNode = new RegExp("^\\s*\\!DOCTYPE\\s+([\\w\\-\\:]+)\\s+(SYSTEM|PUBLIC)\\s+\\\"([^\\\"]+)\\\"");
XML.prototype.patInlineDTDNode = /^\s*\!DOCTYPE\s+([\w\-\:]+)\s+\[/;
XML.prototype.patEndDTD = /\]$/;
XML.prototype.patDTDNode = /^\s*\!DOCTYPE\s+([\w\-\:]+)\s+\[(.*)\]/;
XML.prototype.patEndCDATA = /\]\]$/;
XML.prototype.patCDATANode = /^\s*\!\s*\[\s*CDATA\s*\[(.*)\]\]/;

XML.prototype.attribsKey = '_Attribs';
XML.prototype.dataKey = '_Data';

XML.prototype.parse = function(branch, name) {
	// parse text into XML tree, recurse for nested nodes
	if (!branch) branch = this.tree;
	if (!name) name = null;
	var foundClosing = false;
	var matches = null;
	
	// match each tag, plus preceding text
	while ( matches = this.patTag.exec(this.text) ) {
		var before = matches[1];
		var tag = matches[2];
		
		// text leading up to tag = content of parent node
		if (before.match(/\S/)) {
			if (typeof(branch[this.dataKey]) != 'undefined') branch[this.dataKey] += ' '; else branch[this.dataKey] = '';
			branch[this.dataKey] += trim(decode_entities(before));
		}
		
		// parse based on tag type
		if (tag.match(this.patSpecialTag)) {
			// special tag
			if (tag.match(this.patPITag)) tag = this.parsePINode(tag);
			else if (tag.match(this.patCommentTag)) tag = this.parseCommentNode(tag);
			else if (tag.match(this.patDTDTag)) tag = this.parseDTDNode(tag);
			else if (tag.match(this.patCDATATag)) {
				tag = this.parseCDATANode(tag);
				if (typeof(branch[this.dataKey]) != 'undefined') branch[this.dataKey] += ' '; else branch[this.dataKey] = '';
				branch[this.dataKey] += trim(decode_entities(tag));
			} // cdata
			else {
				this.throwParseError( "Malformed special tag", tag );
				break;
			} // error
			
			if (tag == null) break;
			continue;
		} // special tag
		else {
			// Tag is standard, so parse name and attributes (if any)
			var matches = tag.match(this.patStandardTag);
			if (!matches) {
				this.throwParseError( "Malformed tag", tag );
				break;
			}
			
			var closing = matches[1];
			var nodeName = matches[2];
			var attribsRaw = matches[3];
			
			// If this is a closing tag, make sure it matches its opening tag
			if (closing) {
				if (nodeName == (name || '')) {
					foundClosing = 1;
					break;
				}
				else {
					this.throwParseError( "Mismatched closing tag (expected </" + name + ">)", tag );
					break;
				}
			} // closing tag
			else {
				// Not a closing tag, so parse attributes into hash.  If tag
				// is self-closing, no recursive parsing is needed.
				var selfClosing = !!attribsRaw.match(this.patSelfClosing);
				var leaf = {};
				var attribs = leaf;
				
				// preserve attributes means they go into a sub-hash named "_Attribs"
				// the XML composer honors this for restoring the tree back into XML
				if (this.preserveAttributes) {
					leaf[this.attribsKey] = {};
					attribs = leaf[this.attribsKey];
				}
				
				// parse attributes
				this.patAttrib.lastIndex = 0;
				while ( matches = this.patAttrib.exec(attribsRaw) ) {
					attribs[ matches[1] ] = decode_entities( matches[3] );
				} // foreach attrib
				
				// if no attribs found, but we created the _Attribs subhash, clean it up now
				if (this.preserveAttributes && !num_keys(attribs)) {
					delete leaf[this.attribsKey];
				}
				
				// Recurse for nested nodes
				if (!selfClosing) {
					this.parse( leaf, nodeName );
					if (this.error()) break;
				}
				
				// Compress into simple node if text only
				var num_leaf_keys = num_keys(leaf);
				if ((typeof(leaf[this.dataKey]) != 'undefined') && (num_leaf_keys == 1)) {
					leaf = leaf[this.dataKey];
				}
				else if (!num_leaf_keys) {
					leaf = '';
				}
				
				// Add leaf to parent branch
				if (typeof(branch[nodeName]) != 'undefined') {
					if (isa_array(branch[nodeName])) {
						array_push( branch[nodeName], leaf );
					}
					else {
						var temp = branch[nodeName];
						branch[nodeName] = [ temp, leaf ];
					}
				}
				else {
					branch[nodeName] = leaf;
				}
				
				if (this.error() || (branch == this.tree)) break;
			} // not closing
		} // standard tag
	} // main reg exp
	
	// Make sure we found the closing tag
	if (name && !foundClosing) {
		this.throwParseError( "Missing closing tag (expected </" + name + ">)", name );
	}
	
	// If we are the master node, finish parsing and setup our doc node
	if (branch == this.tree) {
		if (typeof(this.tree[this.dataKey]) != 'undefined') delete this.tree[this.dataKey];
		
		if (num_keys(this.tree) > 1) {
			this.throwParseError( 'Only one top-level node is allowed in document', first_key(this.tree) );
			return;
		}

		this.documentNodeName = first_key(this.tree);
		if (this.documentNodeName) {
			this.tree = this.tree[this.documentNodeName];
		}
	}
};

XML.prototype.throwParseError = function(key, tag) {
	// log error and locate current line number in source XML document
	var parsedSource = this.text.substring(0, this.patTag.lastIndex);
	var eolMatch = parsedSource.match(/\n/g);
	var lineNum = (eolMatch ? eolMatch.length : 0) + 1;
	lineNum -= tag.match(/\n/) ? tag.match(/\n/g).length : 0;
	
	array_push(this.errors, {
		type: 'Parse',
		key: key,
		text: '<' + tag + '>',
		line: lineNum
	});
};

XML.prototype.error = function() {
	// return number of errors
	return this.errors.length;
};

XML.prototype.getError = function(error) {
	// get formatted error
	var text = '';
	if (!error) return '';

	text = (error.type || 'General') + ' Error';
	if (error.code) text += ' ' + error.code;
	text += ': ' + error.key;
	
	if (error.line) text += ' on line ' + error.line;
	if (error.text) text += ': ' + error.text;

	return text;
};

XML.prototype.getLastError = function() {
	// Get most recently thrown error in plain text format
	if (!this.error()) return '';
	return this.getError( this.errors[this.errors.length - 1] );
};

XML.prototype.parsePINode = function(tag) {
	// Parse Processor Instruction Node, e.g. <?xml version="1.0"?>
	if (!tag.match(this.patPINode)) {
		this.throwParseError( "Malformed processor instruction", tag );
		return null;
	}
	
	array_push( this.piNodeList, tag );
	return tag;
};

XML.prototype.parseCommentNode = function(tag) {
	// Parse Comment Node, e.g. <!-- hello -->
	var matches = null;
	this.patNextClose.lastIndex = this.patTag.lastIndex;
	
	while (!tag.match(this.patEndComment)) {
		if (matches = this.patNextClose.exec(this.text)) {
			tag += '>' + matches[1];
		}
		else {
			this.throwParseError( "Unclosed comment tag", tag );
			return null;
		}
	}
	
	this.patTag.lastIndex = this.patNextClose.lastIndex;
	return tag;
};

XML.prototype.parseDTDNode = function(tag) {
	// Parse Document Type Descriptor Node, e.g. <!DOCTYPE ... >
	var matches = null;
	
	if (tag.match(this.patExternalDTDNode)) {
		// tag is external, and thus self-closing
		array_push( this.dtdNodeList, tag );
	}
	else if (tag.match(this.patInlineDTDNode)) {
		// Tag is inline, so check for nested nodes.
		this.patNextClose.lastIndex = this.patTag.lastIndex;
		
		while (!tag.match(this.patEndDTD)) {
			if (matches = this.patNextClose.exec(this.text)) {
				tag += '>' + matches[1];
			}
			else {
				this.throwParseError( "Unclosed DTD tag", tag );
				return null;
			}
		}
		
		this.patTag.lastIndex = this.patNextClose.lastIndex;
		
		// Make sure complete tag is well-formed, and push onto DTD stack.
		if (tag.match(this.patDTDNode)) {
			array_push( this.dtdNodeList, tag );
		}
		else {
			this.throwParseError( "Malformed DTD tag", tag );
			return null;
		}
	}
	else {
		this.throwParseError( "Malformed DTD tag", tag );
		return null;
	}
	
	return tag;
};

XML.prototype.parseCDATANode = function(tag) {
	// Parse CDATA Node, e.g. <![CDATA[Brooks & Shields]]>
	var matches = null;
	this.patNextClose.lastIndex = this.patTag.lastIndex;
	
	while (!tag.match(this.patEndCDATA)) {
		if (matches = this.patNextClose.exec(this.text)) {
			tag += '>' + matches[1];
		}
		else {
			this.throwParseError( "Unclosed CDATA tag", tag );
			return null;
		}
	}
	
	this.patTag.lastIndex = this.patNextClose.lastIndex;
	
	if (matches = tag.match(this.patCDATANode)) {
		return matches[1];
	}
	else {
		this.throwParseError( "Malformed CDATA tag", tag );
		return null;
	}
};

XML.prototype.getTree = function() {
	// get reference to parsed XML tree
	return this.tree;
};

XML.prototype.compose = function() {
	// compose tree back into XML
	var raw = compose_xml( this.documentNodeName, this.tree );
	var body = raw.substring( raw.indexOf("\n") + 1, raw.length );
	var xml = '';
	
	if (this.piNodeList.length) {
		for (var idx = 0, len = this.piNodeList.length; idx < len; idx++) {
			xml += '<' + this.piNodeList[idx] + '>' + "\n";
		}
	}
	else {
		xml += xml_header + "\n";
	}
	
	if (this.dtdNodeList.length) {
		for (var idx = 0, len = this.dtdNodeList.length; idx < len; idx++) {
			xml += '<' + this.dtdNodeList[idx] + '>' + "\n";
		}
	}
	
	xml += body;
	return xml;
};

//
// Static Utility Functions:
//

function parse_xml(text) {
	// turn text into XML tree quickly
	var parser = new XML(text);
	return parser.error() ? parser.getLastError() : parser.getTree();
}

function trim(text) {
	// strip whitespace from beginning and end of string
	if (text == null) return '';
	
	if (text && text.replace) {
		text = text.replace(/^\s+/, "");
		text = text.replace(/\s+$/, "");
	}
	
	return text;
}

function encode_entities(text) {
	// Simple entitize function for composing XML
	if (text == null) return '';

	if (text && text.replace) {
		text = text.replace(/\&/g, "&amp;"); // MUST BE FIRST
		text = text.replace(/</g, "&lt;");
		text = text.replace(/>/g, "&gt;");
	}

	return text;
}

function encode_attrib_entities(text) {
	// Simple entitize function for composing XML attributes
	if (text == null) return '';

	if (text && text.replace) {
		text = text.replace(/\&/g, "&amp;"); // MUST BE FIRST
		text = text.replace(/</g, "&lt;");
		text = text.replace(/>/g, "&gt;");
		text = text.replace(/\"/g, "&quot;");
		text = text.replace(/\'/g, "&apos;");
	}

	return text;
}

function decode_entities(text) {
	// Decode XML entities into raw ASCII
	if (text == null) return '';

	if (text && text.replace) {
		text = text.replace(/\&lt\;/g, "<");
		text = text.replace(/\&gt\;/g, ">");
		text = text.replace(/\&quot\;/g, '"');
		text = text.replace(/\&apos\;/g, "'");
		text = text.replace(/\&amp\;/g, "&"); // MUST BE LAST
	}

	return text;
}

function compose_xml(name, node, indent) {
	// Compose node into XML including attributes
	// Recurse for child nodes
	var xml = "";
	
	// If this is the root node, set the indent to 0
	// and setup the XML header (PI node)
	if (!indent) {
		indent = 0;
		xml = xml_header + "\n";
	}
	
	// Setup the indent text
	var indent_text = "";
	for (var k = 0; k < indent; k++) indent_text += indent_string;

	if ((typeof(node) == 'object') && (node != null)) {
		// node is object -- now see if it is an array or hash
		if (!node.length) { // what about zero-length array?
			// node is hash
			xml += indent_text + "<" + name;

			var num_keys = 0;
			var has_attribs = 0;
			for (var key in node) num_keys++; // there must be a better way...

			if (node["_Attribs"]) {
				has_attribs = 1;
				var sorted_keys = hash_keys_to_array(node["_Attribs"]).sort();
				for (var idx = 0, len = sorted_keys.length; idx < len; idx++) {
					var key = sorted_keys[idx];
					xml += " " + key + "=\"" + encode_attrib_entities(node["_Attribs"][key]) + "\"";
				}
			} // has attribs

			if (num_keys > has_attribs) {
				// has child elements
				xml += ">";

				if (node["_Data"]) {
					// simple text child node
					xml += encode_entities(node["_Data"]) + "</" + name + ">\n";
				} // just text
				else {
					xml += "\n";
					
					var sorted_keys = hash_keys_to_array(node).sort();
					for (var idx = 0, len = sorted_keys.length; idx < len; idx++) {
						var key = sorted_keys[idx];					
						if ((key != "_Attribs") && key.match(re_valid_tag_name)) {
							// recurse for node, with incremented indent value
							xml += compose_xml( key, node[key], indent + 1 );
						} // not _Attribs key
					} // foreach key

					xml += indent_text + "</" + name + ">\n";
				} // real children
			}
			else {
				// no child elements, so self-close
				xml += "/>\n";
			}
		} // standard node
		else {
			// node is array
			for (var idx = 0; idx < node.length; idx++) {
				// recurse for node in array with same indent
				xml += compose_xml( name, node[idx], indent );
			}
		} // array of nodes
	} // complex node
	else {
		// node is simple string
		xml += indent_text + "<" + name + ">" + encode_entities(node) + "</" + name + ">\n";
	} // simple text node

	return xml;
}

function find_object(obj, criteria) {
	// walk array looking for nested object matching criteria object
	if (isa_hash(obj)) obj = hash_values_to_array(obj);
	
	var criteria_length = 0;
	for (var a in criteria) criteria_length++;
	obj = always_array(obj);
	
	for (var a = 0; a < obj.length; a++) {
		var matches = 0;
		
		for (var b in criteria) {
			if (obj[a][b] && (obj[a][b] == criteria[b])) matches++;
			else if (obj[a]["_Attribs"] && obj[a]["_Attribs"][b] && (obj[a]["_Attribs"][b] == criteria[b])) matches++;
		}
		if (matches >= criteria_length) return obj[a];
	}
	return null;
}

function find_objects(obj, criteria) {
	// walk array gathering all nested objects that match criteria object
	if (isa_hash(obj)) obj = hash_values_to_array(obj);
	
	var objs = new Array();
	var criteria_length = 0;
	for (var a in criteria) criteria_length++;
	obj = always_array(obj);
	
	for (var a = 0; a < obj.length; a++) {
		var matches = 0;
		for (var b in criteria) {
			if (obj[a][b] && obj[a][b] == criteria[b]) matches++;
			else if (obj[a]["_Attribs"] && obj[a]["_Attribs"][b] && (obj[a]["_Attribs"][b] == criteria[b])) matches++;
		}
		if (matches >= criteria_length) array_push( objs, obj[a] );
	}
	
	return objs;
}

function find_object_idx(obj, criteria) {
	// walk array looking for nested object matching criteria object
	// return index in outer array, not object itself
	if (isa_hash(obj)) obj = hash_values_to_array(obj);
	
	var criteria_length = 0;
	for (var a in criteria) criteria_length++;
	obj = always_array(obj);
	
	for (var idx = 0; idx < obj.length; idx++) {
		var matches = 0;
		
		for (var b in criteria) {
			if (obj[idx][b] && (obj[idx][b] == criteria[b])) matches++;
			else if (obj[idx]["_Attribs"] && obj[idx]["_Attribs"][b] && (obj[idx]["_Attribs"][b] == criteria[b])) matches++;
		}
		if (matches >= criteria_length) return idx;
	}
	return -1;
}

function delete_object(obj, criteria) {
	// walk array looking for nested object matching criteria object
	// delete first object found
	var idx = find_object_idx(obj, criteria);

	if (idx > -1) {
		obj.splice( idx, 1 );
		return true;
	}
	return false;
}

function delete_objects(obj, criteria) {
	// delete all objects in obj array matching criteria
	while (delete_object(obj, criteria)) ;
}

function always_array(obj, key) {
	// if object is not array, return array containing object
	// if key is passed, work like XMLalwaysarray() instead
	// apparently MSIE has weird issues with obj = always_array(obj);
	
	if (key) {
		if ((typeof(obj[key]) != 'object') || (typeof(obj[key].length) == 'undefined')) {
			var temp = obj[key];
			delete obj[key];
			obj[key] = new Array();
			obj[key][0] = temp;
		}
		return null;
	}
	else {
		if ((typeof(obj) != 'object') || (typeof(obj.length) == 'undefined')) { return [ obj ]; }
		else return obj;
	}
}

function hash_keys_to_array(hash) {
	// convert hash keys to array (discard values)
	var array = [];
	for (var key in hash) array_push(array, key);
	return array;
}

function hash_values_to_array(hash) {
	// convert hash values to array (discard keys)
	var arr = [];
	for (var key in hash) arr.push( hash[key] );
	return arr;
};

function merge_objects(a, b) {
	// merge keys from a and b into c and return c
	// b has precedence over a
	if (!a) a = {};
	if (!b) b = {};
	var c = {};

	// also handle serialized objects for a and b
	if (typeof(a) != 'object') eval( "a = " + a );
	if (typeof(b) != 'object') eval( "b = " + b );

	for (var key in a) c[key] = a[key];
	for (var key in b) c[key] = b[key];

	return c;
}

function copy_object(obj) {
	// return copy of object (NOT DEEP)
	var new_obj = {};
	for (var key in obj) new_obj[key] = obj[key];
	return new_obj;
}

function deep_copy_object(obj) {
	// recursively copy object and nested objects
	// return new object
	return JSON.parse( JSON.stringify(obj) );
}

function copy_into_object(a, b) {
	// copy b in to a (NOT DEEP)
	// no return value
	for (var key in b) a[key] = b[key];
}

function num_keys(hash) {
	// count the number of keys in a hash
	var count = 0;
	for (var a in hash) count++;
	return count;
}

function reverse_hash(a) {
	// reverse hash keys/values
	var c = {};
	for (var key in a) {
		c[ a[key] ] = key;
	}
	return c;
}

function lookup_path(path, obj) {
	// walk through object tree, psuedo-XPath-style
	// supports arrays as well as objects
	// return final object or value
	// always start query with a slash, i.e. /something/or/other
	path = path.replace(/\/$/, ""); // strip trailing slash
	
	while (/\/[^\/]+/.test(path) && (typeof(obj) == 'object')) {
		// find first slash and strip everything up to and including it
		var slash = path.indexOf('/');
		path = path.substring( slash + 1 );
		
		// find next slash (or end of string) and get branch name
		slash = path.indexOf('/');
		if (slash == -1) slash = path.length;
		var name = path.substring(0, slash);

		// advance obj using branch
		if (typeof(obj.length) == 'undefined') {
			// obj is hash
			if (typeof(obj[name]) != 'undefined') obj = obj[name];
			else return null;
		}
		else {
			// obj is array
			var idx = parseInt(name, 10);
			if (isNaN(idx)) return null;
			if (typeof(obj[idx]) != 'undefined') obj = obj[idx];
			else return null;
		}

	} // while path contains branch

	return obj;
}

function isa_hash(arg) {
	// determine if arg is a hash
	return( !!arg && (typeof(arg) == 'object') && (typeof(arg.length) == 'undefined') );
}

function isa_array(arg) {
	// determine if arg is an array or is array-like
	return( !!arg && (typeof(arg) == 'object') && (typeof(arg.length) != 'undefined') );
}

function first_key(hash) {
	// return first key from hash (unordered)
	for (var key in hash) return key;
	return null; // no keys in hash
}

function array_push(array, item) {
	// push item onto end of array
	array[ array.length ] = item;
}

function rand_array(arr) {
	// return random element from array
	return arr[ parseInt(Math.random() * arr.length, 10) ];
}

function find_in_array(arr, elem) {
	// return true if elem is found in arr, false otherwise
	for (var idx = 0, len = arr.length; idx < len; idx++) {
		if (arr[idx] == elem) return true;
	}
	return false;
}

////
// Joe's Misc JavaScript Tools
// Copyright (c) 2004 - 2015 Joseph Huckaby
// Released under the MIT License
////

var months = [
	[ 1, 'January' ], [ 2, 'February' ], [ 3, 'March' ], [ 4, 'April' ],
	[ 5, 'May' ], [ 6, 'June' ], [ 7, 'July' ], [ 8, 'August' ],
	[ 9, 'September' ], [ 10, 'October' ], [ 11, 'November' ],
	[ 12, 'December' ]
];

function parse_query_string(url) {
	// parse query string into key/value pairs and return as object
	var query = {}; 
	url.replace(/^.*\?/, '').replace(/([^\=]+)\=([^\&]*)\&?/g, function(match, key, value) {
		query[key] = decodeURIComponent(value);
		if (query[key].match(/^\-?\d+$/)) query[key] = parseInt(query[key]);
		else if (query[key].match(/^\-?\d*\.\d+$/)) query[key] = parseFloat(query[key]);
		return ''; 
	} );
	return query; 
};

function compose_query_string(queryObj) {
	// compose key/value pairs into query string
	// supports duplicate keys (i.e. arrays)
	var qs = '';
	for (var key in queryObj) {
		var values = always_array(queryObj[key]);
		for (var idx = 0, len = values.length; idx < len; idx++) {
			qs += (qs.length ? '&' : '?') + escape(key) + '=' + escape(values[idx]);
		}
	}
	return qs;
}

function get_text_from_bytes(bytes, precision) {
	// convert raw bytes to english-readable format
	// set precision to 1 for ints, 10 for 1 decimal point (default), 100 for 2, etc.
	bytes = Math.floor(bytes);
	if (!precision) precision = 10;
	
	if (bytes >= 1024) {
		bytes = Math.floor( (bytes / 1024) * precision ) / precision;
		if (bytes >= 1024) {
			bytes = Math.floor( (bytes / 1024) * precision ) / precision;
			if (bytes >= 1024) {
				bytes = Math.floor( (bytes / 1024) * precision ) / precision;
				if (bytes >= 1024) {
					bytes = Math.floor( (bytes / 1024) * precision ) / precision;
					return bytes + ' TB';
				} 
				else return bytes + ' GB';
			} 
			else return bytes + ' MB';
		}
		else return bytes + ' K';
	}
	else return bytes + pluralize(' byte', bytes);
};

function get_bytes_from_text(text) {
	// parse text into raw bytes, e.g. "1 K" --> 1024
	if (text.toString().match(/^\d+$/)) return parseInt(text); // already in bytes
	var multipliers = {
		b: 1,
		k: 1024,
		m: 1024 * 1024,
		g: 1024 * 1024 * 1024,
		t: 1024 * 1024 * 1024 * 1024
	};
	var bytes = 0;
	text = text.toString().replace(/([\d\.]+)\s*(\w)\w*\s*/g, function(m_all, m_g1, m_g2) {
		var mult = multipliers[ m_g2.toLowerCase() ] || 0;
		bytes += (parseFloat(m_g1) * mult); 
		return '';
	} );
	return Math.floor(bytes);
};

function ucfirst(text) {
	// capitalize first character only, lower-case rest
	return text.substring(0, 1).toUpperCase() + text.substring(1, text.length).toLowerCase();
}

function commify(number) {
	// add commas to integer, like 1,234,567
	if (!number) number = 0;

	number = '' + number;
	if (number.length > 3) {
		var mod = number.length % 3;
		var output = (mod > 0 ? (number.substring(0,mod)) : '');
		for (i=0 ; i < Math.floor(number.length / 3); i++) {
			if ((mod == 0) && (i == 0))
				output += number.substring(mod+ 3 * i, mod + 3 * i + 3);
			else
				output+= ',' + number.substring(mod + 3 * i, mod + 3 * i + 3);
		}
		return (output);
	}
	else return number;
}

function short_float(value, places) {
	// Shorten floating-point decimal to N places max
	if (!places) places = 2;
	var mult = Math.pow(10, places);
	return( Math.floor(parseFloat(value || 0) * mult) / mult );
}

function pct(count, max, floor) {
	// Return formatted percentage given a number along a sliding scale from 0 to 'max'
	var pct = (count * 100) / (max || 1);
	if (!pct.toString().match(/^\d+(\.\d+)?$/)) { pct = 0; }
	return '' + (floor ? Math.floor(pct) : short_float(pct)) + '%';
};

function get_text_from_seconds(sec, abbrev, no_secondary) {
	// convert raw seconds to human-readable relative time
	var neg = '';
	sec = parseInt(sec, 10);
	if (sec<0) { sec =- sec; neg = '-'; }
	
	var p_text = abbrev ? "sec" : "second";
	var p_amt = sec;
	var s_text = "";
	var s_amt = 0;
	
	if (sec > 59) {
		var min = parseInt(sec / 60, 10);
		sec = sec % 60; 
		s_text = abbrev ? "sec" : "second"; 
		s_amt = sec; 
		p_text = abbrev ? "min" : "minute"; 
		p_amt = min;
		
		if (min > 59) {
			var hour = parseInt(min / 60, 10);
			min = min % 60; 
			s_text = abbrev ? "min" : "minute"; 
			s_amt = min; 
			p_text = abbrev ? "hr" : "hour"; 
			p_amt = hour;
			
			if (hour > 23) {
				var day = parseInt(hour / 24, 10);
				hour = hour % 24; 
				s_text = abbrev ? "hr" : "hour"; 
				s_amt = hour; 
				p_text = "day"; 
				p_amt = day;
				
				if (day > 29) {
					var month = parseInt(day / 30, 10);
					s_text = "day"; 
					s_amt = day % 30; 
					p_text = abbrev ? "mon" : "month"; 
					p_amt = month;
					
					if (day >= 365) {
						var year = parseInt(day / 365, 10);
						month = month % 12; 
						s_text = abbrev ? "mon" : "month"; 
						s_amt = month; 
						p_text = abbrev ? "yr" : "year"; 
						p_amt = year;
					} // day>=365
				} // day>29
			} // hour>23
		} // min>59
	} // sec>59
	
	var text = p_amt + "&nbsp;" + p_text;
	if ((p_amt != 1) && !abbrev) text += "s";
	if (s_amt && !no_secondary) {
		text += ", " + s_amt + "&nbsp;" + s_text;
		if ((s_amt != 1) && !abbrev) text += "s";
	}
	
	return(neg + text);
}

function get_text_from_seconds_round(sec, abbrev) {
	// convert raw seconds to human-readable relative time
	// round to nearest instead of floor
	var neg = '';
	sec = Math.round(sec);
	if (sec < 0) { sec =- sec; neg = '-'; }
	
	var text = abbrev ? "sec" : "second";
	var amt = sec;
	
	if (sec > 59) {
		var min = Math.round(sec / 60);
		text = abbrev ? "min" : "minute"; 
		amt = min;
		
		if (min > 59) {
			var hour = Math.round(min / 60);
			text = abbrev ? "hr" : "hour"; 
			amt = hour;
			
			if (hour > 23) {
				var day = Math.round(hour / 24);
				text = "day"; 
				amt = day;
			} // hour>23
		} // min>59
	} // sec>59
	
	var text = "" + amt + " " + text;
	if ((amt != 1) && !abbrev) text += "s";
	
	return(neg + text);
};

function get_seconds_from_text(text) {
	// parse text into raw seconds, e.g. "1 minute" --> 60
	if (text.toString().match(/^\d+$/)) return parseInt(text); // already in seconds
	var multipliers = {
		s: 1,
		m: 60,
		h: 60 * 60,
		d: 60 * 60 * 24,
		w: 60 * 60 * 24 * 7
	};
	var seconds = 0;
	text = text.toString().replace(/([\d\.]+)\s*(\w)\w*\s*/g, function(m_all, m_g1, m_g2) {
		var mult = multipliers[ m_g2.toLowerCase() ] || 0;
		seconds += (parseFloat(m_g1) * mult); 
		return '';
	} );
	return Math.floor(seconds);
};

function get_inner_window_size(dom) {
	// get size of inner window
	if (!dom) dom = window;
	var myWidth = 0, myHeight = 0;
	
	if( typeof( dom.innerWidth ) == 'number' ) {
		// Non-IE
		myWidth = dom.innerWidth;
		myHeight = dom.innerHeight;
	}
	else if( dom.document.documentElement && ( dom.document.documentElement.clientWidth || dom.document.documentElement.clientHeight ) ) {
		// IE 6+ in 'standards compliant mode'
		myWidth = dom.document.documentElement.clientWidth;
		myHeight = dom.document.documentElement.clientHeight;
	}
	else if( dom.document.body && ( dom.document.body.clientWidth || dom.document.body.clientHeight ) ) {
		// IE 4 compatible
		myWidth = dom.document.body.clientWidth;
		myHeight = dom.document.body.clientHeight;
	}
	return { width: myWidth, height: myHeight };
}

function get_scroll_xy(dom) {
	// get page scroll X, Y
	if (!dom) dom = window;
  var scrOfX = 0, scrOfY = 0;
  if( typeof( dom.pageYOffset ) == 'number' ) {
    //Netscape compliant
    scrOfY = dom.pageYOffset;
    scrOfX = dom.pageXOffset;
  } else if( dom.document.body && ( dom.document.body.scrollLeft || dom.document.body.scrollTop ) ) {
    //DOM compliant
    scrOfY = dom.document.body.scrollTop;
    scrOfX = dom.document.body.scrollLeft;
  } else if( dom.document.documentElement && ( dom.document.documentElement.scrollLeft || dom.document.documentElement.scrollTop ) ) {
    //IE6 standards compliant mode
    scrOfY = dom.document.documentElement.scrollTop;
    scrOfX = dom.document.documentElement.scrollLeft;
  }
  return { x: scrOfX, y: scrOfY };
}

function get_scroll_max(dom) {
	// get maximum scroll width/height
	if (!dom) dom = window;
	var myWidth = 0, myHeight = 0;
	if (dom.document.body.scrollHeight) {
		myWidth = dom.document.body.scrollWidth;
		myHeight = dom.document.body.scrollHeight;
	}
	else if (dom.document.documentElement.scrollHeight) {
		myWidth = dom.document.documentElement.scrollWidth;
		myHeight = dom.document.documentElement.scrollHeight;
	}
	return { width: myWidth, height: myHeight };
}

function hires_time_now() {
	// return the Epoch seconds for like right now
	var now = new Date();
	return ( now.getTime() / 1000 );
}

function str_value(str) {
	// Get friendly string value for display purposes.
	if (typeof(str) == 'undefined') str = '';
	else if (str === null) str = '';
	return '' + str;
}

function pluralize(word, num) {
	// Pluralize a word using simplified English language rules.
	if (num != 1) {
		if (word.match(/[^e]y$/)) return word.replace(/y$/, '') + 'ies';
		else if (word.match(/s$/)) return word + 'es'; // processes
		else return word + 's';
	}
	else return word;
}

function render_menu_options(items, sel_value, auto_add) {
	// return HTML for menu options
	var html = '';
	var found = false;
	
	for (var idx = 0, len = items.length; idx < len; idx++) {
		var item = items[idx];
		var item_name = '';
		var item_value = '';
		if (isa_hash(item)) {
			if (('label' in item) && ('data' in item)) {
				item_name = item.label;
				item_value = item.data;
			}
			else {
				item_name = item.title;
				item_value = item.id;
			}
		}
		else if (isa_array(item)) {
			item_value = item[0];
			item_name = item[1];
		}
		else {
			item_name = item_value = item;
		}
		html += '<option value="'+item_value+'" '+((item_value == sel_value) ? 'selected="selected"' : '')+'>'+item_name+'</option>';
		if (item_value == sel_value) found = true;
	}
	
	if (!found && (str_value(sel_value) != '') && auto_add) {
		html += '<option value="'+sel_value+'" selected="selected">'+sel_value+'</option>';
	}
	
	return html;
}

function dirname(path) {
	// return path excluding file at end (same as POSIX function of same name)
	return path.toString().replace(/\/$/, "").replace(/\/[^\/]+$/, "");
}

function basename(path) {
	// return filename, strip path (same as POSIX function of same name)
	return path.toString().replace(/\/$/, "").replace(/^(.*)\/([^\/]+)$/, "$2");
}

function strip_ext(path) {
	// strip extension from filename
	return path.toString().replace(/\.\w+$/, "");
}

function load_script(url) {
	// Dynamically load script into DOM.
	Debug.trace( "Loading script: " + url );
	var scr = document.createElement('SCRIPT');
	scr.type = 'text/javascript';
	scr.src = url;
	document.getElementsByTagName('HEAD')[0].appendChild(scr);
}

function compose_attribs(attribs) {
	// compose Key="Value" style attributes for HTML elements
	var html = '';
	
	if (attribs) {
		for (var key in attribs) {
			html += " " + key + "=\"" + attribs[key] + "\"";
		}
	}

	return html;
}

function compose_style(attribs) {
	// compose key:value; pairs for style (CSS) elements
	var html = '';
	
	if (attribs) {
		for (var key in attribs) {
			html += " " + key + ":" + attribs[key] + ";";
		}
	}

	return html;
}

function truncate_ellipsis(str, len) {
	// simple truncate string with ellipsis if too long
	str = str_value(str);
	if (str.length > len) {
		str = str.substring(0, len - 3) + '...';
	}
	return str;
}

function escape_text_field_value(text) {
	// escape text field value, with stupid IE support
	text = encode_attrib_entities( str_value(text) );
	if (navigator.userAgent.match(/MSIE/) && text.replace) text = text.replace(/\&apos\;/g, "'");
	return text;
}

function expando_text(text, max, link) {
	// if text is longer than max chars, chop with ellipsis and include link to show all
	if (!link) link = 'More';
	text = str_value(text);
	if (text.length <= max) return text;
	
	var before = text.substring(0, max);
	var after = text.substring(max);
	
	return before + 
		'<span>... <a href="javascript:void(0)" onMouseUp="$(this).parent().hide().next().show()">'+link+'</a></span>' + 
		'<span style="display:none">' + after + '</span>';
};

function get_int_version(str, pad) {
	// Joe's Fun Multi-Decimal Comparision Trick
	// Example: convert 2.5.1 to 2005001 for numerical comparison against other similar "numbers".
	if (!pad) pad = 3;
	str = str_value(str).replace(/[^\d\.]+/g, '');
	if (!str.match(/\./)) return parseInt(str, 10);
	
	var parts = str.split(/\./);
	var output = '';
	for (var idx = 0, len = parts.length; idx < len; idx++) {
		var part = '' + parts[idx];
		while (part.length < pad) part = '0' + part;
		output += part;
	}
	return parseInt( output.replace(/^0+/, ''), 10 );
};

function get_unique_id(len, salt) {
	// Get unique ID using MD5, hires time, pseudo-random number and static counter.
	if (this.__unique_id_counter) this.__unique_id_counter = 0;
	this.__unique_id_counter++;
	return hex_md5( '' + hires_time_now() + Math.random() + this.__unique_id_counter + (salt || '') ).substring(0, len || 32);
};

function escape_regexp(text) {
	// Escape text for use in a regular expression.
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

function setPath(target, path, value) {
	// set path using dir/slash/syntax or dot.path.syntax
	// preserve dots and slashes if escaped
	var parts = path.replace(/\\\./g, '__PXDOT__').replace(/\\\//g, '__PXSLASH__').split(/[\.\/]/).map( function(elem) {
		return elem.replace(/__PXDOT__/g, '.').replace(/__PXSLASH__/g, '/');
	} );
	
	var key = parts.pop();
	
	// traverse path
	while (parts.length) {
		var part = parts.shift();
		if (part) {
			if (!(part in target)) {
				// auto-create nodes
				target[part] = {};
			}
			if (typeof(target[part]) != 'object') {
				// path runs into non-object
				return false;
			}
			target = target[part];
		}
	}
	
	target[key] = value;
	return true;
};

function getPath(target, path) {
	// get path using dir/slash/syntax or dot.path.syntax
	// preserve dots and slashes if escaped
	var parts = path.replace(/\\\./g, '__PXDOT__').replace(/\\\//g, '__PXSLASH__').split(/[\.\/]/).map( function(elem) {
		return elem.replace(/__PXDOT__/g, '.').replace(/__PXSLASH__/g, '/');
	} );
	
	var key = parts.pop();
	
	// traverse path
	while (parts.length) {
		var part = parts.shift();
		if (part) {
			if (typeof(target[part]) != 'object') {
				// path runs into non-object
				return undefined;
			}
			target = target[part];
		}
	}
	
	return target[key];
};

function substitute(text, args, fatal) {
	// perform simple [placeholder] substitution using supplied
	// args object and return transformed text
	var self = this;
	var result = true;
	var value = '';
	if (typeof(text) == 'undefined') text = '';
	text = '' + text;
	if (!args) args = {};
	
	text = text.replace(/\[([^\]]+)\]/g, function(m_all, name) {
		value = getPath(args, name);
		if (value === undefined) {
			result = false;
			return m_all;
		}
		else return value;
	} );
	
	if (!result && fatal) return null;
	else return text;
};

// Joe's Date/Time Tools
// Copyright (c) 2004 - 2015 Joseph Huckaby
// Released under the MIT License

var _months = [
	[ 1, 'January' ], [ 2, 'February' ], [ 3, 'March' ], [ 4, 'April' ],
	[ 5, 'May' ], [ 6, 'June' ], [ 7, 'July' ], [ 8, 'August' ],
	[ 9, 'September' ], [ 10, 'October' ], [ 11, 'November' ],
	[ 12, 'December' ]
];
var _days = [
	[1,1], [2,2], [3,3], [4,4], [5,5], [6,6], [7,7], [8,8], [9,9], [10,10],
	[11,11], [12,12], [13,13], [14,14], [15,15], [16,16], [17,17], [18,18], 
	[19,19], [20,20], [21,21], [22,22], [23,23], [24,24], [25,25], [26,26],
	[27,27], [28,28], [29,29], [30,30], [31,31]
];

var _short_month_names = [ 'Jan', 'Feb', 'Mar', 'Apr', 'May', 
	'June', 'July', 'Aug', 'Sept', 'Oct', 'Nov', 'Dec' ];

var _day_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 
	'Thursday', 'Friday', 'Saturday'];
	
var _short_day_names = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

var _number_suffixes = ['th', 'st', 'nd', 'rd', 'th', 'th', 'th', 'th', 'th', 'th'];

var _hour_names = ['12am', '1am', '2am', '3am', '4am', '5am', '6am', '7am', '8am', '9am', '10am', '11am', '12pm', '1pm', '2pm', '3pm', '4pm', '5pm', '6pm', '7pm', '8pm', '9pm', '10pm', '11pm'];

function time_now() {
	// return the Epoch seconds for like right now
	var now = new Date();
	return Math.floor( now.getTime() / 1000 );
}

function hires_time_now() {
	// return the Epoch seconds for like right now
	var now = new Date();
	return ( now.getTime() / 1000 );
}

function format_date(thingy, template) {
	// format date using get_date_args
	// e.g. '[yyyy]/[mm]/[dd]' or '[dddd], [mmmm] [mday], [yyyy]' or '[hour12]:[mi] [ampm]'
	if (!thingy) return false;
	var dargs = thingy.yyyy_mm_dd ? thingy : get_date_args(thingy);
	return template.replace(/\[(\w+)\]/g, function(m_all, m_g1) {
		return (m_g1 in dargs) ? dargs[m_g1] : '';
	});
}

function get_date_args(thingy) {
	// return hash containing year, mon, mday, hour, min, sec
	// given epoch seconds
	var date = (typeof(thingy) == 'object') ? thingy : (new Date( (typeof(thingy) == 'number') ? (thingy * 1000) : thingy ));
	var args = {
		epoch: Math.floor( date.getTime() / 1000 ),
		year: date.getFullYear(),
		mon: date.getMonth() + 1,
		mday: date.getDate(),
		hour: date.getHours(),
		min: date.getMinutes(),
		sec: date.getSeconds(),
		msec: date.getMilliseconds(),
		wday: date.getDay(),
		offset: 0 - (date.getTimezoneOffset() / 60)
	};
	
	args.yyyy = '' + args.year;
	if (args.mon < 10) args.mm = "0" + args.mon; else args.mm = '' + args.mon;
	if (args.mday < 10) args.dd = "0" + args.mday; else args.dd = '' + args.mday;
	if (args.hour < 10) args.hh = "0" + args.hour; else args.hh = '' + args.hour;
	if (args.min < 10) args.mi = "0" + args.min; else args.mi = '' + args.min;
	if (args.sec < 10) args.ss = "0" + args.sec; else args.ss = '' + args.sec;
	
	if (args.hour >= 12) {
		args.ampm = 'pm';
		args.hour12 = args.hour - 12;
		if (!args.hour12) args.hour12 = 12;
	}
	else {
		args.ampm = 'am';
		args.hour12 = args.hour;
		if (!args.hour12) args.hour12 = 12;
	}
	
	args.AMPM = args.ampm.toUpperCase();
	args.yyyy_mm_dd = args.yyyy + '/' + args.mm + '/' + args.dd;
	args.hh_mi_ss = args.hh + ':' + args.mi + ':' + args.ss;
	args.tz = 'GMT' + (args.offset > 0 ? '+' : '') + args.offset;
	
	// add formatted month and weekdays
	args.mmm = _short_month_names[ args.mon - 1 ];
	args.mmmm = _months[ args.mon - 1] ? _months[ args.mon - 1][1] : '';
	args.ddd = _short_day_names[ args.wday ];
	args.dddd = _day_names[ args.wday ];
	
	return args;
}

function get_time_from_args(args) {
	// return epoch given args like those returned from get_date_args()
	var then = new Date(
		args.year,
		args.mon - 1,
		args.mday,
		args.hour,
		args.min,
		args.sec,
		0
	);
	return parseInt( then.getTime() / 1000, 10 );
}

function yyyy(epoch) {
	// return current year (or epoch) in YYYY format
	if (!epoch) epoch = time_now();
	var args = get_date_args(epoch);
	return args.year;
}

function yyyy_mm_dd(epoch, ch) {
	// return current date (or custom epoch) in YYYY/MM/DD format
	if (!epoch) epoch = time_now();
	if (!ch) ch = '/';
	var args = get_date_args(epoch);
	return args.yyyy + ch + args.mm + ch + args.dd;
}

function mm_dd_yyyy(epoch, ch) {
	// return current date (or custom epoch) in YYYY/MM/DD format
	if (!epoch) epoch = time_now();
	if (!ch) ch = '/';
	var args = get_date_args(epoch);
	return args.mm + ch + args.dd + ch + args.yyyy;
}

function normalize_time(epoch, zero_args) {
	// quantize time into any given precision
	// example hourly: { min:0, sec:0 }
	// daily: { hour:0, min:0, sec:0 }
	var args = get_date_args(epoch);
	for (key in zero_args) args[key] = zero_args[key];

	// mday is 1-based
	if (!args['mday']) args['mday'] = 1;

	return get_time_from_args(args);
}

function get_nice_date(epoch, abbrev) {
	var dargs = get_date_args(epoch);
	var month = window._months[dargs.mon - 1][1];
	if (abbrev) month = month.substring(0, 3);
	return month + ' ' + dargs.mday + ', ' + dargs.year;
}

function get_nice_time(epoch, secs) {
	// return time in HH12:MM format
	var dargs = get_date_args(epoch);
	if (dargs.min < 10) dargs.min = '0' + dargs.min;
	if (dargs.sec < 10) dargs.sec = '0' + dargs.sec;
	var output = dargs.hour12 + ':' + dargs.min;
	if (secs) output += ':' + dargs.sec;
	output += ' ' + dargs.ampm.toUpperCase();
	return output;
}

function get_nice_date_time(epoch, secs, abbrev_date) {
	return get_nice_date(epoch, abbrev_date) + ' ' + get_nice_time(epoch, secs);
}

function get_short_date_time(epoch) {
	return get_nice_date(epoch, true) + ' ' + get_nice_time(epoch, false);
}

function parse_date(str) {
	// parse date into epoch
	return Math.floor( ((new Date(str)).getTime() / 1000) );
};

function check_valid_date(str) {
	// return true if a date is valid, false otherwise
	// returns false for Jan 1, 1970 00:00:00 GMT
	var epoch = 0;
	try { epoch = parse_date(str); }
	catch (e) { epoch = 0; }
	return (epoch >= 86400);
};

/**
 * WebApp 1.0 Page Manager
 * Author: Joseph Huckaby
 * Copyright (c) 2010 Joseph Huckaby
 * Released under the MIT License.
 **/

var Nav = {
	
	/**
	 * Virtual Page Navigation System
	 **/
	
	loc: '',
	old_loc: '',
	inited: false,
	nodes: [],
	
	init: function() {
		// initialize nav system
		assert( window.config, "window.config not present.");
		
		if (!this.inited) {
			this.inited = true;
			this.loc = 'init';
			this.monitor();
			
			if (window.addEventListener) {
				window.addEventListener("hashchange", function(event) {
					Nav.monitor();
				}, false);
			}
			else {
				window.onhashchange = function() { Nav.monitor(); };
			}
		}
	},
	
	monitor: function() {
		// monitor browser location and activate handlers as needed
		var parts = window.location.href.split(/\#/);
		var anchor = parts[1];
		if (!anchor) anchor = config.DefaultPage || 'Main';
		
		var full_anchor = '' + anchor;
		var sub_anchor = '';
		
		anchor = anchor.replace(/\%7C/, '|');
		if (anchor.match(/\|(\w+)$/)) {
			// inline section anchor after article name, pipe delimited
			sub_anchor = RegExp.$1.toLowerCase();
			anchor = anchor.replace(/\|(\w+)$/, '');
		}
		
		if ((anchor != this.loc) && !anchor.match(/^_/)) { // ignore doxter anchors
			Debug.trace('nav', "Caught navigation anchor: " + full_anchor);
			
			var page_name = '';
			var page_args = {};
			if (full_anchor.match(/^\w+\?.+/)) {
				parts = full_anchor.split(/\?/);
				page_name = parts[0];
				page_args = parse_query_string( parts[1] );
			}
			else {
				parts = full_anchor.split(/\//);
				page_name = parts[0];
				page_args = {};
			}
			
			Debug.trace('nav', "Calling page: " + page_name + ": " + JSON.stringify(page_args));
			Dialog.hide();
			// app.hideMessage();
			var result = app.page_manager.click( page_name, page_args );
			if (result) {
				this.old_loc = this.loc;
				if (this.old_loc == 'init') this.old_loc = config.DefaultPage || 'Main';
				this.loc = anchor;
			}
			else {
				// current page aborted navigation -- recover current page without refresh
				this.go( this.loc );
			}
		}
		else if (sub_anchor != this.sub_anchor) {
			Debug.trace('nav', "Caught sub-anchor: " + sub_anchor);
			$P().gosub( sub_anchor );
		} // sub-anchor changed
		
		this.sub_anchor = sub_anchor;	
	},
	
	go: function(anchor, force) {
		// navigate to page
		anchor = anchor.replace(/^\#/, '');
		if (force) {
			if (anchor == this.loc) {
				this.loc = 'init';
				this.monitor();
			}
			else {
				this.loc = 'init';
				window.location.href = '#' + anchor;
			}
		}
		else {
			window.location.href = '#' + anchor;
		}
	},
	
	prev: function() {
		// return to previous page
		this.go( this.old_loc || config.DefaultPage || 'Main' );
	},
	
	refresh: function() {
		// re-nav to current page
		this.loc = 'refresh';
		this.monitor();
	},
	
	currentAnchor: function() {
		// return current page anchor
		var parts = window.location.href.split(/\#/);
		var anchor = parts[1] || '';
		var sub_anchor = '';
		
		anchor = anchor.replace(/\%7C/, '|');
		if (anchor.match(/\|(\w+)$/)) {
			// inline section anchor after article name, pipe delimited
			sub_anchor = RegExp.$1.toLowerCase();
			anchor = anchor.replace(/\|(\w+)$/, '');
		}
		
		return anchor;
	}
	
}; // Nav

//
// Page Base Class
//

Class.create( 'Page', {
	// 'Page' class is the abstract base class for all pages
	// Each web component calls this class daddy
	
	// member variables
	ID: '', // ID of DIV for component
	data: null,   // holds all data for freezing
	active: false, // whether page is active or not
	sidebar: true, // whether to show sidebar or not
	
	// methods
	__construct: function(config, div) {
		if (!config) return;
		
		// class constructor, import config into self
		this.data = {};
		if (!config) config = {};
		for (var key in config) this[key] = config[key];
		
		this.div = div || $('#page_' + this.ID);
		assert(this.div, "Cannot find page div: page_" + this.ID);
		
		this.tab = $('#tab_' + this.ID);
	},
	
	onInit: function() {
		// called with the page is initialized
	},
	
	onActivate: function() {
		// called when page is activated
		return true;
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		return true;
	},
	
	show: function() {
		// show page
		this.div.show();
	},
	
	hide: function() {
		this.div.hide();
	},
	
	gosub: function(anchor) {
		// go to sub-anchor (article section link)
	},
	
	getSidebarTabs: function(current, tabs) {
		// get html for sidebar tabs
		var html = '';
		
		html += '<div style="margin-left:151px; position:relative; min-height:400px;">';
		html += '<div class="side_tab_bar" style="position:absolute; left:-161px;">';
		html += '<div style="height:50px;"></div>';
		
		for (var idx = 0, len = tabs.length; idx < len; idx++) {
			var tab = tabs[idx];
			if (typeof(tab) == 'string') html += tab;
			else {
				var class_name = 'inactive';
				var link = 'Nav.go(\''+this.ID+'?sub='+tab[0]+'\')';
				
				if (tab[0] == current) {
					class_name = 'active';
					link = '';
				}
				html += '<div class="tab side '+class_name+'" onMouseUp="'+link+'"><span class="content">'+tab[1]+'</span></div>';
			}
		}
		
		html += '</div>';
		
		return html;
	},
	
	getPaginatedTable: function(resp, cols, data_type, callback) {
		// get html for paginated table
		// dual-calling convention: (resp, cols, data_type, callback) or (args)
		var args = null;
		if (arguments.length == 1) {
			// custom args calling convention
			args = arguments[0];
			
			// V2 API
			if (!args.resp && args.rows && args.total) {
				args.resp = {
					rows: args.rows,
					list: { length: args.total }
				};
			}
		}
		else {
			// classic calling convention
			args = {
				resp: arguments[0],
				cols: arguments[1],
				data_type: arguments[2],
				callback: arguments[3],
				limit: this.args.limit,
				offset: this.args.offset || 0
			};
		}
		
		var resp = args.resp;
		var cols = args.cols;
		var data_type = args.data_type;
		var callback = args.callback;
		var cpl = args.pagination_link || '';
		var html = '';
		
		// pagination header
		html += '<div class="pagination">';
		html += '<table cellspacing="0" cellpadding="0" border="0" width="100%"><tr>';
		
		var results = {
			limit: args.limit,
			offset: args.offset || 0,
			total: resp.list.length
		};
		
		var num_pages = Math.floor( results.total / results.limit ) + 1;
		if (results.total % results.limit == 0) num_pages--;
		var current_page = Math.floor( results.offset / results.limit ) + 1;
		
		html += '<td align="left" width="33%">';
		html += commify(results.total) + ' ' + pluralize(data_type, results.total) + ' found';
		html += '</td>';
		
		html += '<td align="center" width="34%">';
		if (num_pages > 1) html += 'Page ' + commify(current_page) + ' of ' + commify(num_pages);
		else html += '&nbsp;';
		html += '</td>';
		
		html += '<td align="right" width="33%">';
		
		if (num_pages > 1) {
			// html += 'Page: ';
			if (current_page > 1) {
				if (cpl) {
					html += '<span class="link" onMouseUp="'+cpl+'('+Math.floor((current_page - 2) * results.limit)+')">&laquo; Prev Page</span>';
				}
				else {
					html += '<a href="#' + this.ID + compose_query_string(merge_objects(this.args, {
						offset: (current_page - 2) * results.limit
					})) + '">&laquo; Prev Page</a>';
				}
			}
			html += '&nbsp;&nbsp;&nbsp;';

			var start_page = current_page - 4;
			var end_page = current_page + 5;

			if (start_page < 1) {
				end_page += (1 - start_page);
				start_page = 1;
			}

			if (end_page > num_pages) {
				start_page -= (end_page - num_pages);
				if (start_page < 1) start_page = 1;
				end_page = num_pages;
			}

			for (var idx = start_page; idx <= end_page; idx++) {
				if (idx == current_page) {
					html += '<b>' + commify(idx) + '</b>';
				}
				else {
					if (cpl) {
						html += '<span class="link" onMouseUp="'+cpl+'('+Math.floor((idx - 1) * results.limit)+')">' + commify(idx) + '</span>';
					}
					else {
						html += '<a href="#' + this.ID + compose_query_string(merge_objects(this.args, {
							offset: (idx - 1) * results.limit
						})) + '">' + commify(idx) + '</a>';
					}
				}
				html += '&nbsp;';
			}

			html += '&nbsp;&nbsp;';
			if (current_page < num_pages) {
				if (cpl) {
					html += '<span class="link" onMouseUp="'+cpl+'('+Math.floor((current_page + 0) * results.limit)+')">Next Page &raquo;</span>';
				}
				else {
					html += '<a href="#' + this.ID + compose_query_string(merge_objects(this.args, {
						offset: (current_page + 0) * results.limit
					})) + '">Next Page &raquo;</a>';
				}
			}
		} // more than one page
		else {
			html += 'Page 1 of 1';
		}
		html += '</td>';
		html += '</tr></table>';
		html += '</div>';
		
		html += '<div style="margin-top:5px;">';
		html += '<table class="data_table" width="100%">';
		html += '<tr><th>' + cols.join('</th><th>').replace(/\s+/g, '&nbsp;') + '</th></tr>';
		
		for (var idx = 0, len = resp.rows.length; idx < len; idx++) {
			var row = resp.rows[idx];
			var tds = callback(row, idx);
			if (tds) {
				html += '<tr' + (tds.className ? (' class="'+tds.className+'"') : '') + '>';
				html += '<td>' + tds.join('</td><td>') + '</td>';
				html += '</tr>';
			}
		} // foreach row
		
		if (!resp.rows.length) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'No '+pluralize(data_type)+' found.';
			html += '</td></tr>';
		}
		
		html += '</table>';
		html += '</div>';
		
		return html;
	},
	
	getBasicTable: function(rows, cols, data_type, callback) {
		// get html for sorted table (fake pagination, for looks only)
		var html = '';
		
		// pagination
		html += '<div class="pagination">';
		html += '<table cellspacing="0" cellpadding="0" border="0" width="100%"><tr>';
		
		html += '<td align="left" width="33%">';
		if (cols.headerLeft) html += cols.headerLeft;
		else html += commify(rows.length) + ' ' + pluralize(data_type, rows.length) + '';
		html += '</td>';
		
		html += '<td align="center" width="34%">';
			html += cols.headerCenter || '&nbsp;';
		html += '</td>';
		
		html += '<td align="right" width="33%">';
			html += cols.headerRight || 'Page 1 of 1';
		html += '</td>';
		
		html += '</tr></table>';
		html += '</div>';
		
		html += '<div style="margin-top:5px;">';
		html += '<table class="data_table" width="100%">';
		html += '<tr><th style="white-space:nowrap;">' + cols.join('</th><th style="white-space:nowrap;">') + '</th></tr>';
		
		for (var idx = 0, len = rows.length; idx < len; idx++) {
			var row = rows[idx];
			var tds = callback(row, idx);
			if (tds.insertAbove) html += tds.insertAbove;
			html += '<tr' + (tds.className ? (' class="'+tds.className+'"') : '') + '>';
			html += '<td>' + tds.join('</td><td>') + '</td>';
			html += '</tr>';
		} // foreach row
		
		if (!rows.length) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'No '+pluralize(data_type)+' found.';
			html += '</td></tr>';
		}
		
		html += '</table>';
		html += '</div>';
		
		return html;
	}
	
} ); // class Page

//
// Page Manager
//

Class.create( 'PageManager', {
	// 'PageManager' class handles all virtual pages in the application
	
	// member variables
	pages: null, // array of pages
	current_page_id: '', // current page ID
	
	// methods
	__construct: function(page_list) {
		// class constructor, create all pages
		// page_list should be array of components from master config
		// each one should have at least a 'ID' parameter
		// anything else is copied into object verbatim
		this.pages = [];
		this.page_list = page_list;
		
		for (var idx = 0, len = page_list.length; idx < len; idx++) {
			Debug.trace( 'page', "Initializing page: " + page_list[idx].ID );
			assert(Page[ page_list[idx].ID ], "Page class not found: Page." + page_list[idx].ID);
			
			var page = new Page[ page_list[idx].ID ]( page_list[idx] );
			page.args = {};
			page.onInit();
			this.pages.push(page);
			
			$('#tab_'+page.ID).click( function(event) {
				// console.log( this );
				// app.page_manager.click( this._page_id );
				Nav.go( this._page_id );
			} )[0]._page_id = page.ID;
		}
	},
	
	find: function(id) {
		// locate page by ID (i.e. Plugin Name)
		var page = find_object( this.pages, { ID: id } );
		if (!page) Debug.trace('PageManager', "Could not find page: " + id);
		return page;
	},
	
	activate: function(id, old_id, args) {
		// send activate event to page by id (i.e. Plugin Name)
		$('#page_'+id).show();
		$('#tab_'+id).removeClass('inactive').addClass('active');
		var page = this.find(id);
		page.active = true;
		
		if (!args) args = {};
		
		// if we are navigating here from a different page, AND the new sub mismatches the old sub, clear the page html
		var new_sub = args.sub || '';
		if (old_id && (id != old_id) && (typeof(page._old_sub) != 'undefined') && (new_sub != page._old_sub) && page.div) {
			page.div.html('');
		}
						
		var result = page.onActivate.apply(page, [args]);
		if (typeof(result) == 'boolean') return result;
		else throw("Page " + id + " onActivate did not return a boolean!");
	},
	
	deactivate: function(id, new_id) {
		// send deactivate event to page by id (i.e. Plugin Name)
		var page = this.find(id);
		var result = page.onDeactivate(new_id);
		if (result) {
			$('#page_'+id).hide();
			$('#tab_'+id).removeClass('active').addClass('inactive');
			// $('#d_message').hide();
			page.active = false;
			
			// if page has args.sub, save it for clearing html on reactivate, if page AND sub are different
			if (page.args) page._old_sub = page.args.sub || '';
		}
		return result;
	},
	
	click: function(id, args) {
		// exit current page and enter specified page
		Debug.trace('page', "Switching pages to: " + id);
		var old_id = this.current_page_id;
		if (this.current_page_id) {
			var result = this.deactivate( this.current_page_id, id );
			if (!result) return false; // current page said no
		}
		this.current_page_id = id;
		this.old_page_id = old_id;
		
		window.scrollTo( 0, 0 );
		
		var result = this.activate(id, old_id, args);
		if (!result) {
			// new page has rejected activation, probably because a login is required
			// un-hide previous page div, but don't call activate on it
			$('#page_'+id).hide();
			this.current_page_id = '';
			// if (old_id) {
				// $('page_'+old_id).show();
				// this.current_page_id = old_id;
			// }
		}
		
		return true;
	}
	
} ); // class PageManager


// Dialog Tools
// Author: Joseph Huckaby
// Released under the MIT License.

var Dialog = {
	
	active: false,
	clickBlock: false,
	
	showAuto: function(title, inner_html, click_block) {
		// measure size of HTML to create correctly positioned dialog
		var temp = $('<div/>').css({
			position: 'absolute',
			visibility: 'hidden'
		}).html(inner_html).appendTo('body');
		
		var width = temp.width();
		var height = temp.height();
		temp.remove();
		
		this.show( width, height, title, inner_html, click_block );
	},
	
	autoResize: function() {
		// automatically resize dialog to match changed content size
		var temp = $('<div/>').css({
			position: 'absolute',
			visibility: 'hidden'
		}).html( $('#dialog_main').html() ).appendTo('body');
		
		var width = temp.width();
		var height = temp.height();
		temp.remove();
		
		var size = get_inner_window_size();
		var x = Math.floor( (size.width / 2) - ((width + 0) / 2) );
		var y = Math.floor( ((size.height / 2) - (height / 2)) * 0.75 );
		
		$('#dialog_main').css({
			width: '' + width + 'px',
			height: '' + height + 'px'
		});
		$('#dialog_container').css({
			left: '' + x + 'px',
			top: '' + y + 'px'
		});
	},
	
	show: function(width, height, title, inner_html, click_block) {
		// show dialog
		this.clickBlock = click_block || false;
		var body = document.getElementsByTagName('body')[0];
		
		// build html for dialog
		var html = '';
		if (title) {
			html += '<div class="tab_bar" style="width:'+width+'px;">';
				html += '<div class="tab active"><span class="content">'+title+'</span></div>';
			html += '</div>';
		}
		html += '<div id="dialog_main" style="width:auto; height:auto;">';
			html += inner_html;
		html += '</div>';
		
		var size = get_inner_window_size();
		var x = Math.floor( (size.width / 2) - ((width + 0) / 2) );
		var y = Math.floor( ((size.height / 2) - (height / 2)) * 0.75 );
		
		if ($('#dialog_overlay').length) {
			$('#dialog_overlay').stop().remove();
		}
		
		var overlay = document.createElement('div');
		overlay.id = 'dialog_overlay';
		overlay.style.opacity = 0;
		body.appendChild(overlay);
		$(overlay).fadeTo( 500, 0.75 ).click(function() {
			if (!Dialog.clickBlock) Dialog.hide();
		});
		
		if ($('#dialog_container').length) {
			$('#dialog_container').stop().remove();
		}
		
		var container = document.createElement('div');
		container.id = 'dialog_container';
		container.style.opacity = 0;
		container.style.left = '' + x + 'px';
		container.style.top = '' + y + 'px';
		container.innerHTML = html;
		body.appendChild(container);
		$(container).fadeTo( 250, 1.0 );
		
		this.active = true;
	},
	
	hide: function() {
		// hide dialog
		if (this.active) {
			$('#dialog_container').stop().fadeOut( 250, function() { $(this).remove(); } );
			$('#dialog_overlay').stop().fadeOut( 500, function() { $(this).remove(); } );
			this.active = false;
		}
	},
	
	showProgress: function(msg) {
		// show simple progress dialog (unspecified duration)
		var html = '';
		html += '<table width="300" height="120" cellspacing="0" cellpadding="0"><tr><td width="300" height="120" align="center" valign="center">';
		html += '<img src="images/loading.gif" width="32" height="32"/><br/><br/>';
		html += '<span class="label" style="padding-top:5px">' + msg + '</span>';
		html += '</td></tr></table>';
		this.show( 300, 120, '', html );
	}
	
};

// Base App Framework

var app = {
	
	username: '',
	cacheBust: hires_time_now(),
	proto: location.protocol.match(/^https/i) ? 'https://' : 'http://',
	secure: !!location.protocol.match(/^https/i),
	retina: (window.devicePixelRatio > 1),
	base_api_url: '/api',
	plain_text_post: false,
	prefs: {},
	
	init: function() {
		// override this in your app.js
	},
	
	extend: function(obj) {
		// extend app object with another
		for (var key in obj) this[key] = obj[key];
	},
	
	setAPIBaseURL: function(url) {
		// set the API base URL (commands are appended to this)
		this.base_api_url = url;
	},
	
	setWindowTitle: function(title) {
		// set the current window title, includes app name
		document.title = title + ' | ' + this.name;
	},
	
	showTabBar: function(visible) {
		// show or hide tab bar
		if (visible) $('.tab_bar').show();
		else $('.tab_bar').hide();
	},
	
	updateHeaderInfo: function() {
		// update top-right display
		// override this function in app
	},
	
	getUserAvatarURL: function() {
		// get URL to user's avatar using Gravatar.com service
		var size = 0;
		var email = '';
		if (arguments.length == 2) {
			email = arguments[0];
			size = arguments[1];
		}
		else if (arguments.length == 1) {
			email = this.user.email;
			size = arguments[0];
		}
		
		// user may have custom avatar
		if (this.user && this.user.avatar) {
			// convert to protocol-less URL
			return this.user.avatar.replace(/^\w+\:/, '');
		}
		
		return '//en.gravatar.com/avatar/' + hex_md5( email.toLowerCase() ) + '.jpg?s=' + size + '&d=mm';
	},
	
	doMyAccount: function() {
		// nav to the my account page
		Nav.go('MyAccount');
	},
	
	doUserLogin: function(resp) {
		// user login, called from login page, or session recover
		app.username = resp.username;
		app.user = resp.user;
		
		app.setPref('username', resp.username);
		app.setPref('session_id', resp.session_id);
		
		this.updateHeaderInfo();
		
		if (this.isAdmin()) $('#tab_Admin').show();
		else $('#tab_Admin').hide();
	},
	
	doUserLogout: function(bad_cookie) {
		// log user out and redirect to login screen
		if (!bad_cookie) {
			// user explicitly logging out
			app.showProgress(1.0, "Logging out...");
			app.setPref('username', '');
		}
		
		app.api.post( 'user/logout', {
			session_id: app.getPref('session_id')
		}, 
		function(resp, tx) {
			app.hideProgress();
			
			delete app.user;
			delete app.username;
			delete app.user_info;
			
			app.setPref('session_id', '');
			
			$('#d_header_user_container').html( '' );
			
			Debug.trace("User session cookie was deleted, redirecting to login page");
			Nav.go('Login');
			
			setTimeout( function() {
				if (bad_cookie) app.showMessage('error', "Your session has expired.  Please log in again.");
				else app.showMessage('success', "You were logged out successfully.");
			}, 150 );
			
			$('#tab_Admin').hide();
		} );
	},
	
	isAdmin: function() {
		// return true if user is logged in and admin, false otherwise
		return( app.user && app.user.privileges && app.user.privileges.admin );
	},
	
	handleResize: function() {
		// called when window resizes
		if (this.page_manager && this.page_manager.current_page_id) {
			var id = this.page_manager.current_page_id;
			var page = this.page_manager.find(id);
			if (page && page.onResize) page.onResize( get_inner_window_size() );
		}
		
		// also handle sending resize events at a 250ms delay
		// so some pages can perform a more expensive refresh at a slower interval
		if (!this.resize_timer) {
			this.resize_timer = setTimeout( this.handleResizeDelay.bind(this), 250 );
		}
	},
	
	handleResizeDelay: function() {
		// called 250ms after latest resize event
		this.resize_timer = null;
		
		if (this.page_manager && this.page_manager.current_page_id) {
			var id = this.page_manager.current_page_id;
			var page = this.page_manager.find(id);
			if (page && page.onResizeDelay) page.onResizeDelay( get_inner_window_size() );
		}
	},
	
	handleUnload: function() {
		// called just before user navs off
		if (this.page_manager && this.page_manager.current_page_id && $P && $P() && $P().onBeforeUnload) {
			var result = $P().onBeforeUnload();
			if (result) {
				(e || window.event).returnValue = result; //Gecko + IE
				return result; // Webkit, Safari, Chrome etc.
			}
		}
	},
	
	doError: function(msg, lifetime) {
		// show an error message at the top of the screen
		// and hide the progress dialog if applicable
		Debug.trace("ERROR: " + msg);
		this.showMessage( 'error', msg, lifetime );
		if (this.progress) this.hideProgress();
		return null;
	},
	
	badField: function(id, msg) {
		// mark field as bad
		if (id.match(/^\w+$/)) id = '#' + id;
		$(id).removeClass('invalid').width(); // trigger reflow to reset css animation
		$(id).addClass('invalid');
		try { $(id).focus(); } catch (e) {;}
		if (msg) return this.doError(msg);
		else return false;
	},
	
	clearError: function(animate) {
		// clear last error
		app.hideMessage(animate);
		$('.invalid').removeClass('invalid');
	},
	
	showMessage: function(type, msg, lifetime) {
		// show success, warning or error message
		// Dialog.hide();
		var icon = '';
		msg = escape_text_field_value(msg); // escape any html chars
		switch (type) {
			case 'success': icon = 'check-circle'; break;
			case 'warning': icon = 'exclamation-circle'; break;
			case 'error': icon = 'exclamation-triangle'; break;
		}
		if (icon) {
			msg = '<i class="fa fa-'+icon+' fa-lg" style="transform-origin:50% 50%; transform:scale(1.25); -webkit-transform:scale(1.25);">&nbsp;&nbsp;&nbsp;</i>' + msg;
		}
		
		$('#d_message_inner').html( msg );
		$('#d_message').hide().removeClass().addClass('message').addClass(type).show(250);
		
		if (this.messageTimer) clearTimeout( this.messageTimer );
		if ((type == 'success') || lifetime) {
			if (!lifetime) lifetime = 8;
			this.messageTimer = setTimeout( function() { app.hideMessage(500); }, lifetime * 1000 );
		}
	},
	
	hideMessage: function(animate) {
		if (animate) $('#d_message').hide(animate);
		else $('#d_message').hide();
	},
	
	api: {
		request: function(url, args, callback, errorCallback) {
			// send AJAX request to server using jQuery
			var headers = {};
			
			// inject session id into headers, unless app is using plain_text_post
			if (app.getPref('session_id') && !app.plain_text_post) {
				headers['X-Session-ID'] = app.getPref('session_id');
			}
			
			args.context = this;
			args.url = url;
			args.dataType = 'text'; // so we can parse the response json ourselves
			args.timeout = 1000 * 10; // 10 seconds
			args.headers = headers;
			
			$.ajax(args).done( function(text) {
				// parse JSON and fire callback
				Debug.trace( 'api', "Received response from server: " + text );
				var resp = null;
				try { resp = JSON.parse(text); }
				catch (e) {
					// JSON parse error
					var desc = "JSON Error: " + e.toString();
					if (errorCallback) errorCallback({ code: 500, description: desc });
					else app.doError(desc);
				}
				// success, but check json for server error code
				if (resp) {
					if (('code' in resp) && (resp.code != 0)) {
						// an error occurred within the JSON response
						// session errors are handled specially
						if (resp.code == 'session') app.doUserLogout(true);
						else if (errorCallback) errorCallback(resp);
						else app.doError("Error: " + resp.description);
					}
					else if (callback) callback(resp);
				}
			} )
			.fail( function(xhr, status, err) {
				// XHR or HTTP error
				var code = xhr.status || 500;
				var desc = err.toString() || status.toString();
				switch (desc) {
					case 'timeout': desc = "The request timed out.  Please try again."; break;
					case 'error': desc = "An unknown network error occurred.  Please try again."; break;
				}
				Debug.trace( 'api', "Network Error: " + code + ": " + desc );
				if (errorCallback) errorCallback({ code: code, description: desc });
				else app.doError( "Network Error: " + code + ": " + desc );
			} );
		},
		
		post: function(cmd, params, callback, errorCallback) {
			// send AJAX POST request to server using jQuery
			var url = cmd;
			if (!url.match(/^(\w+\:\/\/|\/)/)) url = app.base_api_url + "/" + cmd;
			
			if (!params) params = {};
			
			// inject session in into json if submitting as plain text (cors preflight workaround)
			if (app.getPref('session_id') && app.plain_text_post) {
				params['session_id'] = app.getPref('session_id');
			}
			
			var json_raw = JSON.stringify(params);
			Debug.trace( 'api', "Sending HTTP POST to: " + url + ": " + json_raw );
			
			this.request(url, {
				type: "POST",
				data: json_raw,
				contentType: app.plain_text_post ? 'text/plain' : 'application/json'
			}, callback, errorCallback);
		},
		
		get: function(cmd, query, callback, errorCallback) {
			// send AJAX GET request to server using jQuery
			var url = cmd;
			if (!url.match(/^(\w+\:\/\/|\/)/)) url = app.base_api_url + "/" + cmd;
			
			if (!query) query = {};
			query.cachebust = app.cacheBust;
			url += compose_query_string(query);
			
			Debug.trace( 'api', "Sending HTTP GET to: " + url );
			
			this.request(url, {
				type: "GET"
			}, callback, errorCallback);
		}
	}, // api
	
	getPref: function(key) {
		// get pref using html5 localStorage
		if (window.localStorage) return localStorage[key];
		else return this.prefs[key];
	},
	
	setPref: function(key, value) {
		if (window.localStorage) localStorage[key] = value;
		else prefs[key] = value;
	},
	
	hideProgress: function() {
		// hide progress dialog
		Dialog.hide();
		delete app.progress;
	},
	
	showProgress: function(counter, title) {
		// show or update progress bar
		if (!$('#d_progress_bar').length) {
			// no progress dialog is active, so set it up
			if (!counter) counter = 0;
			if (counter < 0) counter = 0;
			if (counter > 1) counter = 1;
			var cx = Math.floor( counter * 196 );
			
			var html = '';
			html += '<div class="dialog_simple dialog_shadow">';
			// html += '<center>';
			// html += '<div class="loading" style="width:32px; height:32px; margin:0 auto 10px auto;"></div>';
			html += '<div id="d_progress_title" class="dialog_subtitle" style="text-align:center; position:relative; top:-5px;">' + title + '</div>';
			
			var extra_classes = '';
			if (counter == 1.0) extra_classes = 'indeterminate';
			
			html += '<div id="d_progress_bar_cont" class="progress_bar_container '+extra_classes+'" style="width:196px; margin:0 auto 0 auto;">';
				html += '<div id="d_progress_bar" class="progress_bar_inner" style="width:'+cx+'px;"></div>';
			html += '</div>';
			
			// html += '</center>';
			html += '</div>';
			
			app.hideMessage();
			Dialog.show(275, 100, "", html, true);
			
			app.progress = {
				start_counter: counter,
				counter: counter,
				counter_max: 1,
				start_time: hires_time_now(),
				last_update: hires_time_now(),
				title: title
			};
		}
		else if (app.progress) {
			// dialog is active, so update existing elements
			var now = hires_time_now();
			var cx = Math.floor( counter * 196 );
			$('#d_progress_bar').css( 'width', '' + cx + 'px' );
			
			var prog_cont = $('#d_progress_bar_cont');
			if ((counter == 1.0) && !prog_cont.hasClass('indeterminate')) prog_cont.addClass('indeterminate');
			else if ((counter < 1.0) && prog_cont.hasClass('indeterminate')) prog_cont.removeClass('indeterminate');
			
			if (title) app.progress.title = title;
			$('#d_progress_title').html( app.progress.title );
			
			app.progress.last_update = now;
			app.progress.counter = counter;
		}
	},
	
	showDialog: function(title, inner_html, buttons_html) {
		// show dialog using our own look & feel
		var html = '';
		html += '<div class="dialog_title">' + title + '</div>';
		html += '<div class="dialog_content">' + inner_html + '</div>';
		html += '<div class="dialog_buttons">' + buttons_html + '</div>';
		Dialog.showAuto( "", html );
	},
	
	hideDialog: function() {
		Dialog.hide();
	},
	
	confirm: function(title, html, ok_btn_label, callback) {
		// show simple OK / Cancel dialog with custom text
		// fires callback with true (OK) or false (Cancel)
		if (!ok_btn_label) ok_btn_label = "OK";
		this.confirm_callback = callback;
		
		var inner_html = "";
		inner_html += '<div class="confirm_container">'+html+'</div>';
		
		var buttons_html = "";
		buttons_html += '<center><table><tr>';
			buttons_html += '<td><div class="button" style="width:100px; font-weight:normal;" onMouseUp="app.confirm_click(false)">Cancel</div></td>';
			buttons_html += '<td width="60">&nbsp;</td>';
			buttons_html += '<td><div class="button" style="width:100px;" onMouseUp="app.confirm_click(true)">'+ok_btn_label+'</div></td>';
		buttons_html += '</tr></table></center>';
		
		this.showDialog( title, inner_html, buttons_html );
		
		// special mode for key capture
		Dialog.active = 'confirmation';
	},
	
	confirm_click: function(result) {
		// user clicked OK or Cancel in confirmation dialog, fire callback
		// caller MUST deal with Dialog.hide() if result is true
		if (this.confirm_callback) {
			this.confirm_callback(result);
			if (!result) Dialog.hide();
		}
	},
	
	confirm_key: function(event) {
		// handle keydown with active confirmation dialog
		if (Dialog.active !== 'confirmation') return;
		if ((event.keyCode != 13) && (event.keyCode != 27)) return;
		
		// skip enter check if textarea is active
		if (document.activeElement && (event.keyCode == 13)) {
			if ($(document.activeElement).prop('type') == 'textarea') return;
		}
		
		event.stopPropagation();
		event.preventDefault();
		
		if (event.keyCode == 13) this.confirm_click(true);
		else if (event.keyCode == 27) this.confirm_click(false);
	},
	
	get_base_url: function() {
		return app.proto + location.hostname + '/';
	},
	
	setTheme: function(theme) {
		// toggle light/dark theme
		if (theme == 'dark') {
			$('body').addClass('dark');
			$('#d_theme_ctrl').html( '<i class="fa fa-moon-o fa-lg">&nbsp;</i>Dark' );
			this.setPref('theme', 'dark');
		}
		else {
			$('body').removeClass('dark');
			$('#d_theme_ctrl').html( '<i class="fa fa-lightbulb-o fa-lg">&nbsp;</i>Light' );
			this.setPref('theme', 'light');
		}
		
		if (this.onThemeChange) this.onThemeChange(theme);
	},
	
	initTheme: function() {
		// set theme to user's preference
		if (!this.getPref('theme')) {
			// brand new user: try to guess theme using media query
			if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
				this.setPref('theme', 'dark');
			}
		}
		this.setTheme( this.getPref('theme') || 'light' );
	},
	
	toggleTheme: function() {
		// toggle light/dark theme
		if (this.getPref('theme') == 'dark') this.setTheme('light');
		else this.setTheme('dark');
	}
	
}; // app object

function get_form_table_row() {
	// Get HTML for formatted form table row (label and content).
	var tr_class = '';
	var left = '';
	var right = '';
	if (arguments.length == 3) {
		tr_class = arguments[0]; left = arguments[1]; right = arguments[2];
	}
	else {
		left = arguments[0]; right = arguments[1];
	}
	
	left = left.replace(/\s/g, '&nbsp;').replace(/\:$/, '');
	if (left) left += ':'; else left = '&nbsp;';
	
	var html = '';
	html += '<tr class="'+tr_class+'">';
		html += '<td align="right" class="table_label">'+left+'</td>';
		html += '<td align="left" class="table_value">';
			html += '<div>'+right+'</div>';
		html += '</td>';
	html += '</tr>';
	return html;
};

function get_form_table_caption() {
	// Get HTML for form table caption (takes up a row).
	var tr_class = '';
	var cap = '';
	if (arguments.length == 2) {
		tr_class = arguments[0]; cap = arguments[1];
	}
	else {
		cap = arguments[0];
	}
	
	var html = '';
	html += '<tr class="'+tr_class+'">';
		html += '<td>&nbsp;</td>';
		html += '<td align="left">';
			html += '<div class="caption">'+cap+'</div>';
		html += '</td>';
	html += '</tr>';
	return html;
};

function get_form_table_spacer() {
	// Get HTML for form table spacer (takes up a row).
	var tr_class = '';
	var extra_classes = '';
	if (arguments.length == 2) {
		tr_class = arguments[0]; extra_classes = arguments[1];
	}
	else {
		extra_classes = arguments[0];
	}
	
	var html = '';
	html += '<tr class="'+tr_class+'"><td colspan="2"><div class="table_spacer '+extra_classes+'"></div></td></tr>';
	return html;
};

function $P(id) {
	// shortcut for page_manager.find(), also defaults to current page
	if (!id) id = app.page_manager.current_page_id;
	var page = app.page_manager.find(id);
	assert( !!page, "Failed to locate page: " + id );
	return page;
};

var Debug = {
	backlog: [],
	
	dump: function() {
		// dump backlog to console
		for (var idx = 0, len = this.backlog.length; idx < len; idx++) {
			console.log( this.backlog[idx] );
		}
	},
	
	trace: function(cat, msg) {
		// trace one line to console, or store in backlog
		if (arguments.length == 1) { msg = cat; cat = 'debug'; }
		if (window.console && console.log && window.config && config.debug) {
			console.log( cat + ': ' + msg );
		}
		else {
			this.backlog.push( hires_time_now() + ': ' + cat + ': ' + msg );
			if (this.backlog.length > 100) this.backlog.shift();
		}
	}
};

$(document).ready(function() {
	app.init();
});

window.addEventListener( "keydown", function(event) {
	app.confirm_key(event);
}, false );

window.addEventListener( "resize", function() {
	app.handleResize();
}, false );

window.addEventListener("beforeunload", function (e) {
	return app.handleUnload();
}, false );

// Cronicle Web App
// Author: Joseph Huckaby
// Copyright (c) 2015 Joseph Huckaby and PixlCore.com

if (!window.app) throw new Error("App Framework is not present.");

app.extend({
	
	name: '',
	preload_images: ['loading.gif'],
	activeJobs: {},
	eventQueue: {},
	state: null,
	plain_text_post: true,
	clock_visible: false,
	scroll_time_visible: false,
	default_prefs: {
		schedule_group_by: 'category'
	},
	
	receiveConfig: function(resp) {
		// receive config from server
		if (resp.code) {
			app.showProgress( 1.0, "Waiting for master server..." );
			setTimeout( function() { load_script( '/api/app/config' ); }, 1000 );
			return;
		}
		delete resp.code;
		window.config = resp.config;
		
		for (var key in resp) {
			this[key] = resp[key];
		}
		
		// allow visible app name to be changed in config
		this.name = config.name;
		$('#d_header_title').html( '<b>' + this.name + '</b>' );
		
		// hit the master server directly from now on
		this.setMasterHostname( resp.master_hostname );
		
		this.config.Page = [
			{ ID: 'Home' },
			{ ID: 'Login' },
			{ ID: 'Schedule' },
			{ ID: 'History' },
			{ ID: 'JobDetails' },
			{ ID: 'MyAccount' },
			{ ID: 'Admin' }
		];
		this.config.DefaultPage = 'Home';
		
		// did we try to init and fail?  if so, try again now
		if (this.initReady) {
			this.hideProgress();
			delete this.initReady;
			this.init();
		}
	},
	
	init: function() {
		// initialize application
		if (this.abort) return; // fatal error, do not initialize app
		
		if (!this.config) {
			// must be in master server wait loop
			this.initReady = true;
			return;
		}
		
		if (!this.servers) this.servers = {};
		this.server_groups = [];
		
		// timezone support
		this.tz = this.config.tz || jstz.determine().name();
		this.zones = moment.tz.names();
		
		// preload a few essential images
		for (var idx = 0, len = this.preload_images.length; idx < len; idx++) {
			var filename = '' + this.preload_images[idx];
			var img = new Image();
			img.src = '/images/'+filename;
		}
		
		// populate prefs for first time user
		for (var key in this.default_prefs) {
			if (!(key in window.localStorage)) {
				window.localStorage[key] = this.default_prefs[key];
			}
		}
		
		// pop version into footer
		$('#d_footer_version').html( "Version " + this.version || 0 );
		
		// some css classing for browser-specific adjustments
		var ua = navigator.userAgent;
		if (ua.match(/Safari/) && !ua.match(/(Chrome|Opera)/)) {
			$('body').addClass('safari');
		}
		else if (ua.match(/Chrome/)) {
			$('body').addClass('chrome');
		}
		else if (ua.match(/Firefox/)) {
			$('body').addClass('firefox');
		}
		
		// follow scroll so we can fade in/out the scroll time widget
		window.addEventListener( "scroll", function() {
			app.checkScrollTime();
		}, false );
		app.checkScrollTime();
		
		this.page_manager = new PageManager( always_array(config.Page) );
		
		// this.setHeaderClock();
		this.socketConnect();
		
		// Nav.init();
	},
	
	updateHeaderInfo: function() {
		// update top-right display
		var html = '';
		html += '<div id="d_header_divider" class="right" style="margin-right:0;"></div>';
		html += '<div class="header_option logout right" onMouseUp="app.doUserLogout()"><i class="fa fa-power-off fa-lg">&nbsp;&nbsp;</i>Logout</div>';
		html += '<div id="d_header_divider" class="right"></div>';
		html += '<div id="d_header_user_bar" class="right" style="background-image:url(' + this.getUserAvatarURL( this.retina ? 64 : 32 ) + ')" onMouseUp="app.doMyAccount()">' + (this.user.full_name || app.username).replace(/\s+.+$/, '') + '</div>';
		$('#d_header_user_container').html( html );
	},
	
	doUserLogin: function(resp) {
		// user login, called from login page, or session recover
		// overriding this from base.js, so we can pass the session ID to the websocket
		delete resp.code;
		
		for (var key in resp) {
			this[key] = resp[key];
		}
		
		if (this.isCategoryLimited() || this.isGroupLimited()) {
			this.pruneSchedule();
			this.pruneCategories();
			this.pruneActiveJobs();
		}
		
		this.setPref('username', resp.username);
		this.setPref('session_id', resp.session_id);
		
		this.updateHeaderInfo();
		
		// update clock
		this.setHeaderClock( this.epoch );
		
		// show scheduler master switch
		this.updateMasterSwitch();
		if (this.hasPrivilege('state_update')) $('#d_tab_master').addClass('active');
		
		// show admin tab if user is worthy
		if (this.isAdmin()) $('#tab_Admin').show();
		else $('#tab_Admin').hide();
		
		// authenticate websocket
		this.socket.emit( 'authenticate', { token: resp.session_id } );
	},
	
	doUserLogout: function(bad_cookie) {
		// log user out and redirect to login screen
		var self = this;
		
		if (!bad_cookie) {
			// user explicitly logging out
			this.showProgress(1.0, "Logging out...");
			this.setPref('username', '');
		}
		
		this.api.post( 'user/logout', {
			session_id: this.getPref('session_id')
		}, 
		function(resp, tx) {
			delete self.user;
			delete self.username;
			delete self.user_info;
			
			if (self.socket) self.socket.emit( 'logout', {} );
			
			self.setPref('session_id', '');
			
			$('#d_header_user_container').html( '' );
			$('#d_tab_master').html( '' );
			
			$('div.header_clock_layer').fadeTo( 1000, 0 );
			$('#d_tab_time > span').html( '' );
			self.clock_visible = false;
			self.checkScrollTime();
			
			if (app.config.external_users) {
				// external user api
				Debug.trace("User session cookie was deleted, querying external user API");
				setTimeout( function() {
					if (bad_cookie) app.doExternalLogin(); 
					else app.doExternalLogout(); 
				}, 250 );
			}
			else {
				Debug.trace("User session cookie was deleted, redirecting to login page");
				self.hideProgress();
				Nav.go('Login');
			}
			
			setTimeout( function() {
				if (!app.config.external_users) {
					if (bad_cookie) self.showMessage('error', "Your session has expired.  Please log in again.");
					else self.showMessage('success', "You were logged out successfully.");
				}
				
				self.activeJobs = {};
				delete self.servers;
				delete self.schedule;
				delete self.categories;
				delete self.plugins;
				delete self.server_groups;
				delete self.epoch;
				
			}, 150 );
			
			$('#tab_Admin').hide();
		} );
	},
	
	doExternalLogin: function() {
		// login using external user management system
		// Force API to hit current page hostname vs. master server, so login redirect URL reflects it
		app.api.post( '/api/user/external_login', { cookie: document.cookie }, function(resp) {
			if (resp.user) {
				Debug.trace("User Session Resume: " + resp.username + ": " + resp.session_id);
				app.hideProgress();
				app.doUserLogin( resp );
				Nav.refresh();
			}
			else if (resp.location) {
				Debug.trace("External User API requires redirect");
				app.showProgress(1.0, "Logging in...");
				setTimeout( function() { window.location = resp.location; }, 250 );
			}
			else app.doError(resp.description || "Unknown login error.");
		} );
	},
	
	doExternalLogout: function() {
		// redirect to external user management system for logout
		var url = app.config.external_user_api;
		url += (url.match(/\?/) ? '&' : '?') + 'logout=1';
		
		Debug.trace("External User API requires redirect");
		app.showProgress(1.0, "Logging out...");
		setTimeout( function() { window.location = url; }, 250 );
	},
	
	socketConnect: function() {
		// init socket.io client
		var self = this;
		
		var url = this.proto + this.masterHostname + ':' + this.port;
		if (!config.web_socket_use_hostnames && this.servers && this.servers[this.masterHostname] && this.servers[this.masterHostname].ip) {
			// use ip instead of hostname if available
			url = this.proto + this.servers[this.masterHostname].ip + ':' + this.port;
		}
		if (!config.web_direct_connect) {
			url = this.proto + location.host;
		}
		Debug.trace("Websocket Connect: " + url);
		
		if (this.socket) {
			Debug.trace("Destroying previous socket");
			this.socket.removeAllListeners();
			if (this.socket.connected) this.socket.disconnect();
			this.socket = null;
		}
		
		var socket = this.socket = io( url, {
			// forceNew: true,
			transports: config.socket_io_transports || ['websocket'],
			reconnection: false,
			reconnectionDelay: 1000,
			reconnectionDelayMax: 2000,
			reconnectionAttempts: 9999,
			timeout: 3000
		} );
		
		socket.on('connect', function() {
			if (!Nav.inited) Nav.init();
			
			Debug.trace("socket.io connected successfully");
			// if (self.progress) self.hideProgress();
			
			// if we are already logged in, authenticate websocket now
			var session_id = app.getPref('session_id');
			if (session_id) socket.emit( 'authenticate', { token: session_id } );
		} );
		
		socket.on('connect_error', function(err) {
			Debug.trace("socket.io connect error: " + err);
		} );
		
		socket.on('connect_timeout', function(err) {
			Debug.trace("socket.io connect timeout");
		} );
		
		socket.on('reconnecting', function() {
			Debug.trace("socket.io reconnecting...");
			// self.showProgress( 0.5, "Reconnecting to server..." );
		} );
		
		socket.on('reconnect', function() {
			Debug.trace("socket.io reconnected successfully");
			// if (self.progress) self.hideProgress();
		} );
		
		socket.on('reconnect_failed', function() {
			Debug.trace("socket.io has given up -- we must refresh");
			location.reload();
		} );
		
		socket.on('disconnect', function() {
			// unexpected disconnection
			Debug.trace("socket.io disconnected unexpectedly");
		} );
		
		socket.on('status', function(data) {
			if (!data.master) {
				// OMG we're not talking to master anymore?
				self.recalculateMaster(data);
			}
			else {
				// connected to master
				self.epoch = data.epoch;
				self.servers = data.servers;
				self.setHeaderClock( data.epoch );
				
				// update active jobs
				self.updateActiveJobs( data );
				
				// notify current page
				var id = self.page_manager.current_page_id;
				var page = self.page_manager.find(id);
				if (page && page.onStatusUpdate) page.onStatusUpdate(data);
				
				// remove dialog if present
				if (self.waitingForMaster && self.progress) {
					self.hideProgress();
					delete self.waitingForMaster;
				}
			} // master
		} );
		
		socket.on('update', function(data) {
			// receive data update (global list contents)
			var limited_user = self.isCategoryLimited() || self.isGroupLimited();
			
			for (var key in data) {
				self[key] = data[key];
				
				if (limited_user) {
					if (key == 'schedule') self.pruneSchedule();
					else if (key == 'categories') self.pruneCategories();
				}
				
				var id = self.page_manager.current_page_id;
				var page = self.page_manager.find(id);
				if (page && page.onDataUpdate) page.onDataUpdate(key, data[key]);
			}
			
			// update master switch (once per minute)
			if (data.state) self.updateMasterSwitch();
			
			// clear event autosave data if schedule was updated
			if (data.schedule) delete self.autosave_event;
		} );
		
		// --- Keep socket.io connected forever ---
		// This is the worst hack in history, but socket.io-client
		// is simply not behaving, and I have tried EVERYTHING ELSE.
		setInterval( function() {
			if (socket && !socket.connected) {
				Debug.trace("Forcing socket to reconnect");
				socket.connect();
			}
		}, 5000 );
	},
	
	updateActiveJobs: function(data) {
		// update active jobs
		var jobs = data.active_jobs;
		var changed = false;
		
		// determine if jobs have been added or deleted
		for (var id in jobs) {
			// check for new jobs added
			if (!this.activeJobs[id]) changed = true;
		}
		for (var id in this.activeJobs) {
			// check for jobs completed
			if (!jobs[id]) changed = true;
		}
		
		this.activeJobs = jobs;
		if (this.isCategoryLimited() || this.isGroupLimited()) this.pruneActiveJobs();
		data.jobs_changed = changed;
	},
	
	pruneActiveJobs: function() {
		// remove active jobs that the user should not see, due to category/group privs
		if (!this.activeJobs) return;
		
		for (var id in this.activeJobs) {
			var job = this.activeJobs[id];
			if (!this.hasCategoryAccess(job.category) || !this.hasGroupAccess(job.target)) {
				delete this.activeJobs[id];
			}
		}
	},
	
	pruneSchedule: function() {
		// remove schedule items that the user should not see, due to category/group privs
		if (!this.schedule || !this.schedule.length) return;
		var new_items = [];
		
		for (var idx = 0, len = this.schedule.length; idx < len; idx++) {
			var item = this.schedule[idx];
			if (this.hasCategoryAccess(item.category) && this.hasGroupAccess(item.target)) {
				new_items.push(item);
			}
		}
		
		this.schedule = new_items;
	},
	
	pruneCategories: function() {
		// remove categories that the user should not see, due to category privs
		if (!this.categories || !this.categories.length) return;
		var new_items = [];
		
		for (var idx = 0, len = this.categories.length; idx < len; idx++) {
			var item = this.categories[idx];
			if (this.hasCategoryAccess(item.id)) new_items.push(item);
		}
		
		this.categories = new_items;
	},
	
	isCategoryLimited: function() {
		// return true if user is limited to specific categories, false otherwise
		if (this.isAdmin()) return false;
		return( app.user && app.user.privileges && app.user.privileges.cat_limit );
	},
	
	isGroupLimited: function() {
		// return true if user is limited to specific server groups, false otherwise
		if (this.isAdmin()) return false;
		return( app.user && app.user.privileges && app.user.privileges.grp_limit );
	},
	
	hasCategoryAccess: function(cat_id) {
		// check if user has access to specific category
		if (!app.user || !app.user.privileges) return false;
		if (app.user.privileges.admin) return true;
		if (!app.user.privileges.cat_limit) return true;
		
		var priv_id = 'cat_' + cat_id;
		return( !!app.user.privileges[priv_id] );
	},
	
	hasGroupAccess: function(grp_id) {
		// check if user has access to specific server group
		if (!app.user || !app.user.privileges) return false;
		if (app.user.privileges.admin) return true;
		if (!app.user.privileges.grp_limit) return true;
		
		var priv_id = 'grp_' + grp_id;
		var result = !!app.user.privileges[priv_id];
		if (result) return true;
		
		// make sure grp_id is a hostname from this point on
		if (find_object(app.server_groups, { id: grp_id })) return false;
		
		var groups = app.server_groups.filter( function(group) {
			return grp_id.match( group.regexp );
		} );
		
		// we just need one group to match, then the user has permission to target the server
		for (var idx = 0, len = groups.length; idx < len; idx++) {
			priv_id = 'grp_' + groups[idx].id;
			result = !!app.user.privileges[priv_id];
			if (result) return true;
		}
		return false;
	},
	
	hasPrivilege: function(priv_id) {
		// check if user has privilege
		if (!app.user || !app.user.privileges) return false;
		if (app.user.privileges.admin) return true;
		return( !!app.user.privileges[priv_id] );
	},
	
	recalculateMaster: function(data) {
		// Oops, we're connected to a slave!  Master must have been restarted.
		// If slave knows who is master, switch now, otherwise go into wait loop
		var self = this;
		this.showProgress( 1.0, "Waiting for master server..." );
		this.waitingForMaster = true;
		
		if (data.master_hostname) {
			// reload browser which should connect to master
			location.reload();
		}
	},
	
	setMasterHostname: function(hostname) {
		// set new master hostname, update stuff
		Debug.trace("New Master Hostname: " + hostname);
		this.masterHostname = hostname;
		
		if (config.web_direct_connect) {
			this.base_api_url = this.proto + this.masterHostname + ':' + this.port + config.base_api_uri;
			if (!config.web_socket_use_hostnames && this.servers && this.servers[this.masterHostname] && this.servers[this.masterHostname].ip) {
				// use ip instead of hostname if available
				this.base_api_url = this.proto + this.servers[this.masterHostname].ip + ':' + this.port + config.base_api_uri;
			}
		}
		else {
			this.base_api_url = this.proto + location.host + config.base_api_uri;
		}
		
		Debug.trace("API calls now going to: " + this.base_api_url);
	},
	
	setHeaderClock: function(when) {
		// move the header clock hands to the selected time
		
		if (!when) when = time_now();
		var dargs = get_date_args( when );
		
		// hour hand
		var hour = (((dargs.hour + (dargs.min / 60)) % 12) / 12) * 360;
		$('#d_header_clock_hour').css({
			transform: 'rotateZ('+hour+'deg)',
			'-webkit-transform': 'rotateZ('+hour+'deg)'
		});
		
		// minute hand
		var min = ((dargs.min + (dargs.sec / 60)) / 60) * 360;
		$('#d_header_clock_minute').css({
			transform: 'rotateZ('+min+'deg)',
			'-webkit-transform': 'rotateZ('+min+'deg)'
		});
		
		// second hand
		var sec = (dargs.sec / 60) * 360;
		$('#d_header_clock_second').css({
			transform: 'rotateZ('+sec+'deg)',
			'-webkit-transform': 'rotateZ('+sec+'deg)'
		});
		
		// show clock if needed
		if (!this.clock_visible) {
			this.clock_visible = true;
			$('div.header_clock_layer, #d_tab_time').fadeTo( 1000, 1.0 );
			this.checkScrollTime();
		}
		
		// date/time in tab bar
		// $('#d_tab_time, #d_scroll_time > span').html( get_nice_date_time( when, true, true ) );
		var num_active = num_keys( app.activeJobs || {} );
		var nice_active = commify(num_active) + ' ' + pluralize('Job', num_active);
		if (!num_active) nice_active = "Idle";
		
		$('#d_tab_time > span, #d_scroll_time > span').html(
			// get_nice_date_time( when, true, true ) + ' ' + 
			get_nice_time(when, true) + ' ' + 
			moment.tz( when * 1000, app.tz).format("z") + ' - ' + 
			nice_active
		);
	},
	
	updateMasterSwitch: function() {
		// update master switch display
		var html = '';
		if (this.hasPrivilege('state_update')) {
			html = '<i '+(this.state.enabled ? 'class="fa fa-check-square-o">' : 'class="fa fa-square-o">')+'</i>&nbsp;<b>Scheduler Enabled</b>';
		}
		else {
			if (this.state.enabled) html = '<i class="fa fa-check">&nbsp;</i><b>Scheduler Enabled</b>';
			else html = '<i class="fa fa-times">&nbsp;</i><b>Scheduler Disabled</b>';
		}
		
		$('#d_tab_master')
			.css( 'color', this.state.enabled ? '#3f7ed5' : '#777' )
			.html( html );
	},
	
	toggleMasterSwitch: function() {
		// toggle master scheduler switch on/off
		var self = this;
		var enabled = this.state.enabled ? 0 : 1;
		var action = enabled ? 'enable' : 'disable';
		
		if (!this.hasPrivilege('state_update')) return;
		
		app.confirm( '<span style="color:red">Toggle Scheduler</span>', "Are you sure you want to " + action + " the scheduler?", ucfirst(action), function(result) {
			if (result) {
				app.hideDialog();
				app.api.post( 'app/update_master_state', { enabled: enabled }, function(resp) {
					app.showMessage('success', "Scheduler has been " + (enabled ? 'enabled' : 'disabled') + ".");
					self.state.enabled = enabled;
					self.updateMasterSwitch();
				} );
			}
		} );
	},
	
	checkScrollTime: function() {
		// check page scroll, see if we need to fade in/out the scroll time widget
		var pos = get_scroll_xy();
		var y = pos.y;
		var min_y = 70;
		
		if ((y >= min_y) && this.clock_visible) {
			if (!this.scroll_time_visible) {
				// time to fade it in
				$('#d_scroll_time').stop().css('top', '0px').fadeTo( 1000, 1.0 );
				this.scroll_time_visible = true;
			}
		}
		else {
			if (this.scroll_time_visible) {
				// time to fade it out
				$('#d_scroll_time').stop().fadeTo( 500, 0, function() {
					$(this).css('top', '-30px');
				} );
				this.scroll_time_visible = false;
			}
		}
	},
	
	get_password_type: function() {
		// get user's pref for password field type, defaulting to config
		return this.getPref('password_type') || config.default_password_type || 'password';
	},
	
	get_password_toggle_html: function() {
		// get html for a password toggle control
		var text = (this.get_password_type() == 'password') ? 'Show' : 'Hide';
		return '<span class="link password_toggle" onMouseUp="app.toggle_password_field(this)">' + text + '</span>';
	},
	
	toggle_password_field: function(span) {
		// toggle password field visible / masked
		var $span = $(span);
		var $field = $span.prev();
		if ($field.attr('type') == 'password') {
			$field.attr('type', 'text');
			$span.html( 'Hide' );
			this.setPref('password_type', 'text');
		}
		else {
			$field.attr('type', 'password');
			$span.html( 'Show' );
			this.setPref('password_type', 'password');
		}
	},
	
	password_strengthify: function(sel) {
		// add password strength meter (text field should be wrapped by div)
		var $field = $(sel);
		var $div = $field.parent();
		
		var $cont = $('<div class="psi_container" title="Password strength indicator" onClick="window.open(\'https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/\')"></div>');
		$cont.css('width', $field[0].offsetWidth );
		$cont.html( '<div class="psi_bar"></div>' );
		$div.append( $cont );
		
		$field.keyup( function() {
			setTimeout( function() {
				app.update_password_strength($field, $cont);
			}, 1 );
		} );
		
		if (!window.zxcvbn) load_script('js/external/zxcvbn.js');
	},
	
	update_password_strength: function($field, $cont) {
		// update password strength indicator after keypress
		if (window.zxcvbn) {
			var password = $field.val();
			var result = zxcvbn( password );
			// Debug.trace("Password score: " + password + ": " + result.score);
			var $bar = $cont.find('div.psi_bar');
			$bar.removeClass('str0 str1 str2 str3 str4');
			if (password.length) $bar.addClass('str' + result.score);
			app.last_password_strength = result;
		}
	},
	
	get_password_warning: function() {
		// return string of text used for bad password dialog
		var est_length = app.last_password_strength.crack_time_display;
		if (est_length == 'instant') est_length = 'instantly';
		else est_length = 'in about ' + est_length;
		
		return "The password you entered is <b>insecure</b>, and could be easily compromised by hackers.  Our anaysis indicates that it could be cracked via brute force " + est_length + ". For more details see <a href=\"http://en.wikipedia.org/wiki/Password_strength\" target=\"_blank\">this article</a>.<br/><br/>Do you really want to use this password?";
	},
	
	get_color_checkbox_html: function(id, label, checked) {
		// get html for color label checkbox, with built-in handlers to toggle state
		if (checked === true) checked = "checked";
		else if (checked === false) checked = "";
		
		return '<span id="'+id+'" class="color_label checkbox ' + checked + '" onMouseUp="app.toggle_color_checkbox(this)"><i class="fa '+(checked.match(/\bchecked\b/) ? 'fa-check-square-o' : 'fa-square-o')+'">&nbsp;</i>'+label+'</span>';
	},
	
	toggle_color_checkbox: function(elem) {
		// toggle color checkbox state
		var $elem = $(elem);
		if ($elem.hasClass('checked')) {
			// uncheck
			$elem.removeClass('checked').find('i').removeClass('fa-check-square-o').addClass('fa-square-o');
		}
		else {
			// check
			$elem.addClass('checked').find('i').addClass('fa-check-square-o').removeClass('fa-square-o');
		}
	}
	
}); // app

function get_pretty_int_list(arr, ranges) {
	// compose int array to string using commas + spaces, and
	// the english "and" to group the final two elements.
	// also detect sequences and collapse those into dashed ranges
	if (!arr || !arr.length) return '';
	if (arr.length == 1) return arr[0].toString();
	arr = deep_copy_object(arr).sort( function(a, b) { return a - b; } );
	
	// check for ranges and collapse them
	if (ranges) {
		var groups = [];
		var group = [];
		for (var idx = 0, len = arr.length; idx < len; idx++) {
			var elem = arr[idx];
			if (!group.length || (elem == group[group.length - 1] + 1)) group.push(elem);
			else { groups.push(group); group = [elem]; }
		}
		if (group.length) groups.push(group);
		arr = [];
		for (var idx = 0, len = groups.length; idx < len; idx++) {
			var group = groups[idx];
			if (group.length == 1) arr.push( group[0] );
			else if (group.length == 2) {
				arr.push( group[0] );
				arr.push( group[1] );
			}
			else {
				arr.push( group[0] + ' - ' + group[group.length - 1] );
			}
		}
	} // ranges
	
	if (arr.length == 1) return arr[0].toString();
	return arr.slice(0, arr.length - 1).join(', ') + ' and ' + arr[ arr.length - 1 ];
}

function summarize_event_timing(timing, timezone) {
	// summarize event timing into human-readable string
	if (!timing) return "On demand";
	
	// years
	var year_str = '';
	if (timing.years && timing.years.length) {
		year_str = get_pretty_int_list(timing.years, true);
	}
	
	// months
	var mon_str = '';
	if (timing.months && timing.months.length) {
		mon_str = get_pretty_int_list(timing.months, true).replace(/(\d+)/g, function(m_all, m_g1) {
			return _months[ parseInt(m_g1) - 1 ][1];
		});
	}
	
	// days
	var mday_str = '';
	if (timing.days && timing.days.length) {
		mday_str = get_pretty_int_list(timing.days, true).replace(/(\d+)/g, function(m_all, num_label) {
			if (num_label.match(/^1[1-9]$/)) return num_label + 'th'; // teens break the rule (11th, 12th, 13th, etc.)
			else return num_label + _number_suffixes[ parseInt( num_label.substring(num_label.length - 1) ) ];
		});
	}
	
	// weekdays	
	var wday_str = '';
	if (timing.weekdays && timing.weekdays.length) {
		wday_str = get_pretty_int_list(timing.weekdays, true).replace(/(\d+)/g, function(m_all, m_g1) {
			return _day_names[ parseInt(m_g1) ] + 's';
		});
		wday_str = wday_str.replace(/Mondays\s+\-\s+Fridays/, 'weekdays');
	}
	
	// hours
	var hour_str = '';
	if (timing.hours && timing.hours.length) {
		hour_str = get_pretty_int_list(timing.hours, true).replace(/(\d+)/g, function(m_all, m_g1) {
			return _hour_names[ parseInt(m_g1) ];
		});
	}
	
	// minutes
	var min_str = '';
	if (timing.minutes && timing.minutes.length) {
		min_str = get_pretty_int_list(timing.minutes, false).replace(/(\d+)/g, function(m_all, m_g1) {
			return ':' + ((m_g1.length == 1) ? ('0'+m_g1) : m_g1);
		});
	}
	
	// construct final string
	var groups = [];
	var mday_compressed = false;
	
	if (year_str) {
		groups.push( 'in ' + year_str );
		if (mon_str) groups.push( mon_str );
	}
	else if (mon_str) {
		// compress single month + single day
		if (timing.months && timing.months.length == 1 && timing.days && timing.days.length == 1) {
			groups.push( 'on ' + mon_str + ' ' + mday_str );
			mday_compressed = true;
		}
		else {
			groups.push( 'in ' + mon_str );
		}
	}
	
	if (mday_str && !mday_compressed) {
		if (mon_str || wday_str) groups.push( 'on the ' + mday_str );
		else groups.push( 'monthly on the ' + mday_str );
	}
	if (wday_str) groups.push( 'on ' + wday_str );
	
	// compress single hour + single minute
	if (timing.hours && timing.hours.length == 1 && timing.minutes && timing.minutes.length == 1) {
		hour_str.match(/^(\d+)(\w+)$/);
		var hr = RegExp.$1;
		var ampm = RegExp.$2;
		var new_str = hr + min_str + ampm;
		
		if (mday_str || wday_str) groups.push( 'at ' + new_str );
		else groups.push( 'daily at ' + new_str );
	}
	else {
		var min_added = false;
		if (hour_str) {
			if (mday_str || wday_str) groups.push( 'at ' + hour_str );
			else groups.push( 'daily at ' + hour_str );
		}
		else {
			// check for repeating minute pattern
			if (timing.minutes && timing.minutes.length) {
				var interval = detect_num_interval( timing.minutes, 60 );
				if (interval) {
					var new_str = 'every ' + interval + ' minutes';
					if (timing.minutes[0] > 0) {
						var m_g1 = timing.minutes[0].toString();
						new_str += ' starting on the :' + ((m_g1.length == 1) ? ('0'+m_g1) : m_g1);
					}
					groups.push( new_str );
					min_added = true;
				}
			}
			
			if (!min_added) {
				if (min_str) groups.push( 'hourly' );
			}
		}
		
		if (!min_added) {
			if (min_str) groups.push( 'on the ' + min_str.replace(/\:00/, 'hour').replace(/\:30/, 'half-hour') );
			else groups.push( 'every minute' );
		}
	}
	
	var text = groups.join(', ');
	var output = text.substring(0, 1).toUpperCase() + text.substring(1, text.length);
	
	if (timezone && (timezone != app.tz)) {
		// get tz abbreviation
		output += ' (' + moment.tz.zone(timezone).abbr( (new Date()).getTime() ) + ')';
	}
	
	return output;
};

function detect_num_interval(arr, max) {
	// detect interval between array elements, return if found
	// all elements must have same interval between them
	if (arr.length < 2) return false;
	// if (arr[0] > 0) return false;
	
	var interval = arr[1] - arr[0];
	for (var idx = 1, len = arr.length; idx < len; idx++) {
		var temp = arr[idx] - arr[idx - 1];
		if (temp != interval) return false;
	}
	
	// if max is provided, final element + interval must equal max
	// if (max && (arr[arr.length - 1] + interval != max)) return false;
	if (max && ((arr[arr.length - 1] + interval) % max != arr[0])) return false;
	
	return interval;
};

// Crontab Parsing Tools
// by Joseph Huckaby, (c) 2015, MIT License

var cron_aliases = {
	jan: 1,
	feb: 2,
	mar: 3,
	apr: 4,
	may: 5,
	jun: 6,
	jul: 7,
	aug: 8,
	sep: 9,
	oct: 10,
	nov: 11,
	dec: 12,
	
	sun: 0,
	mon: 1,
	tue: 2,
	wed: 3,
	thu: 4,
	fri: 5,
	sat: 6
};
var cron_alias_re = new RegExp("\\b(" + hash_keys_to_array(cron_aliases).join('|') + ")\\b", "g");

function parse_crontab_part(timing, raw, key, min, max, rand_seed) {
	// parse one crontab part, e.g. 1,2,3,5,20-25,30-35,59
	// can contain single number, and/or list and/or ranges and/or these things: */5 or 10-50/5
	if (raw == '*') { return; } // wildcard
	if (raw == 'h') {
		// unique value over accepted range, but locked to random seed
		// https://github.com/jhuckaby/Cronicle/issues/6
		raw = min + (parseInt( hex_md5(rand_seed), 16 ) % ((max - min) + 1));
		raw = '' + raw;
	}
	if (!raw.match(/^[\w\-\,\/\*]+$/)) { throw new Error("Invalid crontab format: " + raw); }
	var values = {};
	var bits = raw.split(/\,/);
	
	for (var idx = 0, len = bits.length; idx < len; idx++) {
		var bit = bits[idx];
		if (bit.match(/^\d+$/)) {
			// simple number, easy
			values[bit] = 1;
		}
		else if (bit.match(/^(\d+)\-(\d+)$/)) {
			// simple range, e.g. 25-30
			var start = parseInt( RegExp.$1 );
			var end = parseInt( RegExp.$2 );
			for (var idy = start; idy <= end; idy++) { values[idy] = 1; }
		}
		else if (bit.match(/^\*\/(\d+)$/)) {
			// simple step interval, e.g. */5
			var step = parseInt( RegExp.$1 );
			var start = min;
			var end = max;
			for (var idy = start; idy <= end; idy += step) { values[idy] = 1; }
		}
		else if (bit.match(/^(\d+)\-(\d+)\/(\d+)$/)) {
			// range step inverval, e.g. 1-31/5
			var start = parseInt( RegExp.$1 );
			var end = parseInt( RegExp.$2 );
			var step = parseInt( RegExp.$3 );
			for (var idy = start; idy <= end; idy += step) { values[idy] = 1; }
		}
		else {
			throw new Error("Invalid crontab format: " + bit + " (" + raw + ")");
		}
	}
	
	// min max
	var to_add = {};
	var to_del = {};
	for (var value in values) {
		value = parseInt( value );
		if (value < min) {
			to_del[value] = 1;
			to_add[min] = 1;
		}
		else if (value > max) {
			to_del[value] = 1;
			value -= min;
			value = value % ((max - min) + 1); // max is inclusive
			value += min;
			to_add[value] = 1;
		}
	}
	for (var value in to_del) delete values[value];
	for (var value in to_add) values[value] = 1;
	
	// convert to sorted array
	var list = hash_keys_to_array(values);
	for (var idx = 0, len = list.length; idx < len; idx++) {
		list[idx] = parseInt( list[idx] );
	}
	list = list.sort( function(a, b) { return a - b; } );
	if (list.length) timing[key] = list;
};

function parse_crontab(raw, rand_seed) {
	// parse standard crontab syntax, return timing object
	// e.g. 1,2,3,5,20-25,30-35,59 23 31 12 * *
	// optional 6th element == years
	if (!rand_seed) rand_seed = get_unique_id();
	var timing = {};
	
	// resolve all @shortcuts
	raw = trim(raw).toLowerCase();
	if (raw.match(/\@(yearly|annually)/)) raw = '0 0 1 1 *';
	else if (raw == '@monthly') raw = '0 0 1 * *';
	else if (raw == '@weekly') raw = '0 0 * * 0';
	else if (raw == '@daily') raw = '0 0 * * *';
	else if (raw == '@hourly') raw = '0 * * * *';
	
	// expand all month/wday aliases
	raw = raw.replace(cron_alias_re, function(m_all, m_g1) {
		return cron_aliases[m_g1];
	} );
	
	// at this point string should not contain any alpha characters or '@', except for 'h'
	if (raw.match(/([a-gi-z\@]+)/i)) throw new Error("Invalid crontab keyword: " + RegExp.$1);
	
	// split into parts
	var parts = raw.split(/\s+/);
	if (parts.length > 6) throw new Error("Invalid crontab format: " + parts.slice(6).join(' '));
	if (!parts[0].length) throw new Error("Invalid crontab format");
	
	// parse each part
	if ((parts.length > 0) && parts[0].length) parse_crontab_part( timing, parts[0], 'minutes', 0, 59, rand_seed );
	if ((parts.length > 1) && parts[1].length) parse_crontab_part( timing, parts[1], 'hours', 0, 23, rand_seed );
	if ((parts.length > 2) && parts[2].length) parse_crontab_part( timing, parts[2], 'days', 1, 31, rand_seed );
	if ((parts.length > 3) && parts[3].length) parse_crontab_part( timing, parts[3], 'months', 1, 12, rand_seed );
	if ((parts.length > 4) && parts[4].length) parse_crontab_part( timing, parts[4], 'weekdays', 0, 6, rand_seed );
	if ((parts.length > 5) && parts[5].length) parse_crontab_part( timing, parts[5], 'years', 1970, 3000, rand_seed );
	
	return timing;
};

// TAB handling code from http://www.webdeveloper.com/forum/showthread.php?t=32317
// Hacked to do my bidding - JH 2008-09-15
function setSelectionRange(input, selectionStart, selectionEnd) {
  if (input.setSelectionRange) {
    input.focus();
    input.setSelectionRange(selectionStart, selectionEnd);
  }
  else if (input.createTextRange) {
    var range = input.createTextRange();
    range.collapse(true);
    range.moveEnd('character', selectionEnd);
    range.moveStart('character', selectionStart);
    range.select();
  }
};

function replaceSelection (input, replaceString) {
	var oldScroll = input.scrollTop;
	if (input.setSelectionRange) {
		var selectionStart = input.selectionStart;
		var selectionEnd = input.selectionEnd;
		input.value = input.value.substring(0, selectionStart)+ replaceString + input.value.substring(selectionEnd);

		if (selectionStart != selectionEnd){ 
			setSelectionRange(input, selectionStart, selectionStart + 	replaceString.length);
		}else{
			setSelectionRange(input, selectionStart + replaceString.length, selectionStart + replaceString.length);
		}

	}else if (document.selection) {
		var range = document.selection.createRange();

		if (range.parentElement() == input) {
			var isCollapsed = range.text == '';
			range.text = replaceString;

			 if (!isCollapsed)  {
				range.moveStart('character', -replaceString.length);
				range.select();
			}
		}
	}
	input.scrollTop = oldScroll;
};

function catchTab(item,e){
	var c = e.which ? e.which : e.keyCode;

	if (c == 9){
		replaceSelection(item,String.fromCharCode(9));
		setTimeout("document.getElementById('"+item.id+"').focus();",0);	
		return false;
	}
};

function get_text_from_seconds_round_custom(sec, abbrev) {
	// convert raw seconds to human-readable relative time
	// round to nearest instead of floor, but allow one decimal point if under 10 units
	var neg = '';
	if (sec < 0) { sec =- sec; neg = '-'; }
	
	var text = abbrev ? "sec" : "second";
	var amt = sec;
	
	if (sec > 59) {
		var min = sec / 60;
		text = abbrev ? "min" : "minute"; 
		amt = min;
		
		if (min > 59) {
			var hour = min / 60;
			text = abbrev ? "hr" : "hour"; 
			amt = hour;
			
			if (hour > 23) {
				var day = hour / 24;
				text = "day"; 
				amt = day;
			} // hour>23
		} // min>59
	} // sec>59
	
	if (amt < 10) amt = Math.round(amt * 10) / 10;
	else amt = Math.round(amt);
	
	var text = "" + amt + " " + text;
	if ((amt != 1) && !abbrev) text += "s";
	
	return(neg + text);
};

Class.subclass( Page, "Page.Base", {	
	
	graph_colors: ["0,0,255", "138,43,226", "0,128,0", "255,20,147", "0,191,255", "210,105,30", "100,149,237", "220,20,60", "0,139,139", "128,128,128"],
	
	requireLogin: function(args) {
		// user must be logged into to continue
		var self = this;
		
		if (!app.user) {
			// require login
			app.navAfterLogin = this.ID;
			if (args && num_keys(args)) app.navAfterLogin += compose_query_string(args);
			
			this.div.hide();
			
			var session_id = app.getPref('session_id') || '';
			if (session_id) {
				Debug.trace("User has cookie, recovering session: " + session_id);
				
				app.api.post( 'user/resume_session', {
					session_id: session_id
				}, 
				function(resp) {
					if (resp.user) {
						Debug.trace("User Session Resume: " + resp.username + ": " + resp.session_id);
						app.hideProgress();
						app.doUserLogin( resp );
						Nav.refresh();
					}
					else {
						Debug.trace("User cookie is invalid, redirecting to login page");
						// Nav.go('Login');
						self.setPref('session_id', '');
						self.requireLogin(args);
					}
				} );
			}
			else if (app.config.external_users) {
				Debug.trace("User is not logged in, querying external user API");
				app.doExternalLogin();
			}
			else {
				Debug.trace("User is not logged in, redirecting to login page (will return to " + this.ID + ")");
				setTimeout( function() { Nav.go('Login'); }, 1 );
			}
			return false;
		}
		return true;
	},
	
	isAdmin: function() {
		// return true if user is logged in and admin, false otherwise
		// Note: This is used for UI decoration ONLY -- all privileges are checked on the server
		return( app.user && app.user.privileges && app.user.privileges.admin );
	},
	
	getNiceJob: function(job) {
		if (!job) return '(None)';
		var nice_id = job.id;
		// Job labels originate in plugin output, so always encode them before
		// composing HTML for the Home and History pages.
		if (job.label) nice_id = encode_entities(job.label) + ' (' + job.id + ')';
		return '<div style="white-space:nowrap;"><i class="fa fa-pie-chart">&nbsp;</i>' + nice_id + '</div>';
	},
	
	getNiceEvent: function(title, width) {
		if (!width) width = 500;
		if (!title) return '(None)';
		var icon_class = 'fa fa-clock-o';
		if (typeof(title) == 'object') {
			if (title.chain || title.chain_error) icon_class = 'fa fa-link';
			title = title.title;
		}
		return '<div class="ellip" style="max-width:'+width+'px;"><i class="' + icon_class + '">&nbsp;</i>' + title + '</div>';
	},
	
	getNiceCategory: function(cat, width) {
		if (!width) width = 500;
		if (!cat) return '(None)';
		var title = cat.title;
		if (!cat.enabled) title += ' (Disabled)';
		return '<div class="ellip" style="max-width:'+width+'px;"><i class="fa fa-folder-open-o">&nbsp;</i>' + title + '</div>';
	},
	
	getNiceGroup: function(group, target, width) {
		if (!width) width = 500;
		if (!group && !target) return '(None)';
		if (group) {
			var title = group.title;
			if (group.multiplex) title += '&nbsp;(<i class="fa fa-bolt" title="Multiplexed"></i>)';
			return '<div class="ellip" style="max-width:'+width+'px;"><i class="mdi mdi-server-network">&nbsp;</i>' + title + '</div>';
		}
		else {
			return '<div class="ellip" style="max-width:'+width+'px;" title="'+target+'"><i class="mdi mdi-desktop-tower mdi-lg">&nbsp;</i>' + target.replace(/\.[\w\-]+\.\w+$/, '') + '</div>';
		}
	},
	
	getNicePlugin: function(plugin, width) {
		if (!width) width = 500;
		if (!plugin) return '(None)';
		var title = plugin.title;
		if (!plugin.enabled) title += ' (Disabled)';
		return '<div class="ellip" style="max-width:'+width+'px;"><i class="fa fa-plug">&nbsp;</i>' + title + '</div>';
	},
	
	getNiceAPIKey: function(item, link, width) {
		if (!item) return 'n/a';
		if (!width) width = 500;
		var key = item.api_key || item.key;
		var title = item.api_title || item.title;
		
		var html = '<div class="ellip" style="max-width:'+width+'px;">';
		if (link && key) html += '<a href="#Admin?sub=edit_api_key&id='+item.id+'">';
		
		html += '<i class="mdi mdi-key-variant">&nbsp;</i>' + title;
		
		if (link && key) html += '</a>';
		html += '</div>';
		
		return html;
	},
	
	getNiceUsername: function(user, link, width) {
		if (!user) return 'n/a';
		if ((typeof(user) == 'object') && (user.key || user.api_title)) {
			return this.getNiceAPIKey(user, link, width);
		}
		if (!width) width = 500;
		var username = user.username ? user.username : user;
		if (!username || (typeof(username) != 'string')) return 'n/a';
		
		var html = '<div class="ellip" style="max-width:'+width+'px;">';
		if (link) html += '<a href="#Admin?sub=edit_user&username='+username+'">';
		
		html += '<i class="fa fa-user">&nbsp;&nbsp;</i>' + username;
		
		if (link) html += '</a>';
		html += '</div>';
		
		return html;
	},
	
	setGroupVisible: function(group, visible) {
		// set web groups of form fields visible or invisible, 
		// according to master checkbox for each section
		var selector = 'tr.' + group + 'group';
		if (visible) {
			if ($(selector).hasClass('collapse')) {
				$(selector).hide().removeClass('collapse');
			}
			$(selector).show(250);
		}
		else $(selector).hide(250);
		
		return this; // for chaining
	},
	
	checkUserExists: function(pre) {
		// check if user exists, update UI checkbox
		// called after field changes
		var username = trim($('#fe_'+pre+'_username').val().toLowerCase());
		var $elem = $('#d_'+pre+'_valid');
		
		if (username.match(/^[\w\-\.]+$/)) {
			// check with server
			// $elem.css('color','#444').html('<span class="fa fa-spinner fa-spin fa-lg">&nbsp;</span>');
			app.api.post('app/check_user_exists', { username: username }, function(resp) {
				if (resp.user_exists) {
					// username taken
					$elem.css('color','red').html('<span class="fa fa-exclamation-triangle fa-lg">&nbsp;</span>Username Taken');
				}
				else {
					// username is valid and available!
					$elem.css('color','green').html('<span class="fa fa-check-circle fa-lg">&nbsp;</span>Available');
				}
			} );
		}
		else if (username.length) {
			// bad username
			$elem.css('color','red').html('<span class="fa fa-exclamation-triangle fa-lg">&nbsp;</span>Bad Username');
		}
		else {
			// empty
			$elem.html('');
		}
	},
	
	check_add_remove_me: function($elem) {
		// check if user's e-mail is contained in text field or not
		var value = $elem.val().toLowerCase();
		var email = app.user.email.toLowerCase();
		var regexp = new RegExp( "\\b" + escape_regexp(email) + "\\b" );
		return !!value.match(regexp);
	},
	
	update_add_remove_me: function($elems) {
		// update add/remove me text based on if user's e-mail is contained in text field
		var self = this;
				
		$elems.each( function() {
			var $elem = $(this);
			var $span = $elem.next();
						
			if (self.check_add_remove_me($elem)) $span.html( '&raquo; Remove me' );
			else $span.html( '&laquo; Add me' );
		} );
	},
	
	add_remove_me: function($elem) {
		// toggle user's e-mail in/out of text field
		var value = trim( $elem.val().replace(/\,\s*\,/g, ',').replace(/^\s*\,\s*/, '').replace(/\s*\,\s*$/, '') );
		
		if (this.check_add_remove_me($elem)) {
			// remove e-mail
			var email = app.user.email.toLowerCase();
			var regexp = new RegExp( "\\b" + escape_regexp(email) + "\\b", "i" );
			value = value.replace( regexp, '' ).replace(/\,\s*\,/g, ',').replace(/^\s*\,\s*/, '').replace(/\s*\,\s*$/, '');
			$elem.val( trim(value) );
		}
		else {
			// add email
			if (value) value += ', ';
			$elem.val( value + app.user.email );
		}
		
		this.update_add_remove_me($elem);
	},
	
	get_custom_combo_unit_box: function(id, value, items, class_name) {
		// get HTML for custom combo text/menu, where menu defines units of measurement
		// items should be array for use in render_menu_options(), with an increasing numerical value
		if (!class_name) class_name = 'std_combo_unit_table';
		var units = 0;
		var value = parseInt( value || 0 );
		
		for (var idx = items.length - 1; idx >= 0; idx--) {
			var max = items[idx][0];
			if ((value >= max) && (value % max == 0)) {
				units = max;
				value = Math.floor( value / units );
				idx = -1;
			}
		}
		if (!units) {
			// no exact match, so default to first unit in list
			units = items[0][0];
			value = Math.floor( value / units );
		}
		
		return (
			'<table cellspacing="0" cellpadding="0" class="'+class_name+'"><tr>' + 
				'<td style="padding:0"><input type="text" id="'+id+'" style="width:30px;" value="'+value+'"/></td>' + 
				'<td style="padding:0"><select id="'+id+'_units">' + render_menu_options(items, units) + '</select></td>' + 
			'</tr></table>' 
		);
	},
	
	get_relative_time_combo_box: function(id, value, class_name, inc_seconds) {
		// get HTML for combo textfield/menu for a relative time based input
		// provides Minutes, Hours and Days units
		var unit_items = [[60,'Minutes'], [3600,'Hours'], [86400,'Days']];
		if (inc_seconds) unit_items.unshift( [1,'Seconds'] );
		
		return this.get_custom_combo_unit_box( id, value, unit_items, class_name );
	},
	
	get_relative_size_combo_box: function(id, value, class_name) {
		// get HTML for combo textfield/menu for a relative size based input
		// provides MB, GB and TB units
		var TB = 1024 * 1024 * 1024 * 1024;
		var GB = 1024 * 1024 * 1024;
		var MB = 1024 * 1024;
		var KB = 1024;
		
		return this.get_custom_combo_unit_box( id, value, [[KB, 'KB'], [MB,'MB'], [GB,'GB'], [TB,'TB']], class_name );
	},
	
	expand_fieldset: function($span) {
		// expand neighboring fieldset, and hide click control
		var $div = $span.parent();
		var $fieldset = $div.next();
		$fieldset.show( 350 );
		$div.hide( 350 );
	},
	
	collapse_fieldset: function($legend) {
		// collapse fieldset, and show click control again
		var $fieldset = $legend.parent();
		var $div = $fieldset.prev();
		$fieldset.hide( 350 );
		$div.show( 350 );
	},
	
	choose_date_time: function(args) {
		// show dialog for selecting a date/time
		// args: {
		//		when: default date/time (epoch or Date object, defaults to now)
		//		timezone: custom timezone (defaults to app.tz)
		//		title: dialog title
		//		description: optional description
		//		button: optional button label ("Select")
		//		callback: fired when complete, passed new date/time
		// }
		var self = this;
		var html = '';
		
		if (!args.when) args.when = time_now();
		if (!args.timezone) args.timezone = app.tz;
		if (!args.title) args.title = "Select Date/Time";
		if (!args.button) args.button = "Select";
		
		if (args.description) {
			html += '<div style="font-size:12px; color:#777; margin-bottom:20px;">' + args.description + '</div>';
		}
		
		// var dargs = get_date_args( args.when );
		var margs = moment.tz(args.when * 1000, args.timezone);
		
		html += '<center><table><tr>';
		
		// years
		var year_items = [];
		for (var idx = margs.year() - 10; idx <= margs.year() + 10; idx++) { 
			year_items.push(idx); 
		}
		html += '<td align="left"><fieldset class="dt_fs"><legend>Year</legend>';
		html += '<select id="fe_dt_year">' + render_menu_options(year_items, margs.year()) + '</select>';
		html += '</fieldset></td>';
		
		// months
		html += '<td align="left"><fieldset class="dt_fs" style="margin-left:5px;"><legend>Month</legend>';
		html += '<select id="fe_dt_month">' + render_menu_options(_months, margs.month() + 1) + '</select>';
		html += '</fieldset></td>';
		
		// days
		html += '<td align="left"><fieldset class="dt_fs" style="margin-left:5px;"><legend>Day</legend>';
		html += '<select id="fe_dt_day">' + render_menu_options(_days, margs.date()) + '</select>';
		html += '</fieldset></td>';
		
		// hours
		var hour_items = _hour_names.map( function(value, idx) {
			return [idx, value.toUpperCase().replace(/^(\d+)(\w+)$/, '$1 $2')];
		} );
		html += '<td align="left"><fieldset class="dt_fs" style="margin-left:5px;"><legend>Hour</legend>';
		html += '<select id="fe_dt_hour">' + render_menu_options(hour_items, margs.hour()) + '</select>';
		html += '</fieldset></td>';
		
		// minutes
		var min_items = [];
		for (var idx = 0; idx < 60; idx++) { 
			min_items.push([ idx, (idx < 10) ? ('0'+idx) : (''+idx) ]); 
		}
		html += '<td align="left"><fieldset class="dt_fs" style="margin-left:5px;"><legend>Minute</legend>';
		html += '<select id="fe_dt_minute">' + render_menu_options(min_items, margs.minute()) + '</select>';
		html += '</fieldset></td>';
		
		html += '</tr>';
		html += '<tr><td align="left" colspan="5">';
			html += '<div class="caption">Timezone: ' + args.timezone + '</div>';
		html += '</td></tr>';
		html += '</table></center>';
		
		app.confirm( '<i class="fa fa-calendar">&nbsp;</i>' + args.title, html, args.button, function(result) {
			app.clearError();
			
			if (result) {
				Dialog.hide();
				
				margs.year( parseInt( $('#fe_dt_year').val() ) );
				margs.month( parseInt( $('#fe_dt_month').val() ) - 1 );
				margs.date( parseInt( $('#fe_dt_day').val() ) );
				margs.hour( parseInt( $('#fe_dt_hour').val() ) );
				margs.minute( parseInt( $('#fe_dt_minute').val() ) );
				margs.second( 0 );
				
				args.callback( margs.unix() );
			}
		} ); // app.confirm
	},
	
	render_target_menu_options: function(value) {
		// render menu items for server group (target)
		// including optgroups for both server group and individual servers
		var html = '';
		
		var server_groups = app.server_groups.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} )
		.filter( function(group) {
			if (!app.user.privileges.grp_limit) return true; // user is not limited by groups
			return app.hasPrivilege( 'grp_' + group.id );
		});
		
		html += '<optgroup label="Groups:">' + render_menu_options(server_groups, value, false) + '</optgroup>';
		
		if (find_object(server_groups, { id: value })) value = '';
		
		// trim hostname suffixes
		var hostnames = hash_keys_to_array(app.servers).sort();
		if (value && !app.servers[value]) hostnames.push( value );
		
		// filter hostnames by server group privilege
		if (app.user.privileges.grp_limit) {
			hostnames = hostnames.filter(function(hostname) {
				var groups = server_groups.filter( function(group) {
					return hostname.match( group.regexp );
				} );
				
				// we just need one group to match, then the user has permission to target the server
				for (var idx = 0, len = groups.length; idx < len; idx++) {
					priv_id = 'grp_' + groups[idx].id;
					result = app.hasPrivilege(priv_id);
					if (result) return true;
				}
				return false;
			});
		} // grp_limit
		
		var short_hostnames = [];
		for (var idx = 0, len = hostnames.length; idx < len; idx++) {
			short_hostnames.push([ hostnames[idx], hostnames[idx].replace(/\.[\w\-]+\.\w+$/, '') ]);
		}
		
		html += '<optgroup label="Servers:">' + render_menu_options(short_hostnames, value, false) + '</optgroup>';
		return html;
	}
	
} );

Class.subclass( Page.Base, "Page.Home", {	
	
	bar_width: 100,
	
	onInit: function() {
		// called once at page load
		this.worker = new Worker('js/home-worker.js');
		this.worker.onmessage = this.render_upcoming_events.bind(this);
		
		var html = '';
		html += '<div style="padding:10px 20px 20px 20px">';
		
		// header stats
		html += '<div id="d_home_header_stats"></div>';
		html += '<div style="height:20px;"></div>';
		
		// active jobs
		html += '<div class="subtitle">';
			html += 'Active Jobs';
			html += '<div class="clear"></div>';
		html += '</div>';
		html += '<div id="d_home_active_jobs"></div>';
		html += '<div style="height:20px;"></div>';
		
		// queued jobs
		html += '<div id="d_home_queue_container" style="display:none">';
			html += '<div class="subtitle">';
				html += 'Event Queues';
				html += '<div class="clear"></div>';
			html += '</div>';
			html += '<div id="d_home_queued_jobs"></div>';
			html += '<div style="height:20px;"></div>';
		html += '</div>';
		
		// upcoming events
		html += '<div id="d_home_upcoming_header" class="subtitle">';
		html += '</div>';
		html += '<div id="d_home_upcoming_events" class="loading"></div>';
		html += '</div>'; // container
		
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		this.args = args;
		
		app.setWindowTitle('Home');
		app.showTabBar(true);
		
		this.upcoming_offset = 0;
		
		// presort some stuff for the filter menus
		app.categories.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		app.plugins.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		// render upcoming event filters
		var html = '';
		html += 'Upcoming Events';
		
		html += '<div class="subtitle_widget"><i class="fa fa-search">&nbsp;</i><input type="text" id="fe_home_keywords" size="10" placeholder="Find events..." style="border:0px;" value="' + escape_text_field_value( args.keywords ) + '"/></div>';
		
		html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_home_target" class="subtitle_menu" style="width:75px;" onChange="$P().set_search_filters()"><option value="">All Servers</option>' + this.render_target_menu_options( args.target ) + '</select></div>';
		html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_home_plugin" class="subtitle_menu" style="width:75px;" onChange="$P().set_search_filters()"><option value="">All Plugins</option>' + render_menu_options( app.plugins, args.plugin, false ) + '</select></div>';
		html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_home_cat" class="subtitle_menu" style="width:95px;" onChange="$P().set_search_filters()"><option value="">All Categories</option>' + render_menu_options( app.categories, args.category, false ) + '</select></div>';
		
		html += '<div class="clear"></div>';
		
		$('#d_home_upcoming_header').html( html );
		
		setTimeout( function() {
			$('#fe_home_keywords').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().set_search_filters();
				}
			} ); 
		}, 1 );
		
		// refresh datas
		$('#d_home_active_jobs').html( this.get_active_jobs_html() );
		this.refresh_upcoming_events();
		this.refresh_header_stats();
		this.refresh_event_queues();
		
		return true;
	},
	
	refresh_header_stats: function() {
		// refresh daemons stats in header fieldset
		var html = '';
		var stats = app.state ? (app.state.stats || {}) : {};
		var servers = app.servers || {};
		
		html += '<fieldset style="margin-top:0px; margin-right:0px; padding-top:10px;"><legend>Server Stats</legend>';
			
			html += '<div style="float:left; width:25%;">';
				var active_events = find_objects( app.schedule, { enabled: 1 } );
				
				html += '<div class="info_label">TOTAL EVENTS</div>';
				html += '<div class="info_value">' + commify( active_events.length ) + '</div>';
				
				html += '<div class="info_label">TOTAL CATEGORIES</div>';
				html += '<div class="info_value">' + commify( app.categories.length ) + '</div>';
				
				html += '<div class="info_label">TOTAL PLUGINS</div>';
				html += '<div class="info_value">' + commify( app.plugins.length ) + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">JOBS COMPLETED TODAY</div>';
				html += '<div class="info_value">' + commify( stats.jobs_completed || 0 ) + '</div>';
				
				html += '<div class="info_label">JOBS FAILED TODAY</div>';
				html += '<div class="info_value">' + commify( stats.jobs_failed || 0 ) + '</div>';
				
				html += '<div class="info_label">JOB SUCCESS RATE</div>';
				html += '<div class="info_value">' + pct( (stats.jobs_completed || 0) - (stats.jobs_failed || 0), stats.jobs_completed || 1 ) + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">TOTAL SERVERS</div>';
				html += '<div class="info_value">' + commify( num_keys(servers) ) + '</div>';
				
				var total_cpu = 0;
				var total_mem = 0;
				for (var hostname in servers) {
					// daemon process cpu, all servers
					var server = servers[hostname];
					if (server.data && !server.disabled) {
						total_cpu += (server.data.cpu || 0);
						total_mem += (server.data.mem || 0);
					}
				}
				for (var id in app.activeJobs) {
					// active job process cpu, all jobs
					var job = app.activeJobs[id];
					if (job.cpu) total_cpu += (job.cpu.current || 0);
					if (job.mem) total_mem += (job.mem.current || 0);
				}
				html += '<div class="info_label">TOTAL CPU IN USE</div>';
				html += '<div class="info_value">' + short_float(total_cpu) + '%</div>';
				
				html += '<div class="info_label">TOTAL RAM IN USE</div>';
				html += '<div class="info_value">' + get_text_from_bytes(total_mem) + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				var mserver = servers[ app.masterHostname ] || {};
				html += '<div class="info_label">MASTER SERVER UPTIME</div>';
				html += '<div class="info_value">' + get_text_from_seconds( mserver.uptime || 0, false, true ) + '</div>';
				
				var job_avg = (stats.jobs_elapsed || 0) / (stats.jobs_completed || 1);
				html += '<div class="info_label">AVERAGE JOB DURATION</div>';
				html += '<div class="info_value">' + get_text_from_seconds( job_avg, false, true ) + '</div>';
				
				var log_size_avg = (stats.jobs_log_size || 0) / (stats.jobs_completed || 1);
				html += '<div class="info_label">AVERAGE JOB LOG SIZE</div>';
				html += '<div class="info_value">' + get_text_from_bytes(log_size_avg) + '</div>';
			html += '</div>';
			
			html += '<div class="clear"></div>';
		html += '</fieldset>';
		
		$('#d_home_header_stats').html( html );
	},
	
	refresh_upcoming_events: function() {
		// send message to worker to refresh upcoming
		this.worker_start_time = hires_time_now();
		this.worker.postMessage({
			default_tz: app.tz,
			schedule: app.schedule,
			state: app.state,
			categories: app.categories,
			plugins: app.plugins
		});
	},
	
	nav_upcoming: function(offset) {
		// refresh upcoming events with new offset
		this.upcoming_offset = offset;
		this.render_upcoming_events({
			data: this.upcoming_events
		});
	},
	
	set_search_filters: function() {
		// grab values from search filters, and refresh
		var args = this.args;
		
		args.plugin = $('#fe_home_plugin').val();
		if (!args.plugin) delete args.plugin;
		
		args.target = $('#fe_home_target').val();
		if (!args.target) delete args.target;
		
		args.category = $('#fe_home_cat').val();
		if (!args.category) delete args.category;
		
		args.keywords = $('#fe_home_keywords').val();
		if (!args.keywords) delete args.keywords;
		
		this.nav_upcoming(0);
	},
	
	render_upcoming_events: function(e) {
		// receive data from worker, render table now
		var self = this;
		var html = '';
		var now = app.epoch || hires_time_now();
		var args = this.args;
		this.upcoming_events = e.data;
		
		/*var elapsed = now - this.worker_start_time;
		delete this.worker_start_time;
		Debug.trace('Home', "Worker elapsed time: " + elapsed + ' sec for ' + app.schedule.length + ' events.');*/
		
		// apply filters
		var events = [];
		
		for (var idx = 0, len = e.data.length; idx < len; idx++) {
			var stub = e.data[idx];
			var item = find_object( app.schedule, { id: stub.id } ) || {};
			
			// category filter
			if (args.category && (item.category != args.category)) continue;

			// plugin filter
			if (args.plugin && (item.plugin != args.plugin)) continue;
			
			// server group filter
			if (args.target && (item.target != args.target)) continue;
			
			// keyword filter
			var words = [item.title, item.username, item.notes, item.target].join(' ').toLowerCase();
			if (args.keywords && words.indexOf(args.keywords.toLowerCase()) == -1) continue;
			
			events.push( stub );
		} // foreach item in schedule
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 50) / 7 );
		
		var cols = ['Event Name', 'Category', 'Plugin', 'Target', 'Scheduled Time', 'Countdown', 'Actions'];
		var limit = 25;
		
		html += this.getPaginatedTable({
			resp: {
				rows: events.slice(this.upcoming_offset, this.upcoming_offset + limit),
				list: {
					length: events.length
				}
			},
			cols: cols,
			data_type: 'pending event',
			limit: limit,
			offset: this.upcoming_offset,
			pagination_link: '$P().nav_upcoming',
			
			callback: function(stub, idx) {
				var item = find_object( app.schedule, { id: stub.id } ) || {};
				// var dargs = get_date_args( stub.epoch );
				var margs = moment.tz(stub.epoch * 1000, item.timezone || app.tz);
				
				var actions = [
					'<a href="#Schedule?sub=edit_event&id='+item.id+'"><b>Edit Event</b></a>'
				];
				
				var cat = item.category ? find_object( app.categories, { id: item.category } ) : null;
				var group = item.target ? find_object( app.server_groups, { id: item.target } ) : null;
				var plugin = item.plugin ? find_object( app.plugins, { id: item.plugin } ) : null;
				
				var nice_countdown = 'Now';
				if (stub.epoch > now) {
					nice_countdown = get_text_from_seconds_round( Math.max(60, stub.epoch - now), false );
				}
				
				if (group && item.multiplex) {
					group = copy_object(group);
					group.multiplex = 1;
				}
				
				var tds = [
					'<div class="td_big" style="white-space:nowrap;"><a href="#Schedule?sub=edit_event&id='+item.id+'">' + self.getNiceEvent('<b>' + item.title + '</b>', col_width) + '</a></div>',
					self.getNiceCategory( cat, col_width ),
					self.getNicePlugin( plugin, col_width ),
					self.getNiceGroup( group, item.target, col_width ),
					// dargs.hour12 + ':' + dargs.mi + ' ' + dargs.ampm.toUpperCase(),
					margs.format("h:mm A z"),
					nice_countdown,
					actions.join(' | ')
				];
				
				if (cat && cat.color) {
					if (tds.className) tds.className += ' '; else tds.className = '';
					tds.className += cat.color;
				}
				
				return tds;
			} // row callback
		}); // table
		
		$('#d_home_upcoming_events').removeClass('loading').html( html );
	},
	
	get_active_jobs_html: function() {
		// get html for active jobs table
		var html = '';
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 50) / 8 );
		
		// copy jobs to array
		var jobs = [];
		for (var id in app.activeJobs) {
			jobs.push( app.activeJobs[id] );
		}
		
		// sort events by time_start descending
		this.jobs = jobs.sort( function(a, b) {
			return (a.time_start < b.time_start) ? 1 : -1;
		} );
		
		var cols = ['Job ID', 'Event Name', 'Category', 'Hostname', 'Elapsed', 'Progress', 'Remaining', 'Actions'];
		
		// render table
		var self = this;
		html += this.getBasicTable( this.jobs, cols, 'active job', function(job, idx) {
			var actions = [
				// '<span class="link" onMouseUp="$P().go_job_details('+idx+')"><b>Details</b></span>',
				'<span class="link" onMouseUp="$P().abort_job('+idx+')"><b>Abort Job</b></span>'
			];
			
			var cat = job.category ? find_object( app.categories || [], { id: job.category } ) : { title: 'n/a' };
			// var group = item.target ? find_object( app.server_groups || [], { id: item.target } ) : null;
			var plugin = job.plugin ? find_object( app.plugins || [], { id: job.plugin } ) : { title: 'n/a' };
			var tds = null;
			
			if (job.pending && job.log_file) {
				// job in retry delay
				tds = [
					'<div class="td_big"><span class="link" onMouseUp="$P().go_job_details('+idx+')">' + self.getNiceJob(job) + '</span></div>',
					self.getNiceEvent( job.event_title, col_width ),
					self.getNiceCategory( cat, col_width ),
					// self.getNicePlugin( plugin ),
					self.getNiceGroup( null, job.hostname, col_width ),
					'<div id="d_home_jt_elapsed_'+job.id+'">' + self.getNiceJobElapsedTime(job) + '</div>',
					'<div id="d_home_jt_progress_'+job.id+'">' + self.getNiceJobPendingText(job) + '</div>',
					'n/a',
					actions.join(' | ')
				];
			}
			else if (job.pending) {
				// multiplex stagger delay
				tds = [
					'<div class="td_big">' + self.getNiceJob(job) + '</div>',
					self.getNiceEvent( job.event_title, col_width ),
					self.getNiceCategory( cat, col_width ),
					// self.getNicePlugin( plugin ),
					self.getNiceGroup( null, job.hostname, col_width ),
					'n/a',
					'<div id="d_home_jt_progress_'+job.id+'">' + self.getNiceJobPendingText(job) + '</div>',
					'n/a',
					actions.join(' | ')
				];
			} // pending job
			else {
				// active job
				tds = [
					'<div class="td_big"><span class="link" onMouseUp="$P().go_job_details('+idx+')">' + self.getNiceJob(job) + '</span></div>',
					self.getNiceEvent( job.event_title, col_width ),
					self.getNiceCategory( cat, col_width ),
					// self.getNicePlugin( plugin ),
					self.getNiceGroup( null, job.hostname, col_width ),
					'<div id="d_home_jt_elapsed_'+job.id+'">' + self.getNiceJobElapsedTime(job) + '</div>',
					'<div id="d_home_jt_progress_'+job.id+'">' + self.getNiceJobProgressBar(job) + '</div>',
					'<div id="d_home_jt_remaining_'+job.id+'">' + self.getNiceJobRemainingTime(job) + '</div>',
					actions.join(' | ')
				];
			} // active job
			
			if (cat && cat.color) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += cat.color;
			}
			
			return tds;
		} );
		
		return html;
	},
	
	refresh_event_queues: function() {
		// update display of event queues, if any
		var self = this;
		var total_count = 0;
		for (var key in app.eventQueue) {
			total_count += app.eventQueue[key] || 0;
		}
		
		if (!total_count) {
			$('#d_home_queue_container').hide();
			return;
		}
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 50) / 6 );
		var cols = ['Event Name', 'Category', 'Plugin', 'Target', 'Queued Jobs', 'Actions'];
		
		var stubs = [];
		var sorted_ids = hash_keys_to_array(app.eventQueue).sort( function(a, b) {
			return (app.eventQueue[a] < app.eventQueue[b]) ? 1 : -1;
		} );
		sorted_ids.forEach( function(id) {
			if (app.eventQueue[id]) stubs.push({ id: id });
		} );
		
		this.queue_stubs = stubs;
		
		// render table
		var html = '';
		html += this.getBasicTable( stubs, cols, 'event', function(stub, idx) {
			var queue_count = app.eventQueue[ stub.id ] || 0;
			var item = find_object( app.schedule, { id: stub.id } ) || {};
			
			// for flush dialog
			stub.title = item.title;
			
			var cat = item.category ? find_object( app.categories, { id: item.category } ) : null;
			var group = item.target ? find_object( app.server_groups, { id: item.target } ) : null;
			var plugin = item.plugin ? find_object( app.plugins, { id: item.plugin } ) : null;
			
			var actions = [
				'<span class="link" onMouseUp="$P().flush_event_queue('+idx+')"><b>Flush Queue</b></span>'
			];
			
			var tds = [
				'<div class="td_big" style="white-space:nowrap;"><a href="#Schedule?sub=edit_event&id='+item.id+'">' + self.getNiceEvent('<b>' + item.title + '</b>', col_width) + '</a></div>',
				self.getNiceCategory( cat, col_width ),
				self.getNicePlugin( plugin, col_width ),
				self.getNiceGroup( group, item.target, col_width ),
				commify( queue_count ),
				actions.join(' | ')
			];
			
			if (cat && cat.color) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += cat.color;
			}
			
			return tds;
			
		} ); // getBasicTable
		
		$('#d_home_queued_jobs').html( html );
		$('#d_home_queue_container').show();
	},
	
	go_job_details: function(idx) {
		// jump to job details page
		var job = this.jobs[idx];
		Nav.go( '#JobDetails?id=' + job.id );
	},
	
	abort_job: function(idx) {
		// abort job, after confirmation
		var job = this.jobs[idx];
		
		app.confirm( '<span style="color:red">Abort Job</span>', "Are you sure you want to abort the job &ldquo;<b>"+job.id+"</b>&rdquo;?</br>(Event: "+job.event_title+")", "Abort", function(result) {
			if (result) {
				app.showProgress( 1.0, "Aborting job..." );
				app.api.post( 'app/abort_job', job, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Job '"+job.event_title+"' was aborted successfully.");
				} );
			}
		} );
	},
	
	flush_event_queue: function(idx) {
		// abort job, after confirmation
		var stub = this.queue_stubs[idx];
		
		app.confirm( '<span style="color:red">Flush Event Queue</span>', "Are you sure you want to flush the queue for event &ldquo;<b>"+stub.title+"</b>&rdquo;?", "Flush", function(result) {
			if (result) {
				app.showProgress( 1.0, "Flushing event queue..." );
				app.api.post( 'app/flush_event_queue', stub, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Event queue for '"+stub.title+"' was flushed successfully.");
				} );
			}
		} );
	},
	
	getNiceJobElapsedTime: function(job) {
		// render nice elapsed time display
		var elapsed = Math.floor( Math.max( 0, app.epoch - job.time_start ) );
		return get_text_from_seconds( elapsed, true, false );
	},
	
	getNiceJobProgressBar: function(job) {
		// render nice progress bar for job
		var html = '';
		var counter = Math.min(1, Math.max(0, job.progress || 1));
		var cx = Math.floor( counter * this.bar_width );
		var extra_classes = '';
		var extra_attribs = '';
		if (counter == 1.0) extra_classes = 'indeterminate';
		else extra_attribs = 'title="'+Math.floor( (counter / 1.0) * 100 )+'%"';
		
		html += '<div class="progress_bar_container '+extra_classes+'" style="width:'+this.bar_width+'px; margin:0;" '+extra_attribs+'>';
			html += '<div class="progress_bar_inner" style="width:'+cx+'px;"></div>';
		html += '</div>';
		
		return html;
	},
	
	getNiceJobRemainingTime: function(job) {
		// get nice job remaining time, using elapsed and progress
		var elapsed = Math.floor( Math.max( 0, app.epoch - job.time_start ) );
		var progress = job.progress || 0;
		if ((elapsed >= 10) && (progress > 0) && (progress < 1.0)) {
			var sec_remain = Math.floor(((1.0 - progress) * elapsed) / progress);
			return get_text_from_seconds( sec_remain, true, true );
		}
		else return 'n/a';
	},
	
	getNiceJobPendingText: function(job) {
		// get nice display for pending job status
		var html = '';
		
		// if job has a log_file, it's in a retry delay, otherwise it's pending (multiplex stagger)
		html += (job.log_file ? 'Retry' : 'Pending');
		
		// countdown to actual launch
		var nice_countdown = get_text_from_seconds( Math.max(0, job.when - app.epoch), true, true );
		html += ' (' + nice_countdown + ')';
		
		return html;
	},
	
	onStatusUpdate: function(data) {
		// received status update (websocket), update page if needed
		if (data.jobs_changed) {
			// refresh tables
			$('#d_home_active_jobs').html( this.get_active_jobs_html() );
		}
		else {
			// update progress, time remaining, no refresh
			for (var id in app.activeJobs) {
				var job = app.activeJobs[id];
				
				if (job.pending) {
					// update countdown
					$('#d_home_jt_progress_' + job.id).html( this.getNiceJobPendingText(job) );
					
					if (job.log_file) {
						// retry delay
						$('#d_home_jt_elapsed_' + job.id).html( this.getNiceJobElapsedTime(job) );
					}
				} // pending job
				else {
					$('#d_home_jt_elapsed_' + job.id).html( this.getNiceJobElapsedTime(job) );
					$('#d_home_jt_remaining_' + job.id).html( this.getNiceJobRemainingTime(job) );
					
					// update progress bar without redrawing it (so animation doesn't jitter)
					var counter = job.progress || 1;
					var cx = Math.floor( counter * this.bar_width );
					var prog_cont = $('#d_home_jt_progress_' + job.id + ' > div.progress_bar_container');
					
					if ((counter == 1.0) && !prog_cont.hasClass('indeterminate')) {
						prog_cont.addClass('indeterminate').attr('title', "");
					}
					else if ((counter < 1.0) && prog_cont.hasClass('indeterminate')) {
						prog_cont.removeClass('indeterminate');
					}
					
					if (counter < 1.0) prog_cont.attr('title', '' + Math.floor( (counter / 1.0) * 100 ) + '%');
					
					prog_cont.find('> div.progress_bar_inner').css( 'width', '' + cx + 'px' );
				} // active job
			} // foreach job
		} // quick update
	},
	
	onDataUpdate: function(key, value) {
		// recieved data update (websocket)
		switch (key) {
			case 'state':
			case 'schedule':
				// state update (new cursors)
				// $('#d_home_upcoming_events').html( this.get_upcoming_events_html() );
				this.refresh_upcoming_events();
				this.refresh_header_stats();
			break;
			
			case 'eventQueue':
				this.refresh_event_queues();
			break;
		}
	},
	
	onResizeDelay: function(size) {
		// called 250ms after latest window resize
		// so we can run more expensive redraw operations
		$('#d_home_active_jobs').html( this.get_active_jobs_html() );
		this.refresh_header_stats();
		this.refresh_event_queues();
		
		if (this.upcoming_events) {
			this.render_upcoming_events({
				data: this.upcoming_events
			});
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		// this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Login", {	
	
	onInit: function() {
		// called once at page load
		// var html = 'Now is the time (LOGIN)';
		// this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (app.user) {
			// user already logged in
			setTimeout( function() { Nav.go(app.navAfterLogin || config.DefaultPage) }, 1 );
			return true;
		}
		else if (args.u && args.h) {
			this.showPasswordResetForm(args);
			return true;
		}
		else if (args.create) {
			this.showCreateAccountForm();
			return true;
		}
		else if (args.recover) {
			this.showRecoverPasswordForm();
			return true;
		}
		
		app.setWindowTitle('Login');
		app.showTabBar(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">User Login</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
					html += '<tr>';
						html += '<td align="right" class="table_label">Username:</td>';
						html += '<td align="left" class="table_value"><div><input type="text" name="username" id="fe_login_username" size="30" spellcheck="false" value="'+(app.getPref('username') || '')+'"/></div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
					html += '<tr>';
						html += '<td align="right" class="table_label">Password:</td>';
						html += '<td align="left" class="table_value"><div><input type="' + app.get_password_type() + '" name="password" id="fe_login_password" size="30" spellcheck="false" value=""/>' + app.get_password_toggle_html() + '</div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
				html += '</table></center>';
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				if (config.free_accounts) {
					html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().navCreateAccount()">Create Account...</div></td>';
					html += '<td width="20">&nbsp;</td>';
				}
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().navPasswordRecovery()">Forgot Password...</div></td>';
				html += '<td width="20">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().doLogin()"><i class="fa fa-sign-in">&nbsp;&nbsp;</i>Login</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		// html += '<input type="submit" value="Login" style="position:absolute; left:-9999px; top:0px;">';
		html += '</form>';
		this.div.html( html );
		
		setTimeout( function() {
			$( app.getPref('username') ? '#fe_login_password' : '#fe_login_username' ).focus();
			
			 $('#fe_login_username, #fe_login_password').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().doLogin();
				}
			} ); 
			
		}, 1 );
		
		return true;
	},
	
	/*doLoginFormSubmit: function() {
		// force login form to submit
		$('#f_login')[0].submit();
	},
	
	doFrameLogin: function(resp) {
		// login from IFRAME redirect
		// alert("GOT HERE FROM IFRAME " + JSON.stringify(resp));
		this.tempFrameResp = JSON.parse( JSON.stringify(resp) );
		setTimeout( '$P().doFrameLogin2()', 1 );
	},
	
	doFrameLogin2: function() {
		// login from IFRAME redirect
		var resp = this.tempFrameResp;
		delete this.tempFrameResp;
		
		Debug.trace("IFRAME Response: " + JSON.stringify(resp));
		
		if (resp.code) {
			return app.doError( resp.description );
		}
		
		Debug.trace("IFRAME User Login: " + resp.username + ": " + resp.session_id);
		
		app.clearError();
		app.hideProgress();
		app.doUserLogin( resp );
		
		Nav.go( app.navAfterLogin || config.DefaultPage );
		// alert("GOT HERE: " + (app.navAfterLogin || config.DefaultPage) );
	},*/
	
	 doLogin: function() {
		// attempt to log user in
		var username = $('#fe_login_username').val().toLowerCase();
		var password = $('#fe_login_password').val();
		
		if (username && password) {
			app.showProgress(1.0, "Logging in...");
			
			app.api.post( 'user/login', {
				username: username,
				password: password
			}, 
			function(resp, tx) {
				Debug.trace("User Login: " + username + ": " + resp.session_id);
				
				app.hideProgress();
				app.doUserLogin( resp );
				
				Nav.go( app.navAfterLogin || config.DefaultPage );
			} ); // post
		}
	}, 
	
	cancel: function() {
		// return to login page
		app.clearError();
		Nav.go('Login', true);
	},
	
	navCreateAccount: function() {
		// nav to create account form
		app.clearError();
		Nav.go('Login?create=1', true);
	},
	
	showCreateAccountForm: function() {
		// allow user to create a new account
		app.setWindowTitle('Create Account');
		app.showTabBar(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">Create Account</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
				
				html += get_form_table_row( 'Username:', 
					'<table cellspacing="0" cellpadding="0"><tr>' + 
						'<td><input type="text" id="fe_ca_username" size="20" style="font-size:14px;" value="" spellcheck="false" onChange="$P().checkUserExists(\'ca\')"/></td>' + 
						'<td><div id="d_ca_valid" style="margin-left:5px; font-weight:bold;"></div></td>' + 
					'</tr></table>'
				);
				
				html += get_form_table_caption('Choose a unique alphanumeric username for your account.') + 
				get_form_table_spacer() + 
				get_form_table_row('Password:', '<input type="' + app.get_password_type() + '" id="fe_ca_password" size="30" value="" spellcheck="false"/>' + app.get_password_toggle_html()) + 
				get_form_table_caption('Enter a secure password that you will not forget.') + 
				get_form_table_spacer() + 
				get_form_table_row('Full Name:', '<input type="text" id="fe_ca_fullname" size="30" value="" spellcheck="false"/>') + 
				get_form_table_caption('This is used for display purposes only.') + 
				get_form_table_spacer() + 
				get_form_table_row('Email Address:', '<input type="text" id="fe_ca_email" size="30" value="" spellcheck="false"/>') + 
				get_form_table_caption('This is used only to recover your password should you lose it.');
					
				html += '</table></center>';
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().doCreateAccount()"><i class="fa fa-user-plus">&nbsp;&nbsp;</i>Create</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		this.div.html( html );
		
		setTimeout( function() {
			$( '#fe_ca_username' ).focus();
			app.password_strengthify( '#fe_ca_password' );
		}, 1 );
	},
	
	doCreateAccount: function(force) {
		// actually create account
		app.clearError();
		
		var username = trim($('#fe_ca_username').val().toLowerCase());
		var email = trim($('#fe_ca_email').val());
		var full_name = trim($('#fe_ca_fullname').val());
		var password = trim($('#fe_ca_password').val());
		
		if (!username.length) {
			return app.badField('#fe_ca_username', "Please enter a username for your account.");
		}
		if (!username.match(/^[\w\-\.]+$/)) {
			return app.badField('#fe_ca_username', "Please make sure your username contains only alphanumerics, dashes and periods.");
		}
		if (!email.length) {
			return app.badField('#fe_ca_email', "Please enter an e-mail address where you can be reached.");
		}
		if (!email.match(/^\S+\@\S+$/)) {
			return app.badField('#fe_ca_email', "The e-mail address you entered does not appear to be correct.");
		}
		if (!full_name.length) {
			return app.badField('#fe_ca_fullname', "Please enter your first and last names. These are used only for display purposes.");
		}
		if (!password.length) {
			return app.badField('#fe_ca_password', "Please enter a secure password to protect your account.");
		}
		if (!force && (app.last_password_strength.score < 3)) {
			app.confirm( '<span style="color:red">Insecure Password Warning</span>', app.get_password_warning(), "Proceed", function(result) {
				if (result) $P().doCreateAccount('force');
			} );
			return;
		} // insecure password
		
		Dialog.hide();
		app.showProgress( 1.0, "Creating account..." );
		
		app.api.post( 'user/create', {
			username: username,
			email: email,
			password: password,
			full_name: full_name
		}, 
		function(resp, tx) {
			app.hideProgress();
			app.showMessage('success', "Account created successfully.");
			
			app.setPref('username', username);
			Nav.go( 'Login', true );
		} ); // api.post
	},
	
	navPasswordRecovery: function() {
		// nav to recover password form
		app.clearError();
		Nav.go('Login?recover=1', true);
	},
	
	showRecoverPasswordForm: function() {
		// allow user to create a new account
		app.setWindowTitle('Forgot Password');
		app.showTabBar(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">Forgot Password</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
				
				html += get_form_table_row('Username:', '<input type="text" id="fe_pr_username" size="30" value="" spellcheck="false"/>') + 
				get_form_table_spacer() + 
				get_form_table_row('Email Address:', '<input type="text" id="fe_pr_email" size="30" value="" spellcheck="false"/>');
				
				html += '</table></center>';
				
				html += '<div class="caption" style="margin-top:15px;">Please enter the username and e-mail address associated with your account, and we will send you instructions for resetting your password.</div>';
				
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().doSendRecoveryEmail()"><i class="fa fa-envelope-o">&nbsp;&nbsp;</i>Send Email</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		this.div.html( html );
		
		setTimeout( function() { 
			$('#fe_pr_username, #fe_pr_email').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().doSendEmail();
				}
			} );
			$( '#fe_pr_username' ).focus();
		}, 1 );
	},
	
	doSendRecoveryEmail: function() {
		// send password recovery e-mail
		app.clearError();
		
		var username = trim($('#fe_pr_username').val()).toLowerCase();
		var email = trim($('#fe_pr_email').val());
		
		if (username.match(/^[\w.-]+$/)) {
			if (email.match(/.+\@.+/)) {
				Dialog.hide();
				app.showProgress( 1.0, "Sending e-mail..." );
				app.api.post( 'user/forgot_password', {
					username: username,
					email: email
				}, 
				function(resp, tx) {
					app.hideProgress();
					app.showMessage('success', "Password reset instructions sent successfully.");
					Nav.go('Login', true);
				} ); // api.post
			} // good address
			else app.badField('#fe_pr_email', "The e-mail address you entered does not appear to be correct.");
		} // good username
		else app.badField('#fe_pr_username', "The username you entered does not appear to be correct.");
	},
	
	showPasswordResetForm: function(args) {
		// show password reset form
		this.recoveryKey = args.h;
		
		app.setWindowTitle('Reset Password');
		app.showTabBar(false);
		
		this.div.css({ 'padding-top':'75px', 'padding-bottom':'75px' });
		var html = '';
		
		html += '<div class="inline_dialog_container">';
			html += '<div class="dialog_title shade-light">Reset Password</div>';
			html += '<div class="dialog_content">';
				html += '<center><table style="margin:0px;">';
					html += '<tr>';
						html += '<td align="right" class="table_label">Username:</td>';
						html += '<td align="left" class="table_value"><div><input type="text" name="username" id="fe_reset_username" size="30" spellcheck="false" value="' + encode_attrib_entities(args.u) + '" disabled="disabled"/></div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
					html += '<tr>';
						html += '<td align="right" class="table_label">New Password:</td>';
						html += '<td align="left" class="table_value"><div><input type="' + app.get_password_type() + '" name="password" id="fe_reset_password" size="30" spellcheck="false" value=""/>' + app.get_password_toggle_html() + '</div></td>';
					html += '</tr>';
					html += '<tr><td colspan="2"><div class="table_spacer"></div></td></tr>';
				html += '</table></center>';
			html += '</div>';
			
			html += '<div class="dialog_buttons"><center><table><tr>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().doResetPassword()"><i class="fa fa-key">&nbsp;&nbsp;</i>Reset Password</div></td>';
			html += '</tr></table></center></div>';
		html += '</div>';
		
		this.div.html( html );
		
		setTimeout( function() {
			$( '#fe_reset_password' ).focus();
			$('#fe_reset_password').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().doResetPassword();
				}
			} );
			app.password_strengthify( '#fe_reset_password' );
		}, 1 );
	},
	
	doResetPassword: function(force) {
		// reset password now
		var username = $('#fe_reset_username').val().toLowerCase();
		var new_password = $('#fe_reset_password').val();
		var recovery_key = this.recoveryKey;
		
		if (username && new_password) {
			if (!force && (app.last_password_strength.score < 3)) {
				app.confirm( '<span style="color:red">Insecure Password Warning</span>', app.get_password_warning(), "Proceed", function(result) {
					if (result) $P().doResetPassword('force');
				} );
				return;
			} // insecure password
			
			app.showProgress(1.0, "Resetting password...");
			
			app.api.post( 'user/reset_password', {
				username: username,
				key: recovery_key,
				new_password: new_password
			}, 
			function(resp, tx) {
				Debug.trace("User password was reset: " + username);
				
				app.hideProgress();
				app.setPref('username', username);
				
				Nav.go( 'Login', true );
				
				setTimeout( function() {
					app.showMessage('success', "Your password was reset successfully.");
				}, 100 );
			} ); // post
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Schedule", {	
	
	default_sub: 'events',
	
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		if (!args.sub) args.sub = this.default_sub;
		this.args = args;
		
		app.showTabBar(true);
		// this.tab[0]._page_id = Nav.currentAnchor();
		
		this.div.addClass('loading');
		this['gosub_'+args.sub](args);
		
		return true;
	},
	
	gosub_events: function(args) {
		// render table of events with filters and search
		this.div.removeClass('loading');
		app.setWindowTitle( "Scheduled Events" );
		
		var size = get_inner_window_size();
		var col_width = 600;
		var group_by = app.getPref('schedule_group_by');
		var html = '';
		
		/* html += this.getSidebarTabs( 'categories',
			[
				['categories', "Categories"],
				['servers', "Servers"],
				['plugins', "Plugins"],
				['users', "Users"]
			]
		); */
		
		// presort some stuff for the filter menus
		app.categories.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		app.plugins.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		// render table
		var cols = [
			config.hide_schedule_checkboxes ? '&nbsp;' : '<i class="fa fa-check-square-o"></i>', 
			'Event Name', 
			'Category', 
			'Plugin', 
			'Target', 
			'Timing', 
			'Status', 
			'Actions'
		];
		
		html += '<div style="padding:20px 20px 20px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Scheduled Events';
			
			html += '<div class="subtitle_widget"><i class="fa fa-search">&nbsp;</i><input type="text" id="fe_sch_keywords" size="10" placeholder="Find events..." style="border:0px;" value="' + escape_text_field_value( args.keywords ) + '"/></div>';
			
			html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_sch_target" class="subtitle_menu" style="width:75px;" onChange="$P().set_search_filters()"><option value="">All Servers</option>' + this.render_target_menu_options( args.target ) + '</select></div>';
			html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_sch_plugin" class="subtitle_menu" style="width:75px;" onChange="$P().set_search_filters()"><option value="">All Plugins</option>' + render_menu_options( app.plugins, args.plugin, false ) + '</select></div>';
			html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_sch_cat" class="subtitle_menu" style="width:95px;" onChange="$P().set_search_filters()"><option value="">All Categories</option>' + render_menu_options( app.categories, args.category, false ) + '</select></div>';
			
			html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_sch_enabled" class="subtitle_menu" style="width:75px;" onChange="$P().set_search_filters()"><option value="">All Events</option>' + render_menu_options( [[1, 'Enabled'], [-1, 'Disabled'], ['success', "Last Run Success"], ['error', "Last Run Error"]], args.enabled, false ) + '</select></div>';
			
			html += '<div class="clear"></div>';
		html += '</div>';
		
		// apply filters
		this.events = [];
		for (var idx = 0, len = app.schedule.length; idx < len; idx++) {
			var item = app.schedule[idx];
			
			// category filter
			if (args.category && (item.category != args.category)) continue;
			
			// plugin filter
			if (args.plugin && (item.plugin != args.plugin)) continue;
			
			// server group filter
			if (args.target && (item.target != args.target)) continue;
			
			// keyword filter
			var words = [item.title, item.username, item.notes, item.target].join(' ').toLowerCase();
			if (('keywords' in args) && words.indexOf(args.keywords.toString().toLowerCase()) == -1) continue;
			
			// enabled filter
			if ((args.enabled == 1) && !item.enabled) continue;
			else if ((args.enabled == -1) && item.enabled) continue;
			
			// last success/fail filter
			else if (args.enabled == 'success') {
				if (!app.state.jobCodes || !(item.id in app.state.jobCodes)) continue; // n/a
				if (app.state.jobCodes[item.id]) continue; // error
			}
			else if (args.enabled == 'error') {
				if (!app.state.jobCodes || !(item.id in app.state.jobCodes)) continue; // n/a
				if (!app.state.jobCodes[item.id]) continue; // success
			}
			
			this.events.push( copy_object(item) );
		} // foreach item in schedule
		
		// prep events for sort
		this.events.forEach( function(item) {
			var cat = item.category ? find_object( app.categories, { id: item.category } ) : null;
			var group = item.target ? find_object( app.server_groups, { id: item.target } ) : null;
			var plugin = item.plugin ? find_object( app.plugins, { id: item.plugin } ) : null;
			
			item.category_title = cat ? cat.title : 'Uncategorized';
			item.group_title = group ? group.title : item.target;
			item.plugin_title = plugin ? plugin.title : 'No Plugin';
		} );
		
		// sort events by title ascending
		this.events = this.events.sort( function(a, b) {
			var key = group_by ? (group_by + '_title') : 'title';
			if (group_by && (a[key].toLowerCase() == b[key].toLowerCase())) key = 'title';
			return a[key].toLowerCase().localeCompare( b[key].toLowerCase() );
			// return (b.title < a.title) ? 1 : -1;
		} );
		
		// header center (group by buttons)
		var chtml = '';
		chtml += '<div class="schedule_group_button_container">';
		chtml += '<i class="fa fa-clock-o '+(group_by ? '' : 'selected')+'" title="Sort by Title" onMouseUp="$P().change_group_by(\'\')"></i>';
		chtml += '<i class="fa fa-folder-open-o '+((group_by == 'category') ? 'selected' : '')+'" title="Group by Category" onMouseUp="$P().change_group_by(\'category\')"></i>';
		chtml += '<i class="fa fa-plug '+((group_by == 'plugin') ? 'selected' : '')+'" title="Group by Plugin" onMouseUp="$P().change_group_by(\'plugin\')"></i>';
		chtml += '<i class="mdi mdi-server-network '+((group_by == 'group') ? 'selected' : '')+'" title="Group by Target" onMouseUp="$P().change_group_by(\'group\')"></i>';
		chtml += '</div>';
		cols.headerRight = chtml;
		
		// render table
		var self = this;
		var last_group = '';
		
		html += this.getBasicTable( this.events, cols, 'event', function(item, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().run_event('+idx+',event)"><b>Run</b></span>',
				'<span class="link" onMouseUp="$P().edit_event('+idx+')"><b>Edit</b></span>',
				'<a href="#History?sub=event_stats&id='+item.id+'"><b>Stats</b></a>',
				'<a href="#History?sub=event_history&id='+item.id+'"><b>History</b></a>',
				// '<span class="link" onMouseUp="$P().delete_event('+idx+')"><b>Delete</b></span>'
			];
			
			var cat = item.category ? find_object( app.categories, { id: item.category } ) : null;
			var group = item.target ? find_object( app.server_groups, { id: item.target } ) : null;
			var plugin = item.plugin ? find_object( app.plugins, { id: item.plugin } ) : null;
			
			// var jobs = find_objects( app.activeJobs, { event: item.id } );
			var status_html = 'n/a';
			if (app.state.jobCodes && (item.id in app.state.jobCodes)) {
				var last_code = app.state.jobCodes[ item.id ];
				status_html = last_code ? '<span class="color_label red clicky"><i class="fa fa-warning">&nbsp;</i>Error</span>' : '<span class="color_label green clicky"><i class="fa fa-check">&nbsp;</i>Success</span>';
			}
			
			if (group && item.multiplex) {
				group = copy_object(group);
				group.multiplex = 1;
			}
			
			var toggle_html = '<input type="checkbox" style="cursor:pointer" onChange="$P().change_event_enabled('+idx+')" '+(item.enabled ? 'checked="checked"' : '')+'/>';
			if (config.hide_schedule_checkboxes) toggle_html = '&nbsp;';
			
			var tds = [
				toggle_html, 
				'<div class="td_big"><span class="link" onMouseUp="$P().edit_event('+idx+')">' + self.getNiceEvent(item, col_width) + '</span></div>',
				self.getNiceCategory( cat, col_width ),
				self.getNicePlugin( plugin, col_width ),
				self.getNiceGroup( group, item.target, col_width ),
				summarize_event_timing( item.timing, item.timezone ),
				'<span id="ss_' + item.id + '" onMouseUp="$P().jump_to_last_job('+idx+')">' + status_html + '</span>',
				actions.join('&nbsp;|&nbsp;')
			];
			
			if (!item.enabled) tds.className = 'disabled';
			if (cat && !cat.enabled) tds.className = 'disabled';
			if (plugin && !plugin.enabled) tds.className = 'disabled';
			
			if (cat && cat.color) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += cat.color;
			}
			
			// group by
			if (group_by) {
				var cur_group = item[ group_by + '_title' ];
				if (cur_group != last_group) {
					last_group = cur_group;
					var insert_html = '<tr><td colspan="'+cols.length+'"><div class="schedule_group_header">';
					switch (group_by) {
						case 'category': insert_html += self.getNiceCategory(cat); break;
						case 'plugin': insert_html += self.getNicePlugin(plugin); break;
						case 'group': insert_html += self.getNiceGroup(group, item.target); break;
					}
					insert_html += '</div></td></tr>';
					tds.insertAbove = insert_html;
				} // group changed
			} // group_by
			
			return tds;
		} );
		
		if (app.hasPrivilege('create_events')) {
			html += '<div style="height:30px;"></div>';
			html += '<center><table><tr>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_event(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Event...</div></td>';
			html += '</tr></table></center>';
		}
		
		html += '</div>'; // padding
		// html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_sch_keywords').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().set_search_filters();
				}
			} ); 
			
			self.update_live_job_counts();
		}, 1 );
	},
	
	update_job_last_runs: function() {
		// update last run state for all jobs, called when state is updated
		if (!app.state.jobCodes) return;
		
		var event_counts = {};
		
		for (var job_id in app.activeJobs) {
			var job = app.activeJobs[job_id];
			event_counts[job.event] = (event_counts[job.event] || 0) + 1;
		}
		
		for (var event_id in app.state.jobCodes) {
			if (!(event_id in event_counts)) {
				var last_code = app.state.jobCodes[event_id];
				var status_html = last_code ? '<span class="color_label red clicky"><i class="fa fa-warning">&nbsp;</i>Error</span>' : '<span class="color_label green clicky"><i class="fa fa-check">&nbsp;</i>Success</span>';
				this.div.find('#ss_' + event_id).html( status_html );
			}
		}
	},
	
	update_live_job_counts: function() {
		// app.activeJobs
		var event_counts = {};
		
		for (var job_id in app.activeJobs) {
			var job = app.activeJobs[job_id];
			event_counts[job.event] = (event_counts[job.event] || 0) + 1;
		}
		
		for (var event_id in event_counts) {
			var count = event_counts[event_id];
			var status_html = '<span class="color_label blue">Running (' + count + ')</span>';
			this.div.find('#ss_' + event_id).html( status_html );
		}
		
		this.update_job_last_runs();
	},
	
	jump_to_last_job: function(idx) {
		// locate ID of latest completed job for event, and redirect to it
		var event = this.events[idx];
		var event_counts = {};
		
		for (var job_id in app.activeJobs) {
			var job = app.activeJobs[job_id];
			event_counts[job.event] = (event_counts[job.event] || 0) + 1;
		}
		
		if (event_counts[event.id]) {
			// if event has active jobs, change behavior of click
			// if exactly 1 job, link to it -- if more, do nothing
			if (event_counts[event.id] == 1) {
				var job = find_object( Object.values(app.activeJobs), { event: event.id } );
				if (job) Nav.go( 'JobDetails?id=' + job.id );
				return;
			}
			else return;
		}
		
		// jump to last completed job
		app.api.post( 'app/get_event_history', { id: event.id, offset: 0, limit: 1 }, function(resp) {
			if (resp && resp.rows && resp.rows[0]) {
				var job = resp.rows[0];
				Nav.go( 'JobDetails?id=' + job.id );
			}
		} );
	},
	
	change_group_by: function(group_by) {
		// change grop by setting and refresh schedule display
		app.setPref('schedule_group_by', group_by);
		this.gosub_events( this.args );
	},
	
	change_event_enabled: function(idx) {
		// toggle event on / off
		var event = this.events[idx];
		event.enabled = event.enabled ? 0 : 1;
		
		var stub = {
			id: event.id,
			title: event.title,
			enabled: event.enabled,
			catch_up: event.catch_up || false
		};
		
		app.api.post( 'app/update_event', stub, function(resp) {
			app.showMessage('success', "Event '"+event.title+"' has been " + (event.enabled ? 'enabled' : 'disabled') + ".");
		} );
	},
	
	run_event: function(event_idx, e) {
		// run event ad-hoc style
		var self = this;
		var event = (event_idx == 'edit') ? this.event : this.events[event_idx];
		
		if (e.shiftKey || e.ctrlKey || e.altKey) {
			// allow use to select the "now" time
			this.choose_date_time({
				when: time_now(),
				title: "Set Current Event Date/Time",
				description: "Configure the internal date/time for the event to run immediately.  This is the timestamp which the Plugin will see as the current time.",
				button: "Run Now",
				timezone: event.timezone || app.tz,
				
				callback: function(new_epoch) {
					self.run_event_now( event_idx, new_epoch );
				}
			});
		}
		else if (config.prompt_before_run) {
			// show prompt before running
			var msg = 'Are you sure you want to run the event "' + event.title + '" now?';
			app.confirm( 'Run Event Now', msg, "Run", function(result) {
				if (!result) return;
				Dialog.hide();
				self.run_event_now(event_idx);
			} );
		}
		else this.run_event_now(event_idx);
	},
	
	run_event_now: function(idx, now) {
		// run event ad-hoc style
		var event = (idx == 'edit') ? this.event : this.events[idx];
		if (!now) now = time_now();
		
		app.api.post( 'app/run_event', merge_objects( event, { now: now } ), function(resp) {
			var msg = '';
			if (resp.ids.length > 1) {
				// multiple jobs (multiplex)
				var num = resp.ids.length;
				msg = 'Event "'+event.title+'" has been started ('+num+' jobs).  View their progress on the Home Tab.';
			}
			else if (resp.ids.length == 1) {
				// single job
				var id = resp.ids[0];
				msg = 'Event "'+event.title+'" has been started.  View its progress on the Home Tab.';
			}
			else {
				// queued
				msg = 'Event "'+event.title+'" could not run right away, but was queued up.  View the queue progress on the Home Tab.';
			}
			app.showMessage('success', msg);
		} );
	},
	
	edit_event: function(idx) {
		// edit or create new event
		if (idx == -1) {
			Nav.go('Schedule?sub=new_event');
			return;
		}
		
		// edit existing
		var event = this.events[idx];
		Nav.go('Schedule?sub=edit_event&id=' + event.id);
	},
	
	delete_event: function(idx) {
		// delete selected event
		var self = this;
		var event = (idx == 'edit') ? this.event : this.events[idx];
		
		// check for active jobs first
		var jobs = find_objects( app.activeJobs, { event: event.id } );
		if (jobs.length) return app.doError("Sorry, you cannot delete an event that has active jobs running.");
		
		var msg = "Are you sure you want to delete the event <b>"+event.title+"</b>?";
		
		if (event.queue && app.eventQueue[event.id]) {
			msg += "  The event's job queue will also be flushed.";
		}
		else {
			msg += "  There is no way to undo this action.";
		}
		
		// proceed with delete
		app.confirm( '<span style="color:red">Delete Event</span>', msg, "Delete", function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Event..." );
				app.api.post( 'app/delete_event', event, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Event '"+event.title+"' was deleted successfully.");
					
					if (idx == 'edit') Nav.go('Schedule?sub=events');
				} );
			}
		} );
	},
	
	set_search_filters: function() {
		// grab values from search filters, and refresh
		var args = this.args;
		
		args.plugin = $('#fe_sch_plugin').val();
		if (!args.plugin) delete args.plugin;
		
		args.target = $('#fe_sch_target').val();
		if (!args.target) delete args.target;
		
		args.category = $('#fe_sch_cat').val();
		if (!args.category) delete args.category;
		
		args.keywords = $('#fe_sch_keywords').val();
		if (!args.keywords) delete args.keywords;
		
		args.enabled = $('#fe_sch_enabled').val();
		if (!args.enabled) delete args.enabled;
		
		Nav.go( 'Schedule' + compose_query_string(args) );
	},
	
	gosub_new_event: function(args) {
		// create new event
		var html = '';
		app.setWindowTitle( "Add New Event" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_event',
			[
				['events', "Schedule"],
				['new_event', "Add New Event"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Add New Event</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		if (this.event_copy) {
			// copied from existing event
			this.event = this.event_copy;
			delete this.event_copy;
		}
		else if (config.new_event_template) {
			// app has a custom event template
			this.event = deep_copy_object( config.new_event_template );
			if (!this.event.timezone) this.event.timezone = app.tz;
		}
		else {
			// default blank event
			this.event = { 
				enabled: 1, 
				params: {}, 
				timing: { minutes: [0] },
				max_children: 1,
				timeout: 3600,
				catch_up: 0,
				timezone: app.tz
			};
		}
		
		html += this.get_event_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_event_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_event()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Create Event</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		html += '</table></center>';
		
		html += '</div>'; // table wrapper div
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ee_title').focus();
		}, 1 );
	},
	
	cancel_event_edit: function() {
		// cancel edit, nav back to schedule
		Nav.go('Schedule');
	},
	
	do_new_event: function(force) {
		// create new event
		app.clearError();
		var event = this.get_event_form_json();
		if (!event) return; // error
		
		// pro-tip: embed id in title as bracketed prefix
		if (event.title.match(/^\[(\w+)\]\s*(.+)$/)) {
			event.id = RegExp.$1;
			event.title = RegExp.$2;
		}
		
		this.event = event;
		
		app.showProgress( 1.0, "Creating event..." );
		app.api.post( 'app/create_event', event, this.new_event_finish.bind(this) );
	},
	
	new_event_finish: function(resp) {
		// new event created successfully
		var self = this;
		app.hideProgress();
		
		Nav.go('Schedule');
		
		setTimeout( function() {
			app.showMessage('success', "Event '"+self.event.title+"' was created successfully.");
		}, 150 );
	},
	
	gosub_edit_event: function(args) {
		// edit event subpage
		var event = find_object( app.schedule, { id: args.id } );
		if (!event) return app.doError("Could not locate Event with ID: " + args.id);
		
		// check for autosave recovery
		// JH 2024-04-29 I have disabled this feature, because everyone hates it, including me.
		if (0 && app.autosave_event) {
			if (args.id == app.autosave_event.id) {
				Debug.trace("Recovering autosave data for: " + args.id);
				event = app.autosave_event;
			}
			delete app.autosave_event;
		}
		
		// make local copy so edits don't affect main app list until save
		this.event = deep_copy_object( event );
		
		var html = '';
		app.setWindowTitle( "Editing Event \"" + event.title + "\"" );
		this.div.removeClass('loading');
		
		var side_tabs = [];
		side_tabs.push( ['events', "Schedule"] );
		if (app.hasPrivilege('create_events')) side_tabs.push( ['new_event', "Add New Event"] );
		side_tabs.push( ['edit_event', "Edit Event"] );
		
		html += this.getSidebarTabs( 'edit_event', side_tabs );
		
		// html += '<div style="padding:20px;"><div class="subtitle">Editing Event &ldquo;' + event.title + '&rdquo;</div></div>';
		
		html += '<div style="padding:20px;">';
			html += '<div class="subtitle">';
				html += 'Editing Event &ldquo;' + event.title + '&rdquo;';
				html += '<div class="subtitle_widget" style="margin-left:5px;"><a href="#History?sub=event_history&id='+event.id+'"><i class="fa fa-arrow-circle-right">&nbsp;</i><b>Jump to History</b></a></div>';
				html += '<div class="subtitle_widget"><a href="#History?sub=event_stats&id='+event.id+'"><i class="fa fa-arrow-circle-right">&nbsp;</i><b>Jump to Stats</b></a></div>';
				html += '<div class="clear"></div>';
			html += '</div>';
		html += '</div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		// Internal ID
		if (this.isAdmin()) {
			html += get_form_table_row( 'Event ID', '<div style="font-size:14px;">' + event.id + '</div>' );
			html += get_form_table_caption( "The internal event ID used for API calls.  This cannot be changed." );
			html += get_form_table_spacer();
		}
		
		html += this.get_event_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				// cancel
				html += '<td><div class="button" style="width:110px; font-weight:normal;" onMouseUp="$P().cancel_event_edit()">Cancel</div></td>';
				
				// delete
				if (app.hasPrivilege('delete_events')) {
					html += '<td width="30">&nbsp;</td>';
					html += '<td><div class="button" style="width:110px; font-weight:normal;" onMouseUp="$P().delete_event(\'edit\')">Delete Event...</div></td>';
				}
				
				// copy
				if (app.hasPrivilege('create_events')) {
					html += '<td width="30">&nbsp;</td>';
					html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().do_copy_event()">Copy Event...</div></td>';
				}
				
				// run
				if (app.hasPrivilege('run_events')) {
					html += '<td width="30">&nbsp;</td>';
					html += '<td><div class="button" style="width:110px; font-weight:normal;" onMouseUp="$P().run_event_from_edit(event)">Run Now</div></td>';
				}
				
				// save
				html += '<td width="30">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_event()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_copy_event: function() {
		// make copy of event and jump into new workflow
		app.clearError();
		
		var event = this.get_event_form_json();
		if (!event) return; // error
		
		delete event.id;
		delete event.created;
		delete event.modified;
		delete event.username;
		
		event.title = "Copy of " + event.title;
		
		this.event_copy = event;
		Nav.go('Schedule?sub=new_event');
	},
	
	run_event_from_edit: function(e) {
		// run event in its current (possibly edited, unsaved) state
		app.clearError();
		
		var event = this.get_event_form_json();
		if (!event) return; // error
		
		this.event = event;
		
		this.run_event('edit', e);
	},
	
	do_save_event: function() {
		// save changes to existing event
		app.clearError();
		
		this.old_event = JSON.parse( JSON.stringify(this.event) );
		
		var event = this.get_event_form_json();
		if (!event) return; // error
		
		this.event = event;
		
		app.showProgress( 1.0, "Saving event..." );
		app.api.post( 'app/update_event', event, this.save_event_finish.bind(this) );
	},
	
	save_event_finish: function(resp, tx) {
		// existing event saved successfully
		var self = this;
		var event = this.event;
		
		app.hideProgress();
		app.showMessage('success', "The event was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// copy active jobs to array
		var jobs = [];
		for (var id in app.activeJobs) {
			var job = app.activeJobs[id];
			if ((job.event == event.id) && !job.detached) jobs.push( job );
		}
		
		// if the event was disabled and there are running jobs, ask user to abort them
		if (this.old_event.enabled && !event.enabled && jobs.length) {
			app.confirm( '<span style="color:red">Abort Jobs</span>', "There " + ((jobs.length != 1) ? 'are' : 'is') + " currently still " + jobs.length + " active " + pluralize('job', jobs.length) + " using the disabled event <b>"+event.title+"</b>.  Do you want to abort " + ((jobs.length != 1) ? 'these' : 'it') + " now?", "Abort", function(result) {
				if (result) {
					app.showProgress( 1.0, "Aborting " + pluralize('Job', jobs.length) + "..." );
					app.api.post( 'app/abort_jobs', { event: event.id }, function(resp) {
						app.hideProgress();
						if (resp.count > 0) {
							app.showMessage('success', "The " + pluralize('job', resp.count) + " " + ((resp.count != 1) ? 'were' : 'was') + " aborted successfully.");
						}
						else {
							app.showMessage('warning', "No jobs were aborted.  It is likely they completed while the dialog was up.");
						}
					} );
				} // clicked Abort
			} ); // app.confirm
		} // disabled + jobs
		else {
			// if certain key properties were changed and event has active jobs, ask user to update them
			var need_update = false;
			var updates = {};
			var keys = ['title', 'timeout', 'retries', 'retry_delay', 'chain', 'chain_error', 'notify_success', 'notify_fail', 'web_hook', 'cpu_limit', 'cpu_sustain', 'memory_limit', 'memory_sustain', 'log_max_size'];
			
			for (var idx = 0, len = keys.length; idx < len; idx++) {
				var key = keys[idx];
				if (event[key] != this.old_event[key]) {
					updates[key] = event[key];
					need_update = true;
				}
			} // foreach key
			
			// recount active jobs, including detached this time
			jobs = [];
			for (var id in app.activeJobs) {
				var job = app.activeJobs[id];
				if (job.event == event.id) jobs.push( job );
			}
			
			if (need_update && jobs.length) {
				app.confirm( 'Update Jobs', "This event currently has " + jobs.length + " active " + pluralize('job', jobs.length) + ".  Do you want to update " + ((jobs.length != 1) ? 'these' : 'it') + " as well?", "Update", function(result) {
					if (result) {
						app.showProgress( 1.0, "Updating " + pluralize('Job', jobs.length) + "..." );
						app.api.post( 'app/update_jobs', { event: event.id, updates: updates }, function(resp) {
							app.hideProgress();
							if (resp.count > 0) {
								app.showMessage('success', "The " + pluralize('job', resp.count) + " " + ((resp.count != 1) ? 'were' : 'was') + " updated successfully.");
							}
							else {
								app.showMessage('warning', "No jobs were updated.  It is likely they completed while the dialog was up.");
							}
						} );
					} // clicked Update
				} ); // app.confirm
			} // jobs need update
		} // check for update
		
		delete this.old_event;
	},
	
	get_event_edit_html: function() {
		// get html for editing a event (or creating a new one)
		var html = '';
		var event = this.event;
		
		// event title
		html += get_form_table_row( 'Event Name', '<input type="text" id="fe_ee_title" style="width:90%" value="'+escape_text_field_value(event.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter a title for the event, which will be displayed on the main schedule." );
		html += get_form_table_spacer();
		
		// event enabled
		html += get_form_table_row( 'Schedule', '<input type="checkbox" id="fe_ee_enabled" value="1" ' + (event.enabled ? 'checked="checked"' : '') + '/><label for="fe_ee_enabled">Event Enabled</label>' );
		html += get_form_table_caption( "Select whether the event should be enabled or disabled in the schedule." );
		html += get_form_table_spacer();
		
		// category
		app.categories.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		html += get_form_table_row( 'Category', 
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><select id="fe_ee_cat" onMouseDown="this.options[0].disabled=true"><option value="">Select Category</option>' + render_menu_options(app.categories, event.category, false) + '</select></td>' + 
				(app.isAdmin() ? '<td><span class="link addme" style="padding-left:5px; font-size:13px;" title="Add New Category" onMouseUp="$P().show_quick_add_cat_dialog()">&laquo; Add New...</span></td>' : '') + 
			'</tr></table>' 
		);
		html += get_form_table_caption( "Select a category for the event (this may limit the max concurrent jobs, etc.)" );
		html += get_form_table_spacer();
		
		// target (server group or individual server)
		html += get_form_table_row( 'Target', 
			'<select id="fe_ee_target" onChange="$P().set_event_target(this.options[this.selectedIndex].value)">' + this.render_target_menu_options( event.target ) + '</select>'
		);
		
		/*html += get_form_table_row( 'Target', 
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><select id="fe_ee_target">' + this.render_target_menu_options( event.target ) + '</select></td>' + 
				'<td style="padding-left:15px;"><input type="checkbox" id="fe_ee_multiplex" value="1" ' + (event.multiplex ? 'checked="checked"' : '') + ' onChange="$P().setGroupVisible(\'mp\',this.checked).setGroupVisible(\'algo\',!this.checked)"/><label for="fe_ee_multiplex">Multiplex</label></td>' + 
			'</tr></table>' 
		);*/
		html += get_form_table_caption( 
			"Select a target server group or individual server to run the event on."
			// "Multiplex means that the event will run on <b>all</b> matched servers simultaneously." 
		);
		html += get_form_table_spacer();
		
		// algo selection
		var algo_classes = 'algogroup';
		var target_group = !event.target || find_object( app.server_groups, { id: event.target } );
		if (!target_group) algo_classes += ' collapse';
		
		var algo_items = [['random',"Random"],['round_robin',"Round Robin"],['least_cpu',"Least CPU Usage"],['least_mem',"Least Memory Usage"],['prefer_first',"Prefer First (Alphabetically)"],['prefer_last',"Prefer Last (Alphabetically)"],['multiplex',"Multiplex"]];
		
		html += get_form_table_row( algo_classes, 'Algorithm', '<select id="fe_ee_algo" onChange="$P().set_algo(this.options[this.selectedIndex].value)">' + render_menu_options(algo_items, event.algo, false) + '</select>' );
		
		html += get_form_table_caption( algo_classes, 
			"Select the desired algorithm for choosing a server from the target group.<br/>" + 
			"'Multiplex' means that the event will run on <b>all</b> group servers simultaneously." 
		);
		html += get_form_table_spacer( algo_classes, '' );
		
		// multiplex stagger
		var mp_classes = 'mpgroup';
		if (!event.multiplex || !target_group) mp_classes += ' collapse';
		
		var stagger_units = 60;
		var stagger = parseInt( event.stagger || 0 );
		if ((stagger >= 3600) && (stagger % 3600 == 0)) {
			// hours
			stagger_units = 3600;
			stagger = stagger / 3600;
		}
		else if ((stagger >= 60) && (stagger % 60 == 0)) {
			// minutes
			stagger_units = 60;
			stagger = Math.floor( stagger / 60 );
		}
		else {
			// seconds
			stagger_units = 1;
		}
		
		// stagger
		html += get_form_table_row( mp_classes, 'Stagger', 
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><input type="text" id="fe_ee_stagger" style="font-size:14px; width:40px;" value="'+stagger+'"/></td>' + 
				'<td><select id="fe_ee_stagger_units" style="font-size:12px">' + render_menu_options([[1,'Seconds'], [60,'Minutes'], [3600,'Hours']], stagger_units) + '</select></td>' + 
			'</tr></table>' 
		);
		html += get_form_table_caption( mp_classes, 
			"For multiplexed events, optionally stagger the jobs across the servers.<br/>" + 
			"Each server will delay its launch by a multiple of the specified time." 
		);
		html += get_form_table_spacer( mp_classes, '' );
		
		// plugin
		app.plugins.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		html += get_form_table_row( 'Plugin', '<select id="fe_ee_plugin" onMouseDown="this.options[0].disabled=true" onChange="$P().change_edit_plugin()"><option value="">Select Plugin</option>' + render_menu_options(app.plugins, event.plugin, false) + '</select>' );
		
		// plugin params
		html += get_form_table_row( '', '<div id="d_ee_plugin_params">' + this.get_plugin_params_html() + '</div>' );
		html += get_form_table_spacer();
		
		// timing
		var timing = event.timing;
		var tmode = '';
		if (!timing) tmode = 'demand';
		else if (timing.years && timing.years.length) tmode = 'custom';
		else if (timing.months && timing.months.length && timing.weekdays && timing.weekdays.length) tmode = 'custom';
		else if (timing.days && timing.days.length && timing.weekdays && timing.weekdays.length) tmode = 'custom';
		else if (timing.months && timing.months.length) tmode = 'yearly';
		else if (timing.weekdays && timing.weekdays.length) tmode = 'weekly';
		else if (timing.days && timing.days.length) tmode = 'monthly';
		else if (timing.hours && timing.hours.length) tmode = 'daily';
		else if (timing.minutes && timing.minutes.length) tmode = 'hourly';
		else if (!num_keys(timing)) tmode = 'hourly';
		
		var timing_items = [
			['demand', 'On Demand'],
			['custom', 'Custom'],
			['yearly', 'Yearly'],
			['monthly', 'Monthly'],
			['weekly', 'Weekly'],
			['daily', 'Daily'],
			['hourly', 'Hourly']
		];
		
		html += get_form_table_row( 'Timing', 
			'<div class="right">' + 
				'<table cellspacing="0" cellpadding="0"><tr>' + 
					'<td><span class="label" style="font-size:12px;">Timezone:&nbsp;</span></td>' + 
					'<td><select id="fe_ee_timezone" style="max-width:150px; font-size:12px;" onChange="$P().change_timezone()">' + render_menu_options(app.zones, event.timezone || app.tz, false) + '</select></td>' + 
				'</tr></table>' + 
			'</div>' + 
			
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><select id="fe_ee_timing" onChange="$P().change_edit_timing()">' + render_menu_options(timing_items, tmode, false) + '</select></td>' + 
				'<td><span class="link addme" style="padding-left:5px; font-size:13px;" title="Import from Crontab" onMouseUp="$P().show_crontab_import_dialog()">&laquo; Import...</span></td>' + 
			'</tr></table>' + 
			
			'<div class="clear"></div>'
		);
		
		// timing params
		this.show_all_minutes = false;
		
		html += get_form_table_row( '', '<div id="d_ee_timing_params">' + this.get_timing_params_html(tmode) + '</div>' );
		html += get_form_table_spacer();
		
		// max children
		html += get_form_table_row( 'Concurrency', '<select id="fe_ee_max_children">' + render_menu_options([[1,"1 (Singleton)"], 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32], event.max_children, false) + '</select>' );
		html += get_form_table_caption( "Select the maximum number of jobs that can run simultaneously." );
		html += get_form_table_spacer();
		
		// timeout
		html += get_form_table_row( 'Timeout', this.get_relative_time_combo_box('fe_ee_timeout', event.timeout) );
		html += get_form_table_caption( "Enter the maximum time allowed for jobs to complete, 0 to disable." );
		html += get_form_table_spacer();
		
		// retries
		html += get_form_table_row( 'Retries', 
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><select id="fe_ee_retries" onChange="$P().change_retry_amount()">' + render_menu_options([[0,'None'], 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32], event.retries, false) + '</select></td>' + 
				'<td id="td_ee_retry1" '+(event.retries ? '' : 'style="display:none"')+'><span style="padding-left:15px; font-size:13px; color:#777;"><b>Delay:</b>&nbsp;</span></td>' + 
				'<td id="td_ee_retry2" '+(event.retries ? '' : 'style="display:none"')+'>' + this.get_relative_time_combo_box('fe_ee_retry_delay', event.retry_delay, '', true) + '</td>' + 
			'</tr></table>'
		);
		html += get_form_table_caption( "Select the number of retries to be attempted before an error is reported." );
		html += get_form_table_spacer();
		
		// catch-up mode (run all)
		// method (interruptable, non-interruptable)
		html += get_form_table_row( 'Misc. Options', 
			'<div><input type="checkbox" id="fe_ee_catch_up" value="1" '+(event.catch_up ? 'checked="checked"' : '') + ' ' + (event.id ? 'onChange="$P().setGroupVisible(\'rc\',this.checked)"' : '') + ' /><label for="fe_ee_catch_up">Catch-Up (Run All)</label></div>' + 
			'<div class="caption">Automatically run all missed events after server downtime or scheduler/event disabled.</div>' + 
			
			'<div style="margin-top:10px"><input type="checkbox" id="fe_ee_detached" value="1" '+(event.detached ? 'checked="checked"' : '')+'/><label for="fe_ee_detached">Detached (Uninterruptible)</label></div>' + 
			'<div class="caption">Run event as a detached background process that is never interrupted.</div>' + 
			
			'<div style="margin-top:10px"><input type="checkbox" id="fe_ee_queue" value="1" '+(event.queue ? 'checked="checked"' : '')+' onChange="$P().setGroupVisible(\'eq\',this.checked)"/><label for="fe_ee_queue">Allow Queued Jobs</label></div>' + 
			'<div class="caption">Jobs that cannot run immediately will be queued.</div>'
		);
		html += get_form_table_spacer();
		
		// reset cursor (only for catch_up and edit mode)
		var rc_epoch = normalize_time( time_now(), { sec: 0 } );
		if (event.id && app.state && app.state.cursors && app.state.cursors[event.id]) {
			rc_epoch = app.state.cursors[event.id];
		}
		
		var rc_classes = 'rcgroup';
		if (!event.catch_up || !event.id) rc_classes += ' collapse';
		
		html += get_form_table_row( rc_classes, 'Time Machine', 
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><input type="checkbox" id="fe_ee_rc_enabled" value="1" onChange="$P().toggle_rc_textfield(this.checked)"/></td><td><label for="fe_ee_rc_enabled">Set Event Clock:</label>&nbsp;</td>' + 
				'<td><input type="text" id="fe_ee_rc_time" style="font-size:13px; width:180px;" disabled="disabled" value="'+$P().rc_get_short_date_time( rc_epoch )+'" data-epoch="' + rc_epoch + '" onFocus="this.blur()" onMouseUp="$P().rc_click()"/></td>' + 
				'<td><span id="s_ee_rc_reset" class="link addme" style="opacity:0" onMouseUp="$P().reset_rc_time_now()">&laquo; Reset</span></td>' + 
			'</tr></table>' 
		);
		html += get_form_table_caption( rc_classes, 
			"Optionally reset the internal clock for this event, to repeat past jobs, or jump over a queue."
		);
		html += get_form_table_spacer( rc_classes, '' );
		
		// event queue max
		var eq_classes = 'eqgroup';
		if (!event.queue) eq_classes += ' collapse';
		
		html += get_form_table_row( eq_classes, 'Queue Limit', 
			'<input type="text" id="fe_ee_queue_max" size="8" value="'+escape_text_field_value(event.queue_max || 0)+'" spellcheck="false"/>'
		);
		html += get_form_table_caption( eq_classes, 
			"Set the maximum number of jobs that can be queued up for this event (or '0' for no limit)."
		);
		html += get_form_table_spacer( eq_classes, '' );
		
		// chain reaction
		var sorted_events = app.schedule.sort( function(a, b) {
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		var chain_expanded = !!(event.chain || event.chain_error);
		html += get_form_table_row( 'Chain Reaction', 
			'<div style="font-size:13px;'+(chain_expanded ? 'display:none;' : '')+'"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Chain Options</span></div>' + 
			'<fieldset style="padding:10px 10px 0 10px; margin-bottom:5px;'+(chain_expanded ? '' : 'display:none;')+'"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Chain Options</legend>' + 
				'<div class="plugin_params_label">Run Event on Success:</div>' + 
				'<div class="plugin_params_content"><select id="fe_ee_chain" style="width:90%; margin-left:10px; font-size:12px;"><option value="">(None)</option>' + render_menu_options( sorted_events, event.chain, false ) + '</select></div>' + 
				
				'<div class="plugin_params_label">Run Event on Failure:</div>' + 
				'<div class="plugin_params_content"><select id="fe_ee_chain_error" style="width:90%; margin-left:10px; font-size:12px;"><option value="">(None)</option>' + render_menu_options( sorted_events, event.chain_error, false ) + '</select></div>' + 
				
			'</fieldset>'
		);
		html += get_form_table_caption( "Select events to run automatically after this event completes." );
		html += get_form_table_spacer();
		
		// notification
		var notif_expanded = !!(event.notify_success || event.notify_fail || event.web_hook);
		html += get_form_table_row( 'Notification', 
			'<div style="font-size:13px;'+(notif_expanded ? 'display:none;' : '')+'"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Notification Options</span></div>' + 
			'<fieldset style="padding:10px 10px 0 10px; margin-bottom:5px;'+(notif_expanded ? '' : 'display:none;')+'"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Notification Options</legend>' + 
				'<div class="plugin_params_label">Email on Success:</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ee_notify_success" size="50" value="'+escape_text_field_value(event.notify_success)+'" placeholder="email@sample.com" spellcheck="false" onChange="$P().update_add_remove_me($(this))"/><span class="link addme" onMouseUp="$P().add_remove_me($(this).prev())"></span></div>' + 
				
				'<div class="plugin_params_label">Email on Failure:</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ee_notify_fail" size="50" value="'+escape_text_field_value(event.notify_fail)+'" placeholder="email@sample.com" spellcheck="false" onChange="$P().update_add_remove_me($(this))"/><span class="link addme" onMouseUp="$P().add_remove_me($(this).prev())"></span></div>' + 
				
				'<div class="plugin_params_label">Web Hook URL:</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ee_web_hook" size="60" value="'+escape_text_field_value(event.web_hook)+'" placeholder="http://" spellcheck="false"/></div>' + 
			'</fieldset>'
		);
		html += get_form_table_caption( "Enter one or more e-mail addresses for notification (comma-separated), and optionally a web hook URL." );
		html += get_form_table_spacer();
		
		// resource limits
		var res_expanded = !!(event.memory_limit || event.memory_sustain || event.cpu_limit || event.cpu_sustain || event.log_max_size);
		html += get_form_table_row( 'Limits', 
			'<div style="font-size:13px;'+(res_expanded ? 'display:none;' : '')+'"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Resource Limits</span></div>' + 
			'<fieldset style="padding:10px 10px 0 10px; margin-bottom:5px;'+(res_expanded ? '' : 'display:none;')+'"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Resource Limits</legend>' + 
				
				'<div class="plugin_params_label">CPU Limit:</div>' + 
				'<div class="plugin_params_content"><table cellspacing="0" cellpadding="0" class="fieldset_params_table"><tr>' + 
					'<td style="padding-right:2px"><input type="checkbox" id="fe_ee_cpu_enabled" value="1" '+(event.cpu_limit ? 'checked="checked"' : '')+' /></td>' + 
					'<td><label for="fe_ee_cpu_enabled">Abort job if CPU exceeds</label></td>' + 
					'<td><input type="text" id="fe_ee_cpu_limit" style="width:30px;" value="'+(event.cpu_limit || 0)+'"/>%</td>' + 
					'<td>for</td>' + 
					'<td>' + this.get_relative_time_combo_box( 'fe_ee_cpu_sustain', event.cpu_sustain, 'fieldset_params_table' ) + '</td>' + 
				'</tr></table></div>' + 
				
				'<div class="plugin_params_label">Memory Limit:</div>' + 
				'<div class="plugin_params_content"><table cellspacing="0" cellpadding="0" class="fieldset_params_table"><tr>' + 
					'<td style="padding-right:2px"><input type="checkbox" id="fe_ee_memory_enabled" value="1" '+(event.memory_limit ? 'checked="checked"' : '')+' /></td>' + 
					'<td><label for="fe_ee_memory_enabled">Abort job if memory exceeds</label></td>' + 
					'<td>' + this.get_relative_size_combo_box( 'fe_ee_memory_limit', event.memory_limit, 'fieldset_params_table' ) + '</td>' + 
					'<td>for</td>' + 
					'<td>' + this.get_relative_time_combo_box( 'fe_ee_memory_sustain', event.memory_sustain, 'fieldset_params_table' ) + '</td>' + 
				'</tr></table></div>' + 
				
				'<div class="plugin_params_label">Log Size Limit:</div>' + 
				'<div class="plugin_params_content"><table cellspacing="0" cellpadding="0" class="fieldset_params_table"><tr>' + 
					'<td style="padding-right:2px"><input type="checkbox" id="fe_ee_log_enabled" value="1" '+(event.log_max_size ? 'checked="checked"' : '')+' /></td>' + 
					'<td><label for="fe_ee_log_enabled">Abort job if log file exceeds</label></td>' + 
					'<td>' + this.get_relative_size_combo_box( 'fe_ee_log_limit', event.log_max_size, 'fieldset_params_table' ) + '</td>' + 
				'</tr></table></div>' + 
				
			'</fieldset>'
		);
		html += get_form_table_caption( 
			"Optionally set CPU load, memory usage and log size limits for the event."
		);
		html += get_form_table_spacer();
		
		// notes
		html += get_form_table_row( 'Notes', '<textarea id="fe_ee_notes" style="width:600px; height:80px; resize:vertical;">'+escape_text_field_value(event.notes)+'</textarea>' );
		html += get_form_table_caption( "Optionally enter notes for the event, which will be included in all e-mail notifications." );
		html += get_form_table_spacer();
		
		setTimeout( function() {
			$P().update_add_remove_me( $('#fe_ee_notify_success, #fe_ee_notify_fail') );
		}, 1 );
		
		return html;
	},
	
	set_event_target: function(target) {
		// event target has changed (from menu selection)
		// hide / show sections as necessary
		var target_group = find_object( app.server_groups, { id: target } );
		var algo = $('#fe_ee_algo').val();
		
		this.setGroupVisible('algo', !!target_group);
		this.setGroupVisible('mp', !!target_group && (algo == 'multiplex'));
	},
	
	set_algo: function(algo) {
		// target server algo has changed
		// hide / show multiplex stagger as necessary
		this.setGroupVisible('mp', (algo == 'multiplex'));
	},
	
	change_retry_amount: function() {
		// user has selected a retry amount from the menu
		// adjust the visibility of the retry delay controls accordingly
		var retries = parseInt( $('#fe_ee_retries').val() );
		if (retries) {
			if (!$('#td_ee_retry1').hasClass('yup')) {
				$('#td_ee_retry1, #td_ee_retry2').css({ display:'table-cell', opacity:0 }).fadeTo( 250, 1.0, function() {
					$(this).addClass('yup');
				} );
			}
		}
		else {
			$('#td_ee_retry1, #td_ee_retry2').fadeTo( 250, 0.0, function() {
				$(this).css({ display:'none', opacity:0 }).removeClass('yup');
			} );
		}
	},
	
	show_crontab_import_dialog: function() {
		// allow user to paste in crontab syntax to set timing
		var self = this;
		var html = '';
		
		html += '<div style="font-size:12px; color:#777; margin-bottom:20px;">Use this to import event timing settings from a <a href="https://en.wikipedia.org/wiki/Cron#CRON_expression" target="_blank">Crontab expression</a>.  This is a string comprising five (or six) fields separated by white space that represents a set of dates/times.  Example: <b>30 4 1 * *</b> (First day of every month at 4:30 AM)</div>';
		
		html += '<center><table>' + 
			// get_form_table_spacer() + 
			get_form_table_row('Crontab:', '<input type="text" id="fe_ee_crontab" style="width:330px;" value="" spellcheck="false"/>') + 
			get_form_table_caption("Enter your crontab date/time expression here.") + 
		'</table></center>';
		
		app.confirm( '<i class="fa fa-clock-o">&nbsp;</i>Import from Crontab', html, "Import", function(result) {
			app.clearError();
			
			if (result) {
				var cron_exp = $('#fe_ee_crontab').val().toLowerCase();
				if (!cron_exp) return app.badField('fe_ee_crontab', "Please enter a crontab date/time expression.");
				
				// validate, convert to timing object
				var timing = null;
				try {
					timing = parse_crontab( cron_exp, $('#fe_ee_title').val() );
				}
				catch (e) {
					return app.badField('fe_ee_crontab', e.toString());
				}
				
				// hide dialog
				Dialog.hide();
				
				// replace event timing object
				self.event.timing = timing;
				
				// redraw display
				var tmode = '';
				if (timing.years && timing.years.length) tmode = 'custom';
				else if (timing.months && timing.months.length && timing.weekdays && timing.weekdays.length) tmode = 'custom';
				else if (timing.days && timing.days.length && timing.weekdays && timing.weekdays.length) tmode = 'custom';
				else if (timing.months && timing.months.length) tmode = 'yearly';
				else if (timing.weekdays && timing.weekdays.length) tmode = 'weekly';
				else if (timing.days && timing.days.length) tmode = 'monthly';
				else if (timing.hours && timing.hours.length) tmode = 'daily';
				else if (timing.minutes && timing.minutes.length) tmode = 'hourly';
				else if (!num_keys(timing)) tmode = 'hourly';
				
				$('#fe_ee_timing').val( tmode );
				$('#d_ee_timing_params').html( self.get_timing_params_html(tmode) );
				
				// and we're done
				app.showMessage('success', "Crontab date/time expression was imported successfully.");
				
			} // user clicked add
		} ); // app.confirm
		
		setTimeout( function() { 
			$('#fe_ee_crontab').focus();
		}, 1 );
	},
	
	show_quick_add_cat_dialog: function() {
		// allow user to quickly add a category
		var self = this;
		var html = '';
		
		html += '<div style="font-size:12px; color:#777; margin-bottom:20px;">Use this to quickly add a new category.  Note that you should visit the Admin Categories page later so you can set additional options, add a descripton, etc.</div>';
		
		html += '<center><table>' + 
			// get_form_table_spacer() + 
			get_form_table_row('Category Title:', '<input type="text" id="fe_ee_cat_title" style="width:315px" value=""/>') + 
			get_form_table_caption("Enter a title for your category here.") + 
		'</table></center>';
		
		app.confirm( '<i class="fa fa-folder-open-o">&nbsp;</i>Quick Add Category', html, "Add", function(result) {
			app.clearError();
			
			if (result) {
				var cat_title = $('#fe_ee_cat_title').val();
				if (!cat_title) return app.badField('fe_ee_cat_title', "Please enter a title for the category.");
				Dialog.hide();
				
				var category = {};
				category.title = cat_title;
				category.description = '';
				category.max_children = 0;
				category.notify_success = '';
				category.notify_fail = '';
				category.web_hook = '';
				category.enabled = 1;
				
				app.showProgress( 1.0, "Adding category..." );
				app.api.post( 'app/create_category', category, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Category was added successfully.");
					
					// set event to new category
					category.id = resp.id;
					self.event.category = category.id;
					
					// due to race conditions with websocket, app.categories may or may not have our new cat at this point
					// so add it manually if needed
					if (!find_object(app.categories, { id: category.id })) {
						app.categories.push( category );
					}
					
					// resort cats for menu rebuild
					app.categories.sort( function(a, b) {
						// return (b.title < a.title) ? 1 : -1;
						return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
					} );
					
					// rebuild menu and select new cat
					$('#fe_ee_cat').html( 
						'<option value="" disabled="disabled">Select Category</option>' + 
						render_menu_options(app.categories, self.event.category, false) 
					);
				} ); // api.post
				
			} // user clicked add
		} ); // app.confirm
		
		setTimeout( function() { 
			$('#fe_ee_cat_title').focus();
		}, 1 );
	},
	
	rc_get_short_date_time: function(epoch) {
		// get short date/time with tz abbrev using moment
		var tz = this.event.timezone || app.tz;
		// return moment.tz( epoch * 1000, tz).format("MMM D, YYYY h:mm A z");
		return moment.tz( epoch * 1000, tz).format("lll z");
	},
	
	rc_click: function() {
		// click in 'reset cursor' text field, popup edit dialog
		var self = this;
		$('#fe_ee_rc_time').blur();
		
		if ($('#fe_ee_rc_enabled').is(':checked')) {
			var epoch = parseInt( $('#fe_ee_rc_time').data('epoch') );
			
			this.choose_date_time({
				when: epoch,
				title: "Set Event Clock",
				timezone: this.event.timezone || app.tz,
				
				callback: function(rc_epoch) {
					$('#fe_ee_rc_time').data('epoch', rc_epoch).val( self.rc_get_short_date_time( rc_epoch ) );
					$('#fe_ee_rc_time').blur();
				}
			});
		}
	},
	
	reset_rc_time_now: function() {
		// reset cursor value to now, from click
		var rc_epoch = normalize_time( time_now(), { sec: 0 } );
		$('#fe_ee_rc_time').data('epoch', rc_epoch).val( this.rc_get_short_date_time( rc_epoch ) );
	},
	
	update_rc_value: function() {
		// received state update from server, event cursor may have changed
		// only update field if in edit mode, catch_up, and field is disabled
		var event = this.event;
		
		if (event.id && $('#fe_ee_catch_up').is(':checked') && !$('#fe_ee_rc_enabled').is(':checked') && app.state && app.state.cursors && app.state.cursors[event.id]) {
			$('#fe_ee_rc_time').data('epoch', app.state.cursors[event.id]).val( this.rc_get_short_date_time( app.state.cursors[event.id] ) );
		}
	},
	
	toggle_rc_textfield: function(state) {
		// set 'disabled' attribute of 'reset cursor' text field, based on checkbox
		var event = this.event;
		
		if (state) {
			$('#fe_ee_rc_time').removeAttr('disabled').css('cursor', 'pointer');
			$('#s_ee_rc_reset').fadeTo( 250, 1.0 );
		}
		else {
			$('#fe_ee_rc_time').attr('disabled', 'disabled').css('cursor', 'default');
			$('#s_ee_rc_reset').fadeTo( 250, 0.0 );
			
			// reset value just in case it changed while field was enabled
			if (event.id && app.state && app.state.cursors && app.state.cursors[event.id]) {
				$('#fe_ee_rc_time').data('epoch', app.state.cursors[event.id]).val( this.rc_get_short_date_time( app.state.cursors[event.id] ) );
			}
		}
	},
	
	change_timezone: function() {
		// change timezone setting
		var event = this.event;
		
		// update 'reset cursor' text field to reflect new timezone
		var new_cursor = parseInt( $('#fe_ee_rc_time').data('epoch') );
		if (!new_cursor || isNaN(new_cursor)) {
			new_cursor = app.state.cursors[event.id] || normalize_time( time_now(), { sec: 0 } );
		}
		new_cursor = normalize_time( new_cursor, { sec: 0 } );
		
		// update timezone
		event.timezone = $('#fe_ee_timezone').val();
		this.change_edit_timing_param();
		
		// render out new RC date/time
		$('#fe_ee_rc_time').data('epoch', new_cursor).val( this.rc_get_short_date_time( new_cursor ) );
	},
	
	change_edit_timing: function() {
		// change edit timing mode
		var event = this.event;
		var timing = event.timing;
		var tmode = $('#fe_ee_timing').val();
		var dargs = get_date_args( time_now() );
		
		// clean up timing object, add sane defaults for the new tmode
		switch (tmode) {
			case 'demand':
				timing = false;
				event.timing = false;
			break;
			
			case 'custom':
				if (!timing) timing = event.timing = {};
			break;
			
			case 'yearly':
				if (!timing) timing = event.timing = {};
				delete timing.years;
				if (!timing.months) timing.months = [];
				if (!timing.months.length) timing.months.push( dargs.mon );
				
				if (!timing.days) timing.days = [];
				if (!timing.days.length) timing.days.push( dargs.mday );
				
				if (!timing.hours) timing.hours = [];
				if (!timing.hours.length) timing.hours.push( dargs.hour );
			break;
			
			case 'weekly':
				if (!timing) timing = event.timing = {};
				delete timing.years;
				delete timing.months;
				delete timing.days;
				if (!timing.weekdays) timing.weekdays = [];
				if (!timing.weekdays.length) timing.weekdays.push( dargs.wday );
				
				if (!timing.hours) timing.hours = [];
				if (!timing.hours.length) timing.hours.push( dargs.hour );
			break;
			
			case 'monthly':
				if (!timing) timing = event.timing = {};
				delete timing.years;
				delete timing.months;
				delete timing.weekdays;
				if (!timing.days) timing.days = [];
				if (!timing.days.length) timing.days.push( dargs.mday );
				
				if (!timing.hours) timing.hours = [];
				if (!timing.hours.length) timing.hours.push( dargs.hour );
			break;
			
			case 'daily':
				if (!timing) timing = event.timing = {};
				delete timing.years;
				delete timing.months;
				delete timing.weekdays;
				delete timing.days;
				if (!timing.hours) timing.hours = [];
				if (!timing.hours.length) timing.hours.push( dargs.hour );
			break;
			
			case 'hourly':
				if (!timing) timing = event.timing = {};
				delete timing.years;
				delete timing.months;
				delete timing.weekdays;
				delete timing.days;
				delete timing.hours;
			break;
		}
		
		if (timing) {
			if (!timing.minutes) timing.minutes = [];
			if (!timing.minutes.length) timing.minutes.push( 0 );
		}
		
		$('#d_ee_timing_params').html( this.get_timing_params_html(tmode) );
	},
	
	get_timing_params_html: function(tmode) {
		// get timing param editor html
		var html = '';
		var event = this.event;
		var timing = event.timing;
		
		html += '<div style="font-size:13px; margin-top:7px; display:none;"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Timing Details</span></div>';
		html += '<fieldset style="margin-top:7px; padding:10px 10px 0 10px; max-width:600px;"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Timing Details</legend>';
		
		// html += '<fieldset style="margin-top:7px; padding:10px 10px 0 10px; max-width:600px;"><legend>Timing Details</legend>';
		
		// only show years in custom mode
		if (tmode == 'custom') {
			html += '<div class="timing_details_label">Years</div>';
			var year = (new Date()).getFullYear();
			html += '<div class="timing_details_content">' + this.get_timing_checkbox_set( 'year', [year, year+1, year+2, year+3, year+4, year+5, year+6, year+7, year+8, year+9, year+10], timing.years || [], true ) + '</div>';
		} // years
		
		if (tmode.match(/(custom|yearly)/)) {
			// show months
			html += '<div class="timing_details_label">Months</div>';
			html += '<div class="timing_details_content">' + this.get_timing_checkbox_set( 'month', _months, timing.months || [] ) + '</div>';
		} // months
		
		if (tmode.match(/(custom|weekly)/)) {
			// show weekdays
			var wday_items = [ [0,'Sunday'], [1,'Monday'], [2,'Tuesday'], [3,'Wednesday'], 
				[4,'Thursday'], [5,'Friday'], [6,'Saturday'] ];
			
			html += '<div class="timing_details_label">Weekdays</div>';
			html += '<div class="timing_details_content">' + this.get_timing_checkbox_set( 'weekday', wday_items, timing.weekdays || [] ) + '</div>';
		} // weekdays
		
		if (tmode.match(/(custom|yearly|monthly)/)) {
			// show days of month
			var mday_items = [];
			for (var idx = 1; idx < 32; idx++) {
				var num_str = '' + idx;
				var num_label = num_str;
				if (idx >= 11 && idx < 20) num_label += 'th'; // teens break the rule (11th, 12th, 13th, etc.)
				else num_label += _number_suffixes[ parseInt( num_str.substring(num_str.length - 1) ) ];
				mday_items.push([ idx, num_label ]);
			}
			
			html += '<div class="timing_details_label">Days of the Month</div>';
			html += '<div class="timing_details_content">' + this.get_timing_checkbox_set( 'day', mday_items, timing.days || [] ) + '</div>';
		} // days
		
		if (tmode.match(/(custom|yearly|monthly|weekly|daily)/)) {
			// show hours
			var hour_items = [];
			for (var idx = 0; idx < 24; idx++) {
				hour_items.push([ idx, _hour_names[idx].toUpperCase() ]);
			}
			
			html += '<div class="timing_details_label">Hours</div>';
			html += '<div class="timing_details_content">' + this.get_timing_checkbox_set( 'hour', hour_items, timing.hours || [] ) + '</div>';
		} // hours
		
		// always show minutes (if timing is enabled)
		if (timing) {
			var min_items = [];
			for (var idx = 0; idx < 60; idx += this.show_all_minutes ? 1 : 5) {
				var num_str = ':' + ((idx < 10) ? '0' : '') + idx;
				min_items.push([ idx, num_str, (idx % 5 == 0) ? '' : 'plain' ]);
			} // minutes
			
			html += '<div class="timing_details_label">Minutes';
			html += ' <span class="link" style="font-weight:normal; font-size:11px" onMouseUp="$P().toggle_show_all_minutes()">(' + (this.show_all_minutes ? 'Show Less' : 'Show All') + ')</span>';
			html += '</div>';
			
			html += '<div class="timing_details_content">';
				html += this.get_timing_checkbox_set( 'minute', min_items, timing.minutes || [], function(idx) {
					var num_str = ':' + ((idx < 10) ? '0' : '') + idx;
					return([ idx, num_str, (idx % 5 == 0) ? '' : 'plain' ]);
				} );
			html += '</div>';
		}
		
		// summary
		html += '<div class="info_label">The event will run:</div>';
		html += '<div class="info_value" id="d_ee_timing_summary">' + summarize_event_timing(timing, event.timezone).replace(/(every\s+minute)/i, '<span style="color:red">$1</span>') + '</div>';
		
		html += '</fieldset>';
		html += '<div class="caption" style="margin-top:6px;">Choose when and how often the event should run.</div>';
		
		setTimeout( function() {
			$('.ccbox_timing').mouseup( function() {
				// need another delay for event listener race condition
				// we want this to happen LAST, after the CSS classes are updated
				setTimeout( function() {
					$P().change_edit_timing_param();
				}, 1 );
			} );
		}, 1 );
		
		return html;
	},
	
	toggle_show_all_minutes: function() {
		// toggle showing every minutes from 0 - 59, to just the 5s
		this.show_all_minutes = !this.show_all_minutes;
		var tmode = $('#fe_ee_timing').val();
		$('#d_ee_timing_params').html( this.get_timing_params_html(tmode) );
	},
	
	change_edit_timing_param: function() {
		// edit timing param has changed, refresh entire timing block
		// rebuild entire event.timing object from scratch
		var event = this.event;
		event.timing = {};
		var timing = event.timing;
		
		// if tmode is demand, wipe timing object
		if ($('#fe_ee_timing').val() == 'demand') {
			event.timing = false;
			timing = false;
		}
		
		$('.ccbox_timing_year.checked').each( function() {
			if (this.id.match(/_(\d+)$/)) {
				var year = parseInt( RegExp.$1 );
				if (!timing.years) timing.years = [];
				timing.years.push( year );
			}
		} );
		
		$('.ccbox_timing_month.checked').each( function() {
			if (this.id.match(/_(\d+)$/)) {
				var month = parseInt( RegExp.$1 );
				if (!timing.months) timing.months = [];
				timing.months.push( month );
			}
		} );
		
		$('.ccbox_timing_weekday.checked').each( function() {
			if (this.id.match(/_(\d+)$/)) {
				var weekday = parseInt( RegExp.$1 );
				if (!timing.weekdays) timing.weekdays = [];
				timing.weekdays.push( weekday );
			}
		} );
		
		$('.ccbox_timing_day.checked').each( function() {
			if (this.id.match(/_(\d+)$/)) {
				var day = parseInt( RegExp.$1 );
				if (!timing.days) timing.days = [];
				timing.days.push( day );
			}
		} );
		
		$('.ccbox_timing_hour.checked').each( function() {
			if (this.id.match(/_(\d+)$/)) {
				var hour = parseInt( RegExp.$1 );
				if (!timing.hours) timing.hours = [];
				timing.hours.push( hour );
			}
		} );
		
		$('.ccbox_timing_minute.checked').each( function() {
			if (this.id.match(/_(\d+)$/)) {
				var minute = parseInt( RegExp.$1 );
				if (!timing.minutes) timing.minutes = [];
				timing.minutes.push( minute );
			}
		} );
		
		// update summary
		$('#d_ee_timing_summary').html( summarize_event_timing(timing, event.timezone).replace(/(every\s+minute)/i, '<span style="color:red">$1</span>') );
	},
	
	get_timing_checkbox_set: function(name, items, values, auto_add) {
		// render html for set of color label checkboxes for timing category
		var html = '';
		
		// make sure all items are arrays
		for (var idx = 0, len = items.length; idx < len; idx++) {
			var item = items[idx];
			if (!isa_array(item)) items[idx] = [item, item];
		}
		
		// add unknown values to items array
		if (auto_add) {
			var is_callback = !!(typeof(auto_add) == 'function');
			var added = 0;
			for (var idx = 0, len = values.length; idx < len; idx++) {
				var value = values[idx];
				var found = false;
				for (var idy = 0, ley = items.length; idy < ley; idy++) {
					if (items[idy][0] == value) { found = true; idy = ley; }
				} // foreach item
				if (!found) {
					items.push( is_callback ? auto_add(value) : [value, value] ); 
					added++; 
				}
			} // foreach value
			
			// resort items
			if (added) {
				items = items.sort( function(a, b) {
					return a[0] - b[0];
				} );
			}
		} // auto_add
		
		for (var idx = 0, len = items.length; idx < len; idx++) {
			var item = items[idx];
			var checked = !!(values.indexOf(item[0]) > -1);
			var classes = [];
			if (checked) classes.push("checked");
			classes.push( "ccbox_timing" );
			classes.push( "ccbox_timing_" + name );
			if (item[2]) classes.push( item[2] );
			
			if (html) html += ' ';
			html += app.get_color_checkbox_html("ccbox_timing_" + name + '_' + item[0], item[1], classes.join(' '));
			// NOTE: the checkbox id isn't currently even used
			
			// if (break_every && (((idx + 1) % break_every) == 0)) html += '<br/>';
		} // foreach item
		
		return html;
	},
	
	change_edit_plugin: function() {
		// switch plugins, set default params, refresh param editor
		var event = this.event;
		var plugin_id = $('#fe_ee_plugin').val();
		event.plugin = plugin_id;
		event.params = {};
		
		if (plugin_id) {
			var plugin = find_object( app.plugins, { id: plugin_id } );
			if (plugin && plugin.params && plugin.params.length) {
				for (var idx = 0, len = plugin.params.length; idx < len; idx++) {
					var param = plugin.params[idx];
					event.params[ param.id ] = param.value;
				}
			}
		}
		
		this.refresh_plugin_params();
	},
	
	get_plugin_params_html: function() {
		// get plugin param editor html
		var html = '';
		var event = this.event;
		var params = event.params;
		
		if (event.plugin) {
			var plugin = find_object( app.plugins, { id: event.plugin } );
			if (plugin && plugin.params && plugin.params.length) {
				
				html += '<div style="font-size:13px; margin-top:7px; display:none;"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Plugin Parameters</span></div>';
				html += '<fieldset style="margin-top:7px; padding:10px 10px 0 10px;"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Plugin Parameters</legend>';
				
				// html += '<fieldset style="margin-top:7px; padding:10px 10px 0 10px;"><legend>Plugin Parameters</legend>';
				
				for (var idx = 0, len = plugin.params.length; idx < len; idx++) {
					var param = plugin.params[idx];
					var value = (param.id in params) ? params[ param.id ] : param.value;
					switch (param.type) {
						
						case 'text':
							html += '<div class="plugin_params_label">' + param.title + '</div>';
							html += '<div class="plugin_params_content"><input type="text" id="fe_ee_pp_'+param.id+'" size="'+param.size+'" value="'+escape_text_field_value(value)+'" spellcheck="false"/></div>';
						break;
						
						case 'textarea':
							var ta_height = parseInt(param.rows) * 15;
							html += '<div class="plugin_params_label">' + param.title + '</div>';
							html += '<div class="plugin_params_content"><textarea id="fe_ee_pp_'+param.id+'" style="width:99%; height:'+ta_height+'px; resize:vertical;" spellcheck="false" onkeydown="return catchTab(this,event)">'+escape_text_field_value(value)+'</textarea></div>';
						break;
						
						case 'checkbox':
							html += '<div class="plugin_params_content"><input type="checkbox" id="fe_ee_pp_'+param.id+'" value="1" ' + (value ? 'checked="checked"' : '') + '/><label for="fe_ee_pp_'+param.id+'">' + param.title + '</label></div>';
						break;
						
						case 'select':
							html += '<div class="plugin_params_label">' + param.title + '</div>';
							html += '<div class="plugin_params_content"><select id="fe_ee_pp_'+param.id+'">' + render_menu_options(param.items, value, true) + '</select></div>';
						break;
						
						case 'hidden':
							// no visible UI
						break;
						
					} // switch type
				} // foreach param
				
				html += '</fieldset>';
				html += '<div class="caption" style="margin-top:6px;">Select the plugin parameters for the event.</div>';
			} // plugin params
			else {
				html += '<div class="caption">The selected plugin has no editable parameters.</div>';
			}
		}
		else {
			html += '<div class="caption">Select a plugin to edit its parameters.</div>';
		}
		
		return html;
	},
	
	refresh_plugin_params: function() {
		// redraw plugin param area after change
		$('#d_ee_plugin_params').html( this.get_plugin_params_html() );
	},
	
	get_event_form_json: function(quiet) {
		// get event elements from form, used for new or edit
		var event = this.event;
		
		// event title
		event.title = trim( $('#fe_ee_title').val() );
		if (!event.title) return quiet ? false : app.badField('fe_ee_title', "Please enter a title for the event.");
		
		// event enabled
		event.enabled = $('#fe_ee_enabled').is(':checked') ? 1 : 0;
		
		// category
		event.category = $('#fe_ee_cat').val();
		if (!event.category) return quiet ? false : app.badField('fe_ee_cat', "Please select a Category for the event."); 
		
		// target (server group or individual server)
		event.target = $('#fe_ee_target').val();
		
		// algo / multiplex / stagger
		event.algo = $('#fe_ee_algo').val();
		event.multiplex = (event.algo == 'multiplex') ? 1 : 0;
		if (event.multiplex) {
			event.stagger = parseInt( $('#fe_ee_stagger').val() ) * parseInt( $('#fe_ee_stagger_units').val() );
			if (isNaN(event.stagger)) return quiet ? false : app.badField('fe_ee_stagger', "Please enter a number of seconds to stagger by.");
		}
		else {
			event.stagger = 0;
		}
		
		// plugin
		event.plugin = $('#fe_ee_plugin').val();
		if (!event.plugin) return quiet ? false : app.badField('fe_ee_plugin', "Please select a Plugin for the event."); 
		
		// plugin params
		event.params = {};
		var plugin = find_object( app.plugins, { id: event.plugin } );
		if (plugin && plugin.params && plugin.params.length) {
			for (var idx = 0, len = plugin.params.length; idx < len; idx++) {
				var param = plugin.params[idx];
				switch (param.type) {
					case 'text':
					case 'textarea':
					case 'select':
						event.params[ param.id ] = $('#fe_ee_pp_' + param.id).val();
					break;
					
					case 'hidden':
						// Special case: Always set this to the plugin default value
						event.params[ param.id ] = param.value;
					break;
					
					case 'checkbox':
						event.params[ param.id ] = $('#fe_ee_pp_' + param.id).is(':checked') ? 1 : 0;
					break;
				} // switch type
			} // foreach param
		} // plugin params
		
		// timezone
		event.timezone = $('#fe_ee_timezone').val();
		
		// max children
		event.max_children = parseInt( $('#fe_ee_max_children').val() );
		
		// timeout
		event.timeout = parseInt( $('#fe_ee_timeout').val() ) * parseInt( $('#fe_ee_timeout_units').val() );
		if (isNaN(event.timeout)) return quiet ? false : app.badField('fe_ee_timeout', "Please enter an integer value for the event timeout.");
		if (event.timeout < 0) return quiet ? false : app.badField('fe_ee_timeout', "Please enter a positive integer for the event timeout.");
		
		// retries
		event.retries = parseInt( $('#fe_ee_retries').val() );
		event.retry_delay = parseInt( $('#fe_ee_retry_delay').val() ) * parseInt( $('#fe_ee_retry_delay_units').val() );
		if (isNaN(event.retry_delay)) return quiet ? false : app.badField('fe_ee_retry_delay', "Please enter an integer value for the event retry delay.");
		if (event.retry_delay < 0) return quiet ? false : app.badField('fe_ee_retry_delay', "Please enter a positive integer for the event retry delay.");
		
		// catch-up mode (run all)
		event.catch_up = $('#fe_ee_catch_up').is(':checked') ? 1 : 0;

		// method (interruptable, non-interruptable)
		event.detached = $('#fe_ee_detached').is(':checked') ? 1 : 0;
		
		// event queue
		event.queue = $('#fe_ee_queue').is(':checked') ? 1 : 0;
		event.queue_max = parseInt( $('#fe_ee_queue_max').val() || "0" );
		if (isNaN(event.queue_max)) return quiet ? false : app.badField('fe_ee_queue_max', "Please enter an integer value for the event queue max.");
		if (event.queue_max < 0) return quiet ? false : app.badField('fe_ee_queue_max', "Please enter a positive integer for the event queue max.");
		
		// chain reaction
		event.chain = $('#fe_ee_chain').val();
		event.chain_error = $('#fe_ee_chain_error').val();
		
		// cursor reset
		if (event.id && event.catch_up && $('#fe_ee_rc_enabled').is(':checked')) {
			var new_cursor = parseInt( $('#fe_ee_rc_time').data('epoch') );
			if (!new_cursor || isNaN(new_cursor)) return quiet ? false : app.badField('fe_ee_rc_time', "Please enter a valid date/time for the new event time.");
			event['reset_cursor'] = normalize_time( new_cursor, { sec: 0 } );
		}
		else delete event['reset_cursor'];
		
		// notification
		event.notify_success = $('#fe_ee_notify_success').val();
		event.notify_fail = $('#fe_ee_notify_fail').val();
		event.web_hook = $('#fe_ee_web_hook').val();
		
		// cpu limit
		if ($('#fe_ee_cpu_enabled').is(':checked')) {
			event.cpu_limit = parseInt( $('#fe_ee_cpu_limit').val() );
			if (isNaN(event.cpu_limit)) return quiet ? false : app.badField('fe_ee_cpu_limit', "Please enter an integer value for the CPU limit.");
			if (event.cpu_limit < 0) return quiet ? false : app.badField('fe_ee_cpu_limit', "Please enter a positive integer for the CPU limit.");
			
			event.cpu_sustain = parseInt( $('#fe_ee_cpu_sustain').val() ) * parseInt( $('#fe_ee_cpu_sustain_units').val() );
			if (isNaN(event.cpu_sustain)) return quiet ? false : app.badField('fe_ee_cpu_sustain', "Please enter an integer value for the CPU sustain period.");
			if (event.cpu_sustain < 0) return quiet ? false : app.badField('fe_ee_cpu_sustain', "Please enter a positive integer for the CPU sustain period.");
		}
		else {
			event.cpu_limit = 0;
			event.cpu_sustain = 0;
		}
		
		// mem limit
		if ($('#fe_ee_memory_enabled').is(':checked')) {
			event.memory_limit = parseInt( $('#fe_ee_memory_limit').val() ) * parseInt( $('#fe_ee_memory_limit_units').val() );
			if (isNaN(event.memory_limit)) return quiet ? false : app.badField('fe_ee_memory_limit', "Please enter an integer value for the memory limit.");
			if (event.memory_limit < 0) return quiet ? false : app.badField('fe_ee_memory_limit', "Please enter a positive integer for the memory limit.");
			
			event.memory_sustain = parseInt( $('#fe_ee_memory_sustain').val() ) * parseInt( $('#fe_ee_memory_sustain_units').val() );
			if (isNaN(event.memory_sustain)) return quiet ? false : app.badField('fe_ee_memory_sustain', "Please enter an integer value for the memory sustain period.");
			if (event.memory_sustain < 0) return quiet ? false : app.badField('fe_ee_memory_sustain', "Please enter a positive integer for the memory sustain period.");
		}
		else {
			event.memory_limit = 0;
			event.memory_sustain = 0;
		}
		
		// log file size limit
		if ($('#fe_ee_log_enabled').is(':checked')) {
			event.log_max_size = parseInt( $('#fe_ee_log_limit').val() ) * parseInt( $('#fe_ee_log_limit_units').val() );
			if (isNaN(event.log_max_size)) return quiet ? false : app.badField('fe_ee_log_limit', "Please enter an integer value for the log size limit.");
			if (event.log_max_size < 0) return quiet ? false : app.badField('fe_ee_log_limit', "Please enter a positive integer for the log size limit.");
		}
		else {
			event.log_max_size = 0;
		}
		
		// notes
		event.notes = trim( $('#fe_ee_notes').val() );
		
		return event;
	},
	
	onDataUpdate: function(key, value) {
		// recieved data update (websocket), see if sub-page cares about it
		switch (key) {
			case 'schedule':
				if (this.args.sub == 'events') this.gosub_events(this.args);
			break;
			
			case 'state':
				if (this.args.sub == 'edit_event') this.update_rc_value();
				else if (this.args.sub == 'events') this.update_job_last_runs();
			break;
		}
	},
	
	onStatusUpdate: function(data) {
		// received status update (websocket)
		if (data.jobs_changed) this.update_live_job_counts();
	},
	
	onResizeDelay: function(size) {
		// called 250ms after latest window resize
		// so we can run more expensive redraw operations
		if (this.args.sub == 'events') this.gosub_events(this.args);
	},
	
	leavesub_edit_event: function(args) {
		// special hook fired when leaving edit_event sub-page
		// try to save edited state of event in mem cache
		if (this.event_copy) return; // in middle of edit --> copy operation
		
		var event = this.get_event_form_json(true); // quiet mode
		if (event) {
			app.autosave_event = event;
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		// this.div.html( '' );
		
		// allow sub-page to hook deactivate
		if (this.args && this.args.sub && this['leavesub_'+this.args.sub]) {
			this['leavesub_'+this.args.sub](this.args);
		}
		
		return true;
	}
	
} );

// Cronicle History Page

Class.subclass( Page.Base, "Page.History", {	
	
	default_sub: 'history',
	
	onInit: function() {
		// called once at page load
		// var html = '';
		// this.div.html( html );
		this.charts = {};
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		if (!args.sub) args.sub = this.default_sub;
		this.args = args;
		
		app.showTabBar(true);
		this.tab[0]._page_id = Nav.currentAnchor();
		
		this.div.addClass('loading');
		this['gosub_'+args.sub](args);
		
		return true;
	},
	
	gosub_history: function(args) {
		// show history
		app.setWindowTitle( "History" );
		
		var html = '';
		// html += '<div style="padding:5px 15px 15px 15px;">';
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'All Completed Jobs';
			// html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().refresh_user_list()"><b>Refresh</b></span></div>';
			// html += '<div class="subtitle_widget"><i class="fa fa-search">&nbsp;</i><input type="text" id="fe_ul_search" size="15" placeholder="Find username..." style="border:0px;"/></div>';
			var sorted_events = app.schedule.sort( function(a, b) {
				return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
			} );
			html += '<div class="subtitle_widget"><i class="fa fa-chevron-down">&nbsp;</i><select id="fe_hist_event" class="subtitle_menu" onChange="$P().jump_to_event_history()"><option value="">Filter by Event</option>' + render_menu_options( sorted_events, '', false ) + '</select></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		html += '<div id="d_history_table"></div>';
		html += '</div>'; // padding
		this.div.html( html );
		
		this.get_history();
	},
	
	get_history: function() {
		var args = this.args;
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = config.default_job_history_limit || 25;
		app.api.post( 'app/get_history', copy_object(args), this.receive_history.bind(this) );
	},
	
	receive_history: function(resp) {
		// receive page of history from server, render it
		this.lastHistoryResp = resp;
		
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) - 50) / 8 );
		
		this.events = [];
		if (resp.rows) this.events = resp.rows;
		
		var cols = ['Job ID', 'Event Name', 'Category', 'Plugin', 'Hostname', 'Result', 'Start Date/Time', 'Elapsed Time'];
		
		var self = this;
		var num_visible_items = 0;
		
		html += this.getPaginatedTable( resp, cols, 'event', function(job, idx) {
			/*var actions = [
				'<a href="#JobDetails?id='+job.id+'"><b>Job&nbsp;Details</b></a>',
				'<a href="#History?sub=event_history&id='+job.event+'"><b>Event&nbsp;History</b></a>'
			];*/
			
			// suppress row view if job was deleted
			if (job.action != 'job_complete') return null;
			num_visible_items++;
			
			var event = find_object( app.schedule, { id: job.event } );
			var event_link = '(None)';
			if (event && job.id) {
				event_link = '<div class="td_big"><a href="#History?sub=event_history&id='+job.event+'">' + self.getNiceEvent('<b>' + (event.title || job.event) + '</b>', col_width + 40) + '</a></div>';
			}
			else if (job.event_title) {
				event_link = self.getNiceEvent(job.event_title, col_width + 40);
			}
			
			var cat = job.category ? find_object( app.categories, { id: job.category } ) : null;
			if (!cat && job.category_title) cat = { id: job.category, title: job.category_title };
			
			var plugin = job.plugin ? find_object( app.plugins, { id: job.plugin } ) : null;
			if (!plugin && job.plugin_title) plugin = { id: job.plugin, title: job.plugin_title };
			
			var job_link = '<div class="td_big">--</div>';
			if (job.id) job_link = '<div class="td_big"><a href="#JobDetails?id='+job.id+'"><b>' + self.getNiceJob(job) + '</b></a></div>';
			
			var tds = [
				job_link,
				event_link,
				self.getNiceCategory( cat, col_width ),
				self.getNicePlugin( plugin, col_width ),
				self.getNiceGroup( null, job.hostname, col_width ),
				(job.code == 0) ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Success</span>' : '<span class="color_label red"><i class="fa fa-warning">&nbsp;</i>Error</span>',
				get_nice_date_time( job.time_start, false, true ),
				get_text_from_seconds( job.elapsed, true, false )
				// actions.join(' | ')
			];
			
			if (!job.id) tds.className = 'disabled';
			
			if (cat && cat.color) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += cat.color;
			}
			
			return tds;
		} );
		
		if (resp.rows && resp.rows.length && !num_visible_items) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'All items were deleted on this page.';
			html += '</td></tr>';
		}
		
		this.div.find('#d_history_table').html( html );
	},
	
	jump_to_event_history: function() {
		// make a selection from the event filter menu
		var id = $('#fe_hist_event').val();
		if (id) Nav.go( '#History?sub=event_history&id=' + id );
	},
	
	gosub_event_stats: function(args) {
		// request event stats
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = config.default_job_stats_limit || 50;
		app.api.post( 'app/get_event_history', copy_object(args), this.receive_event_stats.bind(this) );
	},
	
	receive_event_stats: function(resp) {
		// render event stats page
		this.lastEventStatsResp = resp;
		
		var html = '';
		var args = this.args;
		var rows = this.rows = resp.rows;
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) - 300) / 4 );
		
		var event = find_object( app.schedule, { id: args.id } ) || null;
		if (!event) return app.doError("Could not locate event in schedule: " + args.id);
		
		var cat = event.category ? find_object( app.categories, { id: event.category } ) : null;
		var group = event.target ? find_object( app.server_groups, { id: event.target } ) : null;
		var plugin = event.plugin ? find_object( app.plugins, { id: event.plugin } ) : null;
		
		if (group && event.multiplex) {
			group = copy_object(group);
			group.multiplex = 1;
		}
		
		app.setWindowTitle( "Event Stats: " + event.title );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'event_stats',
			[
				['history', "All Completed"],
				['event_stats', "Event Stats"],
				['event_history&id=' + args.id, "Event History"]
			]
		);
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<fieldset style="margin-top:0px; margin-right:0px; padding-top:10px;"><legend>Event Stats</legend>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">EVENT NAME</div>';
				html += '<div class="info_value"><a href="#Schedule?sub=edit_event&id='+event.id+'">' + this.getNiceEvent(event.title, col_width) + '</a></div>';
				
				html += '<div class="info_label">CATEGORY NAME</div>';
				html += '<div class="info_value">' + this.getNiceCategory(cat, col_width) + '</div>';
				
				html += '<div class="info_label">EVENT TIMING</div>';
				html += '<div class="info_value">' + (event.enabled ? summarize_event_timing(event.timing, event.timezone) : '(Disabled)') + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">USERNAME</div>';
				html += '<div class="info_value">' + this.getNiceUsername(event, false, col_width) + '</div>';
				
				html += '<div class="info_label">PLUGIN NAME</div>';
				html += '<div class="info_value">' + this.getNicePlugin(plugin, col_width) + '</div>';
				
				html += '<div class="info_label">EVENT TARGET</div>';
				html += '<div class="info_value">' + this.getNiceGroup(group, event.target, col_width) + '</div>';
			html += '</div>';
			
			var total_elapsed = 0;
			var total_cpu = 0;
			var total_mem = 0;
			var total_success = 0;
			var total_log_size = 0;
			var count = 0;
			
			for (var idx = 0, len = rows.length; idx < len; idx++) {
				var job = rows[idx];
				if (job.action != 'job_complete') continue;
				
				count++;
				total_elapsed += (job.elapsed || 0);
				if (job.cpu && job.cpu.total) total_cpu += (job.cpu.total / (job.cpu.count || 1));
				if (job.mem && job.mem.total) total_mem += (job.mem.total / (job.mem.count || 1));
				if (job.code == 0) total_success++;
				total_log_size += (job.log_file_size || 0);
			}
			if (!count) count = 1;
			
			var nice_last_result = 'n/a';
			if (rows.length > 0) {
				var job = find_object( rows, { action: 'job_complete' } );
				if (job) nice_last_result = (job.code == 0) ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Success</span>' : '<span class="color_label red"><i class="fa fa-warning">&nbsp;</i>Error</span>';
			}
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">AVG. ELAPSED</div>';
				html += '<div class="info_value">' + get_text_from_seconds(total_elapsed / count, true, false) + '</div>';
				
				html += '<div class="info_label">AVG. CPU</div>';
				html += '<div class="info_value">' + short_float(total_cpu / count) + '%</div>';
				
				html += '<div class="info_label">AVG. MEMORY</div>';
				html += '<div class="info_value">' + get_text_from_bytes( total_mem / count ) + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">SUCCESS RATE</div>';
				html += '<div class="info_value">' + pct(total_success, count) + '</div>';
				
				html += '<div class="info_label">LAST RESULT</div>';
				html += '<div class="info_value" style="position:relative; top:1px;">' + nice_last_result + '</div>';
				
				html += '<div class="info_label">AVG. LOG SIZE</div>';
				html += '<div class="info_value">' + get_text_from_bytes( total_log_size / count ) + '</div>';
			html += '</div>';
			
			html += '<div class="clear"></div>';
		html += '</fieldset>';
		
		// graph containers
		html += '<div style="margin-top:15px;">';
			html += '<div class="graph-title">Performance History</div>';
			html += '<div id="d_graph_hist_perf" style="position:relative; width:100%; height:300px; overflow:hidden;"><canvas id="c_graph_hist_perf"></canvas></div>';
		html += '</div>';
		
		html += '<div style="margin-top:10px; margin-bottom:20px; height:1px; background:#ddd;"></div>';
		
		// cpu / mem graphs
		html += '<div style="margin-top:0px;">';
			html += '<div style="float:left; width:50%;">';
				html += '<div class="graph-title">CPU Usage History</div>';
				html += '<div id="d_graph_hist_cpu" style="position:relative; width:100%; margin-right:5px; height:225px; overflow:hidden;"><canvas id="c_graph_hist_cpu"></canvas></div>';
			html += '</div>';
			html += '<div style="float:left; width:50%;">';
				html += '<div class="graph-title">Memory Usage History</div>';
				html += '<div id="d_graph_hist_mem" style="position:relative; width:100%; margin-left:5px; height:225px; overflow:hidden;"><canvas id="c_graph_hist_mem"></canvas></div>';
			html += '</div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		// graphs
		this.render_perf_line_chart();
		this.render_cpu_line_chart();
		this.render_mem_line_chart();
	},
	
	render_perf_line_chart: function() {
		// event perf over time
		var rows = this.rows;
		
		var perf_keys = {};
		var perf_data = [];
		var perf_times = [];
		
		// build perf data for chart
		// read backwards as server data is unshifted (descending by date, newest first)
		for (var idx = rows.length - 1; idx >= 0; idx--) {
			var job = rows[idx];
			if (job.action != 'job_complete') continue;
			
			if (!job.perf) job.perf = { total: job.elapsed };
			if (!isa_hash(job.perf)) job.perf = parse_query_string( job.perf.replace(/\;/g, '&') );
			
			var pscale = 1;
			if (job.perf.scale) {
				pscale = job.perf.scale;
			}
			
			var perf = deep_copy_object( job.perf.perf ? job.perf.perf : job.perf );
			delete perf.scale;
			
			// remove counters from pie
			for (var key in perf) {
				if (key.match(/^c_/)) delete perf[key];
			}
			
			if (perf.t) { perf.total = perf.t; delete perf.t; }
			if ((num_keys(perf) > 1) && perf.total) {
				if (!perf.other) {
					var totes = 0;
					for (var key in perf) {
						if (key != 'total') totes += perf[key];
					}
					if (totes < perf.total) {
						perf.other = perf.total - totes;
					}
				}
			}
			
			// divide everything by scale, so we get seconds
			for (var key in perf) {
				perf[key] /= pscale;
			}
			
			perf_data.push( perf );
			for (var key in perf) {
				perf_keys[key] = 1;
			}
			
			// track times as well
			perf_times.push( job.time_end || (job.time_start + job.elapsed) );
		} // foreach row
		
		// build up timestamp data
		var tstamp_col = [];
		for (var idy = 0, ley = perf_times.length; idy < ley; idy++) {
			tstamp_col.push( perf_times[idy] * 1000 );
		} // foreach row
		
		var sorted_keys = hash_keys_to_array(perf_keys).sort();
		var datasets = [];
		
		for (var idx = 0, len = sorted_keys.length; idx < len; idx++) {
			var perf_key = sorted_keys[idx];
			var clr = 'rgb(' + this.graph_colors[ idx % this.graph_colors.length ] + ')';
			var dataset = {
				label: perf_key,
				backgroundColor: clr,
				borderColor: clr,
				fill: false,
				data: []
			};
			
			for (var idy = 0, ley = perf_data.length; idy < ley; idy++) {
				var perf = perf_data[idy];
				var value = Math.max( 0, perf[perf_key] || 0 );
				dataset.data.push({ x: tstamp_col[idy], y: short_float(value) });
			} // foreach row
			
			datasets.push( dataset );
		} // foreach key
		
		this.charts.perf = new Chart( $('#c_graph_hist_perf').get(0).getContext('2d'), {
			type: 'line',
			data: { datasets: datasets },
			options: {
				animation: {
					duration: 0
				},
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: true,
					position: 'bottom',
					labels: {
						fontStyle: 'bold',
						padding: 15
					}
				},
				title:{
					display: false,
					text: ""
				},
				scales: {
					xAxes: [{
						type: "time",
						display: true,
						time: {
							parser: 'MM/DD/YYYY HH:mm',
							round: 'minute',
							tooltipFormat: 'll hh:mm a'
						},
						scaleLabel: {
							display: false,
							labelString: 'Date'
						}
					}, ],
					yAxes: [{
						ticks: {
							beginAtZero: true,
							callback: function(value, index, values) {
								if (value < 0) return '';
								return '' + get_text_from_seconds_round_custom(value, true);
							}
						},
						scaleLabel: {
							display: true,
							// labelString: 'value'
						}
					}]
				},
				tooltips: {
					mode: 'nearest',
					intersect: false,
					callbacks: {
						label: function(tooltip, data) {
							var value = short_float(tooltip.yLabel);
							if (value >= 60) value = get_text_from_seconds( Math.floor(value), 1, 0 ).replace(/&nbsp\;/ig, ' ');
							else value = '' + value + " sec";
							return " " + datasets[tooltip.datasetIndex].label + ": " + value;
						}
					}
				}
			}
		});
	},
	
	render_cpu_line_chart: function() {
		// event cpu usage over time
		var rows = this.rows;
		var color = Chart.helpers.color;
		
		var col_avg = [];
		var col_max = [];
		
		// build data for chart
		// read backwards as server data is unshifted (descending by date, newest first)
		for (var idx = rows.length - 1; idx >= 0; idx--) {
			var job = rows[idx];
			if (job.action != 'job_complete') continue;
			
			if (!job.cpu) job.cpu = {};
			var x = (job.time_end || (job.time_start + job.elapsed)) * 1000;
			
			col_avg.push({
				x: x,
				y: short_float( (job.cpu.total || 0) / (job.cpu.count || 1) )
			});
			
			col_max.push({
				x: x,
				y: short_float( job.cpu.max || 0 )
			});
		} // foreach row
		
		var datasets = [
			{
				label: "CPU Peak",
				borderColor: '#888888',
				fill: false,
				data: col_max
			},
			{
				label: "CPU Avg",
				borderColor: '#3f7ed5',
				backgroundColor: color('#3f7ed5').alpha(0.5).rgbString(),
				data: col_avg
			}
		];
		
		this.charts.cpu = new Chart( $('#c_graph_hist_cpu').get(0).getContext('2d'), {
			type: 'line',
			data: { datasets: datasets },
			options: {
				animation: {
					duration: 0
				},
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: true,
					position: 'bottom',
					labels: {
						fontStyle: 'bold',
						padding: 15
					}
				},
				title:{
					display: false,
					text: ""
				},
				scales: {
					xAxes: [{
						type: "time",
						display: true,
						time: {
							parser: 'MM/DD/YYYY HH:mm',
							round: 'minute',
							tooltipFormat: 'll hh:mm a'
						},
						scaleLabel: {
							display: false,
							labelString: 'Date'
						}
					}, ],
					yAxes: [{
						ticks: {
							beginAtZero: true,
							callback: function(value, index, values) {
								return '' + Math.round(value) + '%';
							}
						},
						scaleLabel: {
							display: true,
							// labelString: 'value'
						}
					}]
				},
				tooltips: {
					mode: 'index',
					intersect: false,
					callbacks: {
						label: function(tooltip, data) {
							return " " + datasets[tooltip.datasetIndex].label + ": " + short_float(tooltip.yLabel) + '%';
						}
					}
				}
			}
		});
	},
	
	render_mem_line_chart: function() {
		// event mem usage over time
		var rows = this.rows;
		var color = Chart.helpers.color;
		
		var col_avg = [];
		var col_max = [];
		
		// build data for chart
		// read backwards as server data is unshifted (descending by date, newest first)
		for (var idx = rows.length - 1; idx >= 0; idx--) {
			var job = rows[idx];
			if (job.action != 'job_complete') continue;
			
			if (!job.mem) job.mem = {};
			var x = (job.time_end || (job.time_start + job.elapsed)) * 1000;
			
			col_avg.push({
				x: x,
				y: short_float( (job.mem.total || 0) / (job.mem.count || 1) )
			});
			
			col_max.push({
				x: x,
				y: short_float( job.mem.max || 0 )
			});
		} // foreach row
		
		var datasets = [
			{
				label: "Mem Peak",
				borderColor: '#888888',
				fill: false,
				data: col_max
			},
			{
				label: "Mem Avg",
				borderColor: '#279321',
				backgroundColor: color('#279321').alpha(0.5).rgbString(),
				data: col_avg
			}
		];
		
		this.charts.mem = new Chart( $('#c_graph_hist_mem').get(0).getContext('2d'), {
			type: 'line',
			data: { datasets: datasets },
			options: {
				animation: {
					duration: 0
				},
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: true,
					position: 'bottom',
					labels: {
						fontStyle: 'bold',
						padding: 15
					}
				},
				title:{
					display: false,
					text: ""
				},
				scales: {
					xAxes: [{
						type: "time",
						display: true,
						time: {
							parser: 'MM/DD/YYYY HH:mm',
							round: 'minute',
							tooltipFormat: 'll hh:mm a'
						},
						scaleLabel: {
							display: false,
							labelString: 'Date'
						}
					}, ],
					yAxes: [{
						ticks: {
							beginAtZero: true,
							callback: function(value, index, values) {
								return '' + get_text_from_bytes(value, 1);
							}
						},
						scaleLabel: {
							display: true,
							// labelString: 'value'
						}
					}]
				},
				tooltips: {
					mode: 'index',
					intersect: false,
					callbacks: {
						label: function(tooltip, data) {
							return " " + datasets[tooltip.datasetIndex].label + ": " + get_text_from_bytes(tooltip.yLabel);
						}
					}
				}
			}
		});
	},
	
	gosub_event_history: function(args) {
		// show table of all history for a single event
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = 25;
		app.api.post( 'app/get_event_history', copy_object(args), this.receive_event_history.bind(this) );
	},
	
	receive_event_history: function(resp) {
		// render event history
		this.lastEventHistoryResp = resp;
		
		var html = '';
		var args = this.args;
		var rows = this.rows = resp.rows;
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) - 300) / 7 );
		
		var event = find_object( app.schedule, { id: args.id } ) || null;
		if (!event) return app.doError("Could not locate event in schedule: " + args.id);
		
		app.setWindowTitle( "Event History: " + event.title );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'event_history',
			[
				['history', "All Completed"],
				['event_stats&id=' + args.id, "Event Stats"],
				['event_history', "Event History"]
			]
		);
		html += '<div style="padding:20px 20px 30px 20px">';
		
		var cols = ['Job ID', 'Hostname', 'Result', 'Start Date/Time', 'Elapsed Time', 'Avg CPU', 'Avg Mem'];
		
		html += '<div class="subtitle">';
			html += 'Event History: ' + event.title;
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		var num_visible_items = 0;
		
		html += this.getPaginatedTable( resp, cols, 'event', function(job, idx) {
			if (job.action != 'job_complete') return null;
			num_visible_items++;
			
			var cpu_avg = 0;
			var mem_avg = 0;
			if (job.cpu) cpu_avg = short_float( (job.cpu.total || 0) / (job.cpu.count || 1) );
			if (job.mem) mem_avg = short_float( (job.mem.total || 0) / (job.mem.count || 1) );
			
			var tds = [
				'<div class="td_big"><a href="#JobDetails?id=' + job.id + '"><b>' + self.getNiceJob(job) + '</b></a></div>',
				self.getNiceGroup( null, job.hostname, col_width ),
				(job.code == 0) ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Success</span>' : '<span class="color_label red"><i class="fa fa-warning">&nbsp;</i>Error</span>',
				get_nice_date_time( job.time_start, false, true ),
				get_text_from_seconds( job.elapsed, true, false ),
				'' + cpu_avg + '%',
				get_text_from_bytes(mem_avg)
				// actions.join(' | ')
			];
			
			return tds;
		} );
		
		if (resp.rows && resp.rows.length && !num_visible_items) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'All items were deleted on this page.';
			html += '</td></tr>';
		}
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	onStatusUpdate: function(data) {
		// received status update (websocket), update sub-page if needed
		if (data.jobs_changed && (this.args.sub == 'history')) this.get_history();
	},
	
	onResizeDelay: function(size) {
		// called 250ms after latest window resize
		// so we can run more expensive redraw operations
		switch (this.args.sub) {
			case 'history':
				if (this.lastHistoryResp) {
					this.receive_history( this.lastHistoryResp );
				}
			break;
			
			case 'event_stats':
				if (this.lastEventStatsResp) {
					this.receive_event_stats( this.lastEventStatsResp );
				}
			break;
			
			case 'event_history':
				if (this.lastEventHistoryResp) {
					this.receive_event_history( this.lastEventHistoryResp );
				}
			break;
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		for (var key in this.charts) {
			this.charts[key].destroy();
		}
		this.charts = {};
		
		delete this.rows;
		if (this.args && (this.args.sub == 'event_stats')) this.div.html( '' );
		return true;
	}
	
});

// Cronicle JobDetails Page

Class.subclass( Page.Base, "Page.JobDetails", {	
	
	pie_colors: {
		cool: 'green',
		warm: 'rgb(240,240,0)',
		hot: '#F7464A',
		progress: '#3f7ed5',
		empty: 'rgba(0, 0, 0, 0.05)'
	},
	
	onInit: function() {
		// called once at page load
		// var html = '';
		// this.div.html( html );
		this.charts = {};
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		this.args = args;
		
		if (!args.id) {
			app.doError("The Job Details page requires a Job ID.");
			return true;
		}
		
		app.setWindowTitle( "Job Details: #" + args.id );
		app.showTabBar(true);
		
		this.tab.show();
		this.tab[0]._page_id = Nav.currentAnchor();
		
		this.retry_count = 3;
		this.go_when_ready();
		
		return true;
	},
	
	go_when_ready: function() {
		// make sure we're not in the limbo state between starting a manual job,
		// and waiting for activeJobs to be updated
		var self = this;
		var args = this.args;
		
		if (this.find_job(args.id)) {
			// job is currently active -- jump to real-time view
			args.sub = 'live';
			this.gosub_live(args);
		}
		else {
			// job must be completed -- jump to archive view
			args.sub = 'archive';
			this.gosub_archive(args);
		}
	},
	
	gosub_archive: function(args) {
		// show job archive
		var self = this;
		Debug.trace("Showing archived job: " + args.id);
		this.div.addClass('loading');
		
		app.api.post( 'app/get_job_details', { id: args.id }, this.receive_details.bind(this), function(resp) {
			// error capture
			if (self.retry_count >= 0) {
				Debug.trace("Failed to get_job_details, trying again in 1s...");
				self.retry_count--;
				setTimeout( function() { self.go_when_ready(); }, 1000 );
			}
			else {
				// show error
				app.doError("Error: " + resp.description);
				self.div.removeClass('loading');
			}
		} );
	},
	
	get_job_result_banner: function(job) {
		// render banner based on job result
		var icon = '';
		var type = '';
		if (job.abort_reason || job.unknown) {
			type = 'warning';
			icon = 'exclamation-circle';
		}
		else if (job.code) {
			type = 'error';
			icon = 'exclamation-triangle';
		}
		else {
			type = 'success';
			icon = 'check-circle';
		}
		
		if (!job.description && job.code) {
			job.description = "Job failed with code: " + job.code;
		}
		if (!job.code && (!job.description || job.description.replace(/\W+/, '').match(/^success(ful)?$/i))) {
			job.description = "Job completed successfully at " + get_nice_date_time(job.time_end, false, true);
			
			// add timezone abbreviation
			job.description += " " + moment.tz(job.time_end * 1000, app.tz).format('z');
		}
		if (job.code && !job.description.match(/^\s*error/i)) {
			var desc = job.description;
			job.description = "Error";
			if (job.code != 1) job.description += " " + job.code;
			job.description += ": " + desc;
		}
		
		var job_desc_html = trim( job.description.replace(/\r\n/g, "\n") );
		var multiline = !!job.description.match(/\n/);
		job_desc_html = encode_entities( job_desc_html ).replace(/\n/g, "<br/>\n");
		
		var html = '';
		html += '<div class="message inline '+type+'"><div class="message_inner">';
		
		if (multiline) {
			html += job_desc_html;
		}
		else {
			html += '<i class="fa fa-'+icon+' fa-lg" style="transform-origin:50% 50%; transform:scale(1.25); -webkit-transform:scale(1.25);">&nbsp;&nbsp;&nbsp;</i>' + job_desc_html;
		}
		html += '</div></div>';
		return html;
	},
	
	delete_job: function() {
		// delete job, after confirmation
		var self = this;
		var job = this.job;
		
		app.confirm( '<span style="color:red">Delete Job</span>', "Are you sure you want to delete the current job log and history?", "Delete", function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting job..." );
				app.api.post( 'app/delete_job', job, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Job ID '"+job.id+"' was deleted successfully.");
					$('#tab_History').trigger('click');
					self.tab.hide();
				} );
			}
		} );
	},
	
	run_again: function() {
		// run job again
		var self = this;
		var event = find_object( app.schedule, { id: this.job.event } ) || null;
		if (!event) return app.doError("Could not locate event in schedule: " + this.job.event_title + " (" + this.job.event + ")");
		
		var job = deep_copy_object( event );
		job.now = this.job.now;
		job.params = this.job.params;
		
		app.showProgress( 1.0, "Starting job..." );
		
		app.api.post( 'app/run_event', job, function(resp) {
			// app.showMessage('success', "Event '"+event.title+"' has been started.");
			self.jump_live_job_id = resp.ids[0];
			self.jump_live_time_start = hires_time_now();
			self.jump_to_live_when_ready();
		} );
	},
	
	jump_to_live_when_ready: function() {
		// make sure live view is ready (job may still be starting)
		var self = this;
		if (!this.active) return; // user navigated away from page
		
		if (app.activeJobs[this.jump_live_job_id] || ((hires_time_now() - this.jump_live_time_start) >= 3.0)) {
			app.hideProgress();
			Nav.go( 'JobDetails?id=' + this.jump_live_job_id );
			delete this.jump_live_job_id;
			delete this.jump_live_time_start;
		}
		else {
			setTimeout( self.jump_to_live_when_ready.bind(self), 250 );
		}
	},
	
	receive_details: function(resp) {
		// receive job details from server, render them
		var html = '';
		var job = this.job = resp.job;
		var token = this.token = resp.token;
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) - 300) / 4 );
		
		// locate objects
		var event = find_object( app.schedule, { id: job.event } ) || {};
		var cat = job.category ? find_object( app.categories, { id: job.category } ) : null;
		var group = event.target ? find_object( app.server_groups, { id: event.target } ) : null;
		var plugin = job.plugin ? find_object( app.plugins, { id: job.plugin } ) : null;
		
		if (group && event.multiplex) {
			group = copy_object(group);
			group.multiplex = 1;
		}
		
		html += '<div class="subtitle" style="margin-top:7px; margin-bottom:13px;">';
			html += 'Completed Job';
			if (event.id && !event.multiplex) html += '<div class="subtitle_widget" style="margin-left:2px;"><span class="link" onMouseUp="$P().run_again()"><i class="fa fa-repeat">&nbsp;</i><b>Run Again</b></span></div>';
			if (app.isAdmin()) html += '<div class="subtitle_widget"><span class="link abort" onMouseUp="$P().delete_job()"><i class="fa fa-trash-o">&nbsp;</i><b>Delete Job</b></span></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		// result banner
		html += this.get_job_result_banner(job);
		
		// fieldset header
		html += '<fieldset style="margin-top:8px; margin-right:0px; padding-top:10px; position:relative;"><legend>Job Details</legend>';
			
			// if (event.id && !event.multiplex) html += '<div class="button mini" style="position:absolute; top:15px; left:100%; margin-left:-110px;" onMouseUp="$P().run_again()">Run Again</div>';
			var nice_id = job.id;
			// Job labels originate in plugin output and must be treated as plain text.
			if (job.label) nice_id = encode_entities(job.label) + ' (' + job.id + ')';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">JOB ID</div>';
				html += '<div class="info_value">' + nice_id + '</div>';
				
				html += '<div class="info_label">EVENT NAME</div>';
				html += '<div class="info_value">';
					if (event.id) html += '<a href="#Schedule?sub=edit_event&id='+job.event+'">' + this.getNiceEvent(job.event_title, col_width) + '</a>';
					else if (job.event_title) html += this.getNiceEvent(job.event_title, col_width);
					else html += '(None)';
				html += '</div>';
				
				html += '<div class="info_label">EVENT TIMING</div>';
				html += '<div class="info_value">' + (event.enabled ? summarize_event_timing(event.timing, event.timezone) : '(Disabled)') + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">CATEGORY NAME</div>';
				html += '<div class="info_value">';
					if (cat) html += this.getNiceCategory(cat, col_width);
					else if (job.category_title) html += this.getNiceCategory({ title: job.category_title }, col_width);
					else html += '(None)';
				html += '</div>';
				
				html += '<div class="info_label">PLUGIN NAME</div>';
				html += '<div class="info_value">';
					if (plugin) html += this.getNicePlugin(plugin, col_width);
					else if (job.plugin_title) html += this.getNicePlugin({ title: job.plugin_title }, col_width);
					else html += '(None)';
				html += '</div>';
				
				html += '<div class="info_label">EVENT TARGET</div>';
				html += '<div class="info_value">';
					if (group || event.target) html += this.getNiceGroup(group, event.target, col_width);
					else if (job.nice_target) html += '<div class="ellip" style="max-width:'+col_width+'px;">' + job.nice_target + '</div>';
					else html += '(None)';
				html += '</div>';
			html += '</div>';
			
			var nice_source = (job.source || 'Scheduler');
			if (nice_source.match(/Chain Reaction/) && job.source_job) {
				nice_source = '<a href="#JobDetails?id=' + job.source_job + '">' + nice_source + '</a>';
			}
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">JOB SOURCE</div>';
				html += '<div class="info_value"><div class="" style="">' + nice_source + '</div></div>';
				
				html += '<div class="info_label">SERVER HOSTNAME</div>';
				html += '<div class="info_value">' + this.getNiceGroup( null, job.hostname, col_width ) + '</div>';
				
				html += '<div class="info_label">PROCESS ID</div>';
				html += '<div class="info_value">' + (job.detached_pid || job.pid || '(Unknown)') + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">JOB STARTED</div>';
				html += '<div class="info_value">';
					if ((job.time_start - job.now >= 60) && !event.multiplex && !job.source) {
						html += '<span style="color:red" title="Scheduled Time: '+get_nice_date_time(job.now, false, true)+'">';
						html += get_nice_date_time(job.time_start, false, true);
						html += '</span>';
					}
					else html += get_nice_date_time(job.time_start, false, true);
				html += '</div>';
				
				html += '<div class="info_label">JOB COMPLETED</div>';
				html += '<div class="info_value">' + get_nice_date_time(job.time_end, false, true) + '</div>';
				
				html += '<div class="info_label">ELAPSED TIME</div>';
				html += '<div class="info_value">' + get_text_from_seconds(job.elapsed, false, false) + '</div>';
			html += '</div>';
			
			html += '<div class="clear"></div>';
		html += '</fieldset>';
		
		// pies
		html += '<div style="position:relative; margin-top:15px;">';
			
			html += '<div class="pie-column column-left">';
				html += '<div class="pie-title">Performance Metrics</div>';
				html += '<div id="d_graph_arch_perf" style="position:relative; display:inline-block; width:250px; height:250px; overflow:hidden;"><canvas id="c_arch_perf" class="pie"></canvas></div>';
				// html += '<canvas id="c_arch_perf" width="250" height="250" class="pie"></canvas>';
				html += '<div id="d_arch_perf_legend" class="pie-legend-column"></div>';
			html += '</div>';
			
			html += '<div class="pie-column column-right">';
				html += '<div id="d_arch_mem_overlay" class="pie-overlay"></div>';
				html += '<div class="pie-title">Memory Usage</div>';
				html += '<div id="d_graph_arch_mem" style="position:relative; display:inline-block; width:250px; height:250px; overflow:hidden;"><canvas id="c_arch_mem" class="pie"></canvas></div>';
				// html += '<canvas id="c_arch_mem" width="250" height="250" class="pie"></canvas>';
				html += '<div id="d_arch_mem_legend" class="pie-legend-column"></div>';
			html += '</div>';
			
			html += '<div class="pie-column column-center">';
				html += '<div id="d_arch_cpu_overlay" class="pie-overlay"></div>';
				html += '<div class="pie-title">CPU Usage</div>';
				html += '<div id="d_graph_arch_cpu" style="position:relative; display:inline-block; width:250px; height:250px; overflow:hidden;"><canvas id="c_arch_cpu" class="pie"></canvas></div>';
				// html += '<canvas id="c_arch_cpu" width="250" height="250" class="pie"></canvas>';
				html += '<div id="d_arch_cpu_legend" class="pie-legend-column"></div>';
			html += '</div>';
			
		html += '</div>';
		
		// custom data table
		if (job.table && job.table.rows && job.table.rows.length) {
			var table = job.table;
			html += '<div class="subtitle" style="margin-top:15px;">' + encode_entities(table.title || 'Job Stats') + '</div>';
			html += '<table class="data_table" style="width:100%">';
			
			if (table.header && table.header.length) {
				html += '<tr>';
				for (var idx = 0, len = table.header.length; idx < len; idx++) {
					html += '<th>' + encode_entities(table.header[idx]) + '</th>';
				}
				html += '</tr>';
			}
			
			var filters = table.filters || [];
			
			for (var idx = 0, len = table.rows.length; idx < len; idx++) {
				var row = table.rows[idx];
				if (row && row.length) {
					html += '<tr>';
					
					for (var idy = 0, ley = row.length; idy < ley; idy++) {
						var col = row[idy];
						html += '<td>';
						if (typeof(col) != 'undefined') {
							if (filters[idy] && window[filters[idy]]) html += encode_entities( window[filters[idy]](col) );
							else if ((typeof(col) == 'string') && col.match(/^filter\:(\w+)\((.+)\)$/)) {
								var filter = RegExp.$1;
								var value = RegExp.$2;
								if (window[filter]) html += encode_entities( window[filter](value) );
								else html += encode_entities(value);
							}
							else html += encode_entities(col);
						}
						html += '</td>';
					} // foreach col
					
					html += '</tr>';
				} // good row
			} // foreach row
			
			html += '</table>';
			if (table.caption) html += '<div class="caption" style="margin-top:4px; text-align:center;">' + encode_entities(table.caption) + '</div>';
		} // custom data table
		
		// custom html table
		if (job.html) {
			html += '<div class="subtitle" style="margin-top:15px;">' + encode_entities(job.html.title || 'Job Report') + '</div>';
			html += '<div>' + job.html.content + '</div>'; // this was pre-sanitized on the server
			if (job.html.caption) html += '<div class="caption" style="margin-top:4px; text-align:center;">' + encode_entities(job.html.caption) + '</div>';
		}
		
		// job log (IFRAME)
		html += '<div class="subtitle" style="margin-top:15px;">';
			html += 'Job Event Log';
			if (job.log_file_size) html += ' (' + get_text_from_bytes(job.log_file_size, 1) + ')';
			html += '<div class="subtitle_widget" style="margin-left:2px;"><a href="/api/app/get_job_log?id=' + job.id + '&t=' + token + '" target="_blank"><i class="fa fa-external-link">&nbsp;</i><b>View Full Log</b></a></div>';
			html += '<div class="subtitle_widget"><a href="/api/app/get_job_log?id=' + job.id + '&t=' + token + '&download=1"><i class="fa fa-download">&nbsp;</i><b>Download Log</b></a></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var max_log_file_size = config.max_log_file_size || 10485760;
		if (job.log_file_size && (job.log_file_size >= max_log_file_size)) {
			// too big to show?  ask user
			html += '<div id="d_job_log_warning">';
			html += '<table class="data_table" width="100%"><tr><td style="padding-top:50px; padding-bottom:50px; text-align:center">';
			html += '<div style="margin-bottom:15px;"><b>Warning: Job event log file is ' + get_text_from_bytes(job.log_file_size, 1) + '.  Please consider downloading instead of viewing in browser.</b></div>';
			html += '<div style="width:50%; float:left;"><div class="button right" style="width:110px; margin-right:20px;" onMouseUp="$P().do_download_log()">Download Log</div></div>';
			html += '<div style="width:50%; float:left;"><div class="button left" style="width:110px; margin-left:20px;" onMouseUp="$P().do_view_inline_log()">View Log</div></div>';			
			html += '<div class="clear"></div>';
			html += '</td></tr></table>';
			html += '</div>';
		}
		else {
			var size = get_inner_window_size();
			var iheight = size.height - 100;
			html += '<iframe id="i_arch_job_log" style="width:100%; height:' + iheight + 'px; border:none;" frameborder="0" src="' + app.base_api_url + '/app/get_job_log?id=' + job.id + '&t=' + token + '"></iframe>';
		}
		
		this.div.html( html );
		
		// arch perf chart
		var suffix = ' sec';
		var pscale = 1;
		if (!job.perf) job.perf = { total: job.elapsed };
		if (!isa_hash(job.perf)) job.perf = parse_query_string( job.perf.replace(/\;/g, '&') );
		
		if (job.perf.scale) {
			pscale = job.perf.scale;
			delete job.perf.scale;
		}
		
		var perf = job.perf.perf ? job.perf.perf : job.perf;
		
		// remove counters from pie
		for (var key in perf) {
			if (key.match(/^c_/)) delete perf[key];
		}
		
		// clean up total, add other
		if (perf.t) { perf.total = perf.t; delete perf.t; }
		if ((num_keys(perf) > 1) && perf.total) {
			if (!perf.other) {
				var totes = 0;
				for (var key in perf) {
					if (key != 'total') totes += perf[key];
				}
				if (totes < perf.total) {
					perf.other = perf.total - totes;
				}
			}
			delete perf.total; // only show total if by itself
		}
		
		// remove outer 'umbrella' perf keys if inner ones are more specific
		// (i.e. remove "db" if we have "db_query" and/or "db_connect")
		for (var key in perf) {
			for (var subkey in perf) {
				if ((subkey.indexOf(key + '_') == 0) && (subkey.length > key.length + 1)) {
					delete perf[key];
					break;
				}
			}
		}
		
		// divide everything by scale, so we get seconds
		for (var key in perf) {
			perf[key] /= pscale;
		}
		
		var colors = this.graph_colors;
		var color_idx = 0;
		
		var p_data = [];
		var p_colors = [];
		var p_labels = [];
		
		var perf_keys = hash_keys_to_array(perf).sort();
		
		for (var idx = 0, len = perf_keys.length; idx < len; idx++) {
			var key = perf_keys[idx];
			var value = perf[key];
			
			p_data.push( short_float(value) );
			p_colors.push( 'rgb(' + colors[color_idx] + ')' );
			p_labels.push( key );
			
			color_idx = (color_idx + 1) % colors.length;
		}
		
		var ctx = $("#c_arch_perf").get(0).getContext("2d");
		
		var perf_chart = new Chart(ctx, {
			type: 'pie',
			data: {
				datasets: [{
					data: p_data,
					backgroundColor: p_colors,
					label: ''
				}],
				labels: p_labels
			},
			options: {
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: false,
					position: 'right',
				},
				title: {
					display: false,
					text: ''
				},
				animation: {
					animateScale: true,
					animateRotate: true
				}
			}
		});
		
		var legend_html = '';
		legend_html += '<div class="pie-legend-container">';
		for (var idx = 0, len = perf_keys.length; idx < len; idx++) {
			legend_html += '<div class="pie-legend-item" style="background-color:' + p_colors[idx] + '">' + p_labels[idx] + '</div>';
		}
		legend_html += '</div>';
		
		var perf_legend = $('#d_arch_perf_legend');
		perf_legend.html( legend_html );
		
		
		this.charts.perf = perf_chart;
		
		// arch cpu pie
		var cpu_avg = 0;
		if (!job.cpu) job.cpu = {};
		if (job.cpu.total && job.cpu.count) {
			cpu_avg = short_float( job.cpu.total / job.cpu.count );
		}
		
		var jcm = 100;
		var ctx = $("#c_arch_cpu").get(0).getContext("2d");
		
		var cpu_chart = new Chart(ctx, {
			type: 'doughnut',
			data: {
				datasets: [{
					data: [
						Math.min(cpu_avg, jcm),
						jcm - Math.min(cpu_avg, jcm),
					],
					backgroundColor: [
						(cpu_avg < jcm*0.5) ? this.pie_colors.cool : 
							((cpu_avg < jcm*0.75) ? this.pie_colors.warm : this.pie_colors.hot),
						this.pie_colors.empty
					],
					label: ''
				}],
				labels: []
			},
			options: {
				events: [],
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: false,
					position: 'right',
				},
				title: {
					display: false,
					text: ''
				},
				animation: {
					animateScale: true,
					animateRotate: true
				}
			}
		});
		
		// arch cpu overlay
		var html = '';
		html += '<div class="pie-overlay-title">'+cpu_avg+'%</div>';
		html += '<div class="pie-overlay-subtitle">Average</div>';
		$('#d_arch_cpu_overlay').html( html );
		
		// arch cpu legend
		var html = '';
		
		html += '<div class="info_label">MIN</div>';
		html += '<div class="info_value">' + short_float(job.cpu.min || 0) + '%</div>';
		
		html += '<div class="info_label">PEAK</div>';
		html += '<div class="info_value">' + short_float(job.cpu.max || 0) + '%</div>';
		
		$('#d_arch_cpu_legend').html( html );
		
		this.charts.cpu = cpu_chart;
		
		// arch mem pie
		var mem_avg = 0;
		if (!job.mem) job.mem = {};
		if (job.mem.total && job.mem.count) {
			mem_avg = Math.floor( job.mem.total / job.mem.count );
		}
		
		var jmm = config.job_memory_max || 1073741824;
		var ctx = $("#c_arch_mem").get(0).getContext("2d");
		
		var mem_chart = new Chart(ctx, {
			type: 'doughnut',
			data: {
				datasets: [{
					data: [
						Math.min(mem_avg, jmm),
						jmm - Math.min(mem_avg, jmm),
					],
					backgroundColor: [
						(mem_avg < jmm*0.5) ? this.pie_colors.cool : 
							((mem_avg < jmm*0.75) ? this.pie_colors.warm : this.pie_colors.hot),
						this.pie_colors.empty
					],
					label: ''
				}],
				labels: []
			},
			options: {
				events: [],
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: false,
					position: 'right',
				},
				title: {
					display: false,
					text: ''
				},
				animation: {
					animateScale: true,
					animateRotate: true
				}
			}
		});
		
		// arch mem overlay
		var html = '';
		html += '<div class="pie-overlay-title">'+get_text_from_bytes(mem_avg, 10)+'</div>';
		html += '<div class="pie-overlay-subtitle">Average</div>';
		$('#d_arch_mem_overlay').html( html );
		
		// arch mem legend
		var html = '';
		
		html += '<div class="info_label">MIN</div>';
		html += '<div class="info_value">' + get_text_from_bytes(job.mem.min || 0, 1) + '</div>';
		
		html += '<div class="info_label">PEAK</div>';
		html += '<div class="info_value">' + get_text_from_bytes(job.mem.max || 0, 1) + '</div>';
		
		$('#d_arch_mem_legend').html( html );
		
		this.charts.mem = mem_chart;
	},
	
	do_download_log: function() {
		// download job log file
		var job = this.job;
		window.location = '/api/app/get_job_log?id=' + job.id + '&t=' + this.token + '&download=1';
	},
	
	do_view_inline_log: function() {
		// swap out job log size warning with IFRAME containing inline log
		var job = this.job;
		var html = '';
		
		var size = get_inner_window_size();
		var iheight = size.height - 100;
		html += '<iframe id="i_arch_job_log" style="width:100%; height:' + iheight + 'px; border:none;" frameborder="0" src="/api/app/get_job_log?id=' + job.id + '&t=' + this.token + '"></iframe>';
		
		$('#d_job_log_warning').html( html );
	},
	
	abort_job: function() {
		// abort job, after confirmation
		var job = this.find_job(this.args.id);
		
		app.confirm( '<span style="color:red">Abort Job</span>', "Are you sure you want to abort the current job?", "Abort", function(result) {
			if (result) {
				app.showProgress( 1.0, "Aborting job..." );
				app.api.post( 'app/abort_job', job, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Job '"+job.event_title+"' was aborted successfully.");
				} );
			}
		} );
	},
	
	check_watch_enabled: function(job) {
		// check if watch is enabled on current live job
		var watch_enabled = 0;
		var email = app.user.email.toLowerCase();
		if (email && job.notify_success && (job.notify_success.toLowerCase().indexOf(email) > -1)) watch_enabled++;
		if (email && job.notify_fail && (job.notify_fail.toLowerCase().indexOf(email) > -1)) watch_enabled++;
		return (watch_enabled == 2);
	},
	
	watch_add_me: function(job, key) {
		// add current user's e-mail to job property
		if (!job[key]) job[key] = '';
		var value = trim( job[key].replace(/\,\s*\,/g, ',').replace(/^\s*\,\s*/, '').replace(/\s*\,\s*$/, '') );
		var email = app.user.email.toLowerCase();
		var regexp = new RegExp( "\\b" + escape_regexp(email) + "\\b", "i" );
		
		if (!value.match(regexp)) {
			if (value) value += ', ';
			job[key] = value + app.user.email;
		}
	},
	
	watch_remove_me: function(job, key) {
		// remove current user's email from job property
		if (!job[key]) job[key] = '';
		var value = trim( job[key].replace(/\,\s*\,/g, ',').replace(/^\s*\,\s*/, '').replace(/\s*\,\s*$/, '') );
		var email = app.user.email.toLowerCase();
		var regexp = new RegExp( "\\b" + escape_regexp(email) + "\\b", "i" );
		
		value = value.replace( regexp, '' ).replace(/\,\s*\,/g, ',').replace(/^\s*\,\s*/, '').replace(/\s*\,\s*$/, '');
		job[key] = trim(value);
	},
	
	toggle_watch: function() {
		// toggle watch on/off on current live job
		var job = this.find_job(this.args.id);
		var watch_enabled = this.check_watch_enabled(job);
		
		if (!watch_enabled) {
			this.watch_add_me( job, 'notify_success' );
			this.watch_add_me( job, 'notify_fail' );
		}
		else {
			this.watch_remove_me( job, 'notify_success' );
			this.watch_remove_me( job, 'notify_fail' );
		}
		
		// update on server
		$('#s_watch_job > i').removeClass().addClass('fa fa-spin fa-spinner');
		
		app.api.post( 'app/update_job', { id: job.id, notify_success: job.notify_success, notify_fail: job.notify_fail }, function(resp) {
			watch_enabled = !watch_enabled;
			if (watch_enabled) {
				app.showMessage('success', "You will now be notified via e-mail when the job completes (success or fail).");
				$('#s_watch_job').css('color', '#3f7ed5');
				$('#s_watch_job > i').removeClass().addClass('fa fa-check-square-o');
			}
			else {
				app.showMessage('success', "You will no longer be notified about this job.");
				$('#s_watch_job').css('color', '#777');
				$('#s_watch_job > i').removeClass().addClass('fa fa-square-o');
			}
		} );
	},
	
	gosub_live: function(args) {
		// show live job status
		Debug.trace("Showing live job: " + args.id);
		var job = this.find_job(args.id);
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) - 300) / 4 );
		
		// locate objects
		var event = find_object( app.schedule, { id: job.event } ) || {};
		var cat = job.category ? find_object( app.categories, { id: job.category } ) : { title: 'n/a' };
		var group = event.target ? find_object( app.server_groups, { id: event.target } ) : null;
		var plugin = job.plugin ? find_object( app.plugins, { id: job.plugin } ) : { title: 'n/a' };
		
		if (group && event.multiplex) {
			group = copy_object(group);
			group.multiplex = 1;
		}
		
		// new header with watch & abort
		var watch_enabled = this.check_watch_enabled(job);
		
		html += '<div class="subtitle" style="margin-top:7px; margin-bottom:13px;">';
			html += 'Live Job Progress';
			html += '<div class="subtitle_widget" style="margin-left:2px;"><span class="link abort" onMouseUp="$P().abort_job()"><i class="fa fa-ban">&nbsp;</i><b>Abort Job</b></span></div>';
			html += '<div class="subtitle_widget"><span id="s_watch_job" class="link" onMouseUp="$P().toggle_watch()" style="' + (watch_enabled ? 'color:#3f7ed5;' : 'color:#777;') + '"><i class="fa ' + (watch_enabled ? 'fa-check-square-o' : 'fa-square-o') + '">&nbsp;</i><b>Watch Job</b></span></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		// fieldset header
		html += '<fieldset style="margin-top:0px; margin-right:0px; padding-top:10px; position:relative"><legend>Job Details</legend>';
			
			// html += '<div class="button mini" style="position:absolute; top:15px; left:100%; margin-left:-110px;" onMouseUp="$P().abort_job()">Abort Job...</div>';
			var nice_id = job.id;
			// Job labels originate in plugin output and must be treated as plain text.
			if (job.label) nice_id = encode_entities(job.label) + ' (' + job.id + ')';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">JOB ID</div>';
				html += '<div class="info_value">' + nice_id + '</div>';
				
				html += '<div class="info_label">EVENT NAME</div>';
				html += '<div class="info_value"><a href="#Schedule?sub=edit_event&id='+job.event+'">' + this.getNiceEvent(job.event_title, col_width) + '</a></div>';
				
				html += '<div class="info_label">EVENT TIMING</div>';
				html += '<div class="info_value">' + (event.enabled ? summarize_event_timing(event.timing, event.timezone) : '(Disabled)') + '</div>';
			html += '</div>';
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">CATEGORY NAME</div>';
				html += '<div class="info_value">' + this.getNiceCategory(cat, col_width) + '</div>';
				
				html += '<div class="info_label">PLUGIN NAME</div>';
				html += '<div class="info_value">' + this.getNicePlugin(plugin, col_width) + '</div>';
				
				html += '<div class="info_label">EVENT TARGET</div>';
				html += '<div class="info_value">' + this.getNiceGroup(group, event.target, col_width) + '</div>';
			html += '</div>';
			
			var nice_source = (job.source || 'Scheduler');
			if (nice_source.match(/Chain Reaction/) && job.source_job) {
				nice_source = '<a href="#JobDetails?id=' + job.source_job + '">' + nice_source + '</a>';
			}
			
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">JOB SOURCE</div>';
				html += '<div class="info_value"><div class="" style="">' + nice_source + '</div></div>';
				
				html += '<div class="info_label">SERVER HOSTNAME</div>';
				html += '<div class="info_value">' + this.getNiceGroup( null, job.hostname, col_width ) + '</div>';
				
				html += '<div class="info_label">PROCESS ID</div>';
				html += '<div class="info_value" id="d_live_pid">' + job.pid + '</div>';
			html += '</div>';
							
			html += '<div style="float:left; width:25%;">';
				html += '<div class="info_label">JOB STARTED</div>';
				html += '<div class="info_value">' + get_nice_date_time(job.time_start, false, true) + '</div>';
				
				html += '<div class="info_label">ELAPSED TIME</div>';
				var elapsed = Math.floor( Math.max( 0, app.epoch - job.time_start ) );
				html += '<div class="info_value" id="d_live_elapsed">' + get_text_from_seconds(elapsed, false, false) + '</div>';
				
				var progress = job.progress || 0;
				var nice_remain = 'n/a';
				if (job.pending && job.when) {
					nice_remain = 'Retry in '+get_text_from_seconds( Math.max(0, job.when - app.epoch), true, true )+'';
				}
				else if ((elapsed >= 10) && (progress > 0) && (progress < 1.0)) {
					var sec_remain = Math.floor(((1.0 - progress) * elapsed) / progress);
					nice_remain = get_text_from_seconds( sec_remain, false, true );
				}
				html += '<div class="info_label">REMAINING TIME</div>';
				html += '<div class="info_value" id="d_live_remain">' + nice_remain + '</div>';
			html += '</div>';
			
			html += '<div class="clear"></div>';
		html += '</fieldset>';
		
		// pies
		html += '<div style="position:relative; margin-top:15px;">';
			
			html += '<div class="pie-column column-left">';
				html += '<div id="d_live_progress_overlay" class="pie-overlay"></div>';
				html += '<div class="pie-title">Job Progress</div>';
				html += '<div id="d_graph_live_progress" style="position:relative; display:inline-block; width:250px; height:250px; overflow:hidden;"><canvas id="c_live_progress" class="pie"></canvas></div>';
				// html += '<canvas id="c_live_progress" width="250" height="250" class="pie"></canvas>';
				// html += '<div id="d_live_progress_legend" class="pie-legend-column"></div>';
			html += '</div>';
			
			html += '<div class="pie-column column-right">';
				html += '<div id="d_live_mem_overlay" class="pie-overlay"></div>';
				html += '<div class="pie-title">Memory Usage</div>';
				html += '<div id="d_graph_live_mem" style="position:relative; display:inline-block; width:250px; height:250px; overflow:hidden;"><canvas id="c_live_mem" class="pie"></canvas></div>';
				// html += '<canvas id="c_live_mem" width="250" height="250" class="pie"></canvas>';
				html += '<div id="d_live_mem_legend" class="pie-legend-column"></div>';
			html += '</div>';
			
			html += '<div class="pie-column column-center">';
				html += '<div id="d_live_cpu_overlay" class="pie-overlay"></div>';
				html += '<div class="pie-title">CPU Usage</div>';
				html += '<div id="d_graph_live_cpu" style="position:relative; display:inline-block; width:250px; height:250px; overflow:hidden;"><canvas id="c_live_cpu" class="pie"></canvas></div>';
				// html += '<canvas id="c_live_cpu" width="250" height="250" class="pie"></canvas>';
				html += '<div id="d_live_cpu_legend" class="pie-legend-column"></div>';
			html += '</div>';
			
		html += '</div>';
		
		html += '<div class="subtitle" style="margin-top:15px;">';
			html += 'Live Job Event Log';
			html += '<div class="subtitle_widget" id="d_live_job_view_link" style="margin-left:2px;"></div>';
			html += '<div class="subtitle_widget" id="d_live_job_download_link"></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var size = get_inner_window_size();
		var iheight = size.height - 100;
		html += '<div id="d_live_job_log" style="width:100%; height:'+iheight+'px; overflow-y:scroll; position:relative;"></div>';
		
		this.div.html( html );
		
		// open websocket for log tail stream
		this.start_live_log_watcher(job);
		
		// live progress pie
		if (!job.progress) job.progress = 0;
		var progress = Math.min(1, Math.max(0, job.progress));
		var prog_pct = short_float( progress * 100 );
		
		var ctx = $("#c_live_progress").get(0).getContext("2d");
		var progress_chart = new Chart(ctx, {
			type: 'doughnut',
			data: {
				datasets: [{
					data: [
						prog_pct,
						100 - prog_pct
					],
					backgroundColor: [
						this.pie_colors.progress,
						this.pie_colors.empty
					],
					label: ''
				}],
				labels: []
			},
			options: {
				events: [],
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: false,
					position: 'right',
				},
				title: {
					display: false,
					text: ''
				},
				animation: {
					animateScale: true,
					animateRotate: true
				}
			}
		});
		
		this.charts.progress = progress_chart;
		
		// live cpu pie
		if (!job.cpu) job.cpu = {};
		if (!job.cpu.current) job.cpu.current = 0;
		var cpu_cur = job.cpu.current;
		var cpu_avg = 0;
		if (job.cpu.total && job.cpu.count) {
			cpu_avg = short_float( job.cpu.total / job.cpu.count );
		}
		var jcm = 100;
		var ctx = $("#c_live_cpu").get(0).getContext("2d");
		var cpu_chart = new Chart(ctx, {
			type: 'doughnut',
			data: {
				datasets: [{
					data: [
						Math.min(cpu_cur, jcm),
						jcm - Math.min(cpu_cur, jcm),
					],
					backgroundColor: [
						(cpu_cur < jcm*0.5) ? this.pie_colors.cool : 
							((cpu_cur < jcm*0.75) ? this.pie_colors.warm : this.pie_colors.hot),
						this.pie_colors.empty
					],
					label: ''
				}],
				labels: []
			},
			options: {
				events: [],
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: false,
					position: 'right',
				},
				title: {
					display: false,
					text: ''
				},
				animation: {
					animateScale: true,
					animateRotate: true
				}
			}
		});
		
		this.charts.cpu = cpu_chart;
		
		// live mem pie
		if (!job.mem) job.mem = {};
		if (!job.mem.current) job.mem.current = 0;
		var mem_cur = job.mem.current;
		var mem_avg = 0;
		if (job.mem.total && job.mem.count) {
			mem_avg = short_float( job.mem.total / job.mem.count );
		}
		var jmm = config.job_memory_max || 1073741824;
		var ctx = $("#c_live_mem").get(0).getContext("2d");
		var mem_chart = new Chart(ctx, {
			type: 'doughnut',
			data: {
				datasets: [{
					data: [
						Math.min(mem_cur, jmm),
						jmm - Math.min(mem_cur, jmm),
					],
					backgroundColor: [
						(mem_cur < jmm*0.5) ? this.pie_colors.cool : 
							((mem_cur < jmm*0.75) ? this.pie_colors.warm : this.pie_colors.hot),
						this.pie_colors.empty
					],
					label: ''
				}],
				labels: []
			},
			options: {
				events: [],
				responsive: true,
				responsiveAnimationDuration: 0,
				maintainAspectRatio: false,
				legend: {
					display: false,
					position: 'right',
				},
				title: {
					display: false,
					text: ''
				},
				animation: {
					animateScale: true,
					animateRotate: true
				}
			}
		});
		
		this.charts.mem = mem_chart;
		
		// update dynamic data
		this.update_live_progress(job);
	},
	
	start_live_log_watcher: function(job) {
		// open special websocket to target server for live log feed
		var self = this;
		var $cont = null;
		var chunk_count = 0;
		var error_shown = false;
		
		var url = app.proto + job.hostname + ':' + app.port;
		if (config.custom_live_log_socket_url) {
			// custom websocket URL for single-master systems behind an LB
			url = config.custom_live_log_socket_url;
		}
		else if (!config.web_socket_use_hostnames && app.servers && app.servers[job.hostname] && app.servers[job.hostname].ip) {
			// use ip if available, may work better in some setups
			url = app.proto + app.servers[job.hostname].ip + ':' + app.port;
		}
		
		$('#d_live_job_log').append( 
			'<pre class="log_chunk" style="color:#888">Log Watcher: Connecting to server: ' + url + '...</pre>' 
		);
		
		this.socket = io( url, {
			forceNew: true,
			transports: config.socket_io_transports || ['websocket'],
			reconnection: true,
			reconnectionDelay: 1000,
			reconnectionDelayMax: 5000,
			reconnectionAttempts: 9999,
			timeout: 5000
		} );
		
		this.socket.on('connect', function() {
			Debug.trace("JobDetails socket.io connected successfully: " + url);
			
			// cache this for later
			$cont = $('#d_live_job_log');
			
			$cont.append( 
				'<pre class="log_chunk" style="color:#888; margin-bottom:14px;">Log Watcher: Connected successfully!</pre>' 
			);
			
			// get auth token from master server (uses session)
			app.api.post( 'app/get_log_watch_auth', { id: job.id }, function(resp) {
				// now request log watch stream on target server
				self.socket.emit( 'watch_job_log', {
					token: resp.token,
					id: job.id
				} );
				
				self.setup_live_log_links(job, resp.token);
			}); // api.post
		} );
		this.socket.on('connect_error', function(err) {
			Debug.trace("JobDetails socket.io connect error: " + err);
			$('#d_live_job_log').append( 
				'<pre class="log_chunk">Log Watcher: Server Connect Error: ' + err + ' (' + url + ')</pre>' 
			);
			error_shown = true;
		} );
		this.socket.on('connect_timeout', function(err) {
			Debug.trace("JobDetails socket.io connect timeout");
			if (!error_shown) $('#d_live_job_log').append( 
				'<pre class="log_chunk">Log Watcher: Server Connect Timeout: ' + err + ' (' + url + ')</pre>' 
			);
		} );
		this.socket.on('reconnect', function() {
			Debug.trace("JobDetails socket.io reconnected successfully");
		} );
		
		this.socket.on('log_data', function(lines) {
			// received log data, as array of lines
			var scroll_y = $cont.scrollTop();
			var scroll_max = Math.max(0, $cont.prop('scrollHeight') - $cont.height());
			var need_scroll = ((scroll_max - scroll_y) <= 10);
			
			$cont.append( 
				'<pre class="log_chunk">' + 
					lines.map( function(line) { return line.replace(/</g, '&lt;'); } ).join("\n").trim() + 
				'</pre>' 
			);
			
			// only show newest 1K chunks
			chunk_count++;
			if (chunk_count >= 1000) {
				$cont.children().first().remove();
				chunk_count--;
			}
			
			if (need_scroll) $cont.scrollTop( $cont.prop('scrollHeight') );
		} );
	},
	
	update_live_progress: function(job) {
		// update job progress, elapsed time, time remaining, cpu pie, mem pie
		if (job.complete && !app.progress) app.showProgress( 1.0, "Job is finishing..." );
		
		// pid may have changed (retry)
		$('#d_live_pid').html( job.pid || 'n/a' );
		
		// elapsed time
		var elapsed = Math.floor( Math.max( 0, app.epoch - job.time_start ) );
		$('#d_live_elapsed').html( get_text_from_seconds(elapsed, false, false) );
		
		// remaining time
		var progress = job.progress || 0;
		var nice_remain = 'n/a';
		if (job.pending && job.when) {
			nice_remain = 'Retry in '+get_text_from_seconds( Math.max(0, job.when - app.epoch), true, true )+'';
		}
		else if ((elapsed >= 10) && (progress > 0) && (progress < 1.0)) {
			var sec_remain = Math.floor(((1.0 - progress) * elapsed) / progress);
			nice_remain = get_text_from_seconds( sec_remain, false, true );
		}
		$('#d_live_remain').html( nice_remain );
		
		// progress pie
		if (!job.progress) job.progress = 0;
		var progress = Math.min(1, Math.max(0, job.progress));
		var prog_pct = short_float( progress * 100 );
		
		if (prog_pct != this.charts.progress.__cronicle_prog_pct) {
			this.charts.progress.__cronicle_prog_pct = prog_pct;
			this.charts.progress.config.data.datasets[0].data[0] = prog_pct;
			this.charts.progress.config.data.datasets[0].data[1] = 100 - prog_pct;
			this.charts.progress.update();
		}
		
		// progress overlay
		var html = '';
		html += '<div class="pie-overlay-title">'+Math.floor(prog_pct)+'%</div>';
		html += '<div class="pie-overlay-subtitle">Current</div>';
		$('#d_live_progress_overlay').html( html );
		
		// cpu pie
		if (!job.cpu) job.cpu = {};
		if (!job.cpu.current) job.cpu.current = 0;
		var cpu_cur = job.cpu.current;
		var cpu_avg = 0;
		if (job.cpu.total && job.cpu.count) {
			cpu_avg = short_float( job.cpu.total / job.cpu.count );
		}
		
		var jcm = 100;
		if (cpu_cur != this.charts.cpu.__cronicle_cpu_cur) {
			this.charts.cpu.__cronicle_cpu_cur = cpu_cur;
			
			this.charts.cpu.config.data.datasets[0].data[0] = Math.min(cpu_cur, jcm);
			this.charts.cpu.config.data.datasets[0].data[1] = jcm - Math.min(cpu_cur, jcm);
			
			this.charts.cpu.config.data.datasets[0].backgroundColor[0] = (cpu_cur < jcm*0.5) ? this.pie_colors.cool : ((cpu_cur < jcm*0.75) ? this.pie_colors.warm : this.pie_colors.hot);
			
			this.charts.cpu.update();
		}
		
		// live cpu overlay
		var html = '';
		html += '<div class="pie-overlay-title">' + short_float(cpu_cur) + '%</div>';
		html += '<div class="pie-overlay-subtitle">Current</div>';
		$('#d_live_cpu_overlay').html( html );
		
		// live cpu legend
		var html = '';
		
		html += '<div class="info_label">MIN</div>';
		html += '<div class="info_value">' + short_float(job.cpu.min || 0) + '%</div>';
		
		html += '<div class="info_label">AVERAGE</div>';
		html += '<div class="info_value">' + (cpu_avg || 0) + '%</div>';
		
		html += '<div class="info_label">PEAK</div>';
		html += '<div class="info_value">' + short_float(job.cpu.max || 0) + '%</div>';
		
		$('#d_live_cpu_legend').html( html );
		
		// mem pie
		if (!job.mem) job.mem = {};
		if (!job.mem.current) job.mem.current = 0;
		var mem_cur = job.mem.current;
		var mem_avg = 0;
		if (job.mem.total && job.mem.count) {
			mem_avg = short_float( job.mem.total / job.mem.count );
		}
		
		var jmm = config.job_memory_max || 1073741824;
		if (mem_cur != this.charts.mem.__cronicle_mem_cur) {
			this.charts.mem.__cronicle_mem_cur = mem_cur;
			
			this.charts.mem.config.data.datasets[0].data[0] = Math.min(mem_cur, jmm);
			this.charts.mem.config.data.datasets[0].data[1] = jmm - Math.min(mem_cur, jmm);
			
			this.charts.mem.config.data.datasets[0].backgroundColor[0] = (mem_cur < jmm*0.5) ? this.pie_colors.cool : ((mem_cur < jmm*0.75) ? this.pie_colors.warm : this.pie_colors.hot);
			
			this.charts.mem.update();
		}
		
		// live mem overlay
		var html = '';
		html += '<div class="pie-overlay-title">'+get_text_from_bytes(mem_cur, 10)+'</div>';
		html += '<div class="pie-overlay-subtitle">Current</div>';
		$('#d_live_mem_overlay').html( html );
		
		// live mem legend
		var html = '';
		
		html += '<div class="info_label">MIN</div>';
		html += '<div class="info_value">' + get_text_from_bytes(job.mem.min || 0, 1) + '</div>';
		
		html += '<div class="info_label">AVERAGE</div>';
		html += '<div class="info_value">' + get_text_from_bytes(mem_avg || 0, 1) + '</div>';
		
		html += '<div class="info_label">PEAK</div>';
		html += '<div class="info_value">' + get_text_from_bytes(job.mem.max || 0, 1) + '</div>';
		
		$('#d_live_mem_legend').html( html );
	},
	
	setup_live_log_links: function(job, token) {
		// now that we have the token, we can add the live log view / downlaod links
		var remote_api_url = app.proto + job.hostname + ':' + app.port + config.base_api_uri;
		if (config.custom_live_log_socket_url) {
			// custom websocket URL for single-master systems behind an LB
			remote_api_url = config.custom_live_log_socket_url + config.base_api_uri;
		}
		else if (!config.web_socket_use_hostnames && app.servers && app.servers[job.hostname] && app.servers[job.hostname].ip) {
			// use ip if available, may work better in some setups
			remote_api_url = app.proto + app.servers[job.hostname].ip + ':' + app.port + config.base_api_uri;
		}
		
		$('#d_live_job_view_link').html( 
			'<a href="' + remote_api_url + '/app/get_live_job_log?id=' + job.id + '&t=' + token + '" target="_blank"><i class="fa fa-external-link">&nbsp;</i><b>View Full Log</b></a>' 
		);
		$('#d_live_job_download_link').html( 
			'<a href="' + remote_api_url + '/app/get_live_job_log?id=' + job.id + '&t=' + token + '&download=1"><i class="fa fa-download">&nbsp;</i><b>Download Log</b></a>' 
		);
	},
	
	jump_to_archive_when_ready: function() {
		// make sure archive view is ready (job log may still be uploading)
		var self = this;
		if (!this.active) return; // user navigated away from page
		
		app.api.post( 'app/get_job_details', { id: this.args.id, need_log: 1 }, 
			function(resp) {
				// got it, ready to switch
				app.hideProgress();
				Nav.refresh();
			},
			function(err) {
				// job not complete yet
				if (!app.progress) app.showProgress( 1.0, "Job is finishing..." );
				// self.jump_timer = setTimeout( self.jump_to_archive_when_ready.bind(self), 1000 );
			}
		);
	},
	
	find_job: function(id) {
		// locate active or pending (retry delay) job
		if (!id) id = this.args.id;
		var job = app.activeJobs[id];
		
		if (!job) {
			for (var key in app.activeJobs) {
				var temp_job = app.activeJobs[key];
				if (temp_job.pending && (temp_job.id == id)) {
					job = temp_job;
					break;
				}
			}
		}
		
		return job;
	},
	
	onStatusUpdate: function(data) {
		// received status update (websocket), update sub-page if needed
		if (this.args && (this.args.sub == 'live')) {
			if (!app.activeJobs[this.args.id]) {
				// check for pending job (retry delay)
				var pending_job = null;
				for (var key in app.activeJobs) {
					var job = app.activeJobs[key];
					if (job.pending && (job.id == this.args.id)) {
						pending_job = job;
						break;
					}
				}
				
				if (pending_job) {
					// job switched to pending (retry delay)
					if (app.progress) app.hideProgress();
					this.update_live_progress( pending_job );
				}
				else {
					// the live job we were watching just completed, jump to archive view
					this.jump_to_archive_when_ready();
				}
			}
			else {
				// job is still active
				this.update_live_progress(app.activeJobs[this.args.id]);
			}
		}
	},
	
	onResize: function(size) {
		// window was resized
		var iheight = size.height - 110;
		if (this.args.sub == 'live') {
			$('#d_live_job_log').css( 'height', '' + iheight + 'px' );
		}
		else {
			$('#i_arch_job_log').css( 'height', '' + iheight + 'px' );
		}
	},
	
	onResizeDelay: function(size) {
		// called 250ms after latest window resize
		// so we can run more expensive redraw operations
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		for (var key in this.charts) {
			this.charts[key].destroy();
		}
		if (this.jump_timer) {
			clearTimeout( this.jump_timer );
			delete this.jump_timer;
		}
		if (this.socket) {
			this.socket.disconnect();
			delete this.socket;
		}
		this.charts = {};
		this.div.html( '' );
		// this.tab.hide();
		return true;
	}
	
});

Class.subclass( Page.Base, "Page.MyAccount", {	
		
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		
		if (!args) args = {};
		this.args = args;
		
		app.setWindowTitle('My Account');
		app.showTabBar(true);
		
		this.receive_user({ user: app.user });
		
		return true;
	},
	
	receive_user: function(resp, tx) {
		var self = this;
		var html = '';
		var user = resp.user;
				
		html += '<div style="padding:50px 20px 50px 20px">';
		html += '<center>';
		
		html += '<table><tr>';
			html += '<td valign="top" style="vertical-align:top">';
			
		html += '<table style="margin:0;">';
		
		// user id
		html += get_form_table_row( 'Username', '<div style="font-size: 14px;"><b>' + app.username + '</b></div>' );
		html += get_form_table_caption( "Your username cannot be changed." );
		html += get_form_table_spacer();
		
		// full name
		html += get_form_table_row( 'Full Name', '<input type="text" id="fe_ma_fullname" size="30" value="'+escape_text_field_value(user.full_name)+'"/>' );
		html += get_form_table_caption( "Your first and last names, used for display purposes only.");
		html += get_form_table_spacer();
		
		// email
		html += get_form_table_row( 'Email Address', '<input type="text" id="fe_ma_email" size="30" value="'+escape_text_field_value(user.email)+'"/>' );
		html += get_form_table_caption( "This is used to generate your profile pic, and to<br/>recover your password if you forget it." );
		html += get_form_table_spacer();
		
		// current password
		html += get_form_table_row( 'Current Password', '<input type="' + app.get_password_type() + '" id="fe_ma_old_password" size="30" value="" spellcheck="false"/>' + app.get_password_toggle_html() );
		html += get_form_table_caption( "Enter your current account password to make changes." );
		html += get_form_table_spacer();
		
		// reset password
		html += get_form_table_row( 'New Password', '<input type="' + app.get_password_type() + '" id="fe_ma_new_password" size="30" value="" spellcheck="false"/>' + app.get_password_toggle_html() );
		html += get_form_table_caption( "If you need to change your password, enter the new one here." );
		html += get_form_table_spacer();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_account_dialog()">Delete Account...</div></td>';
				html += '<td width="80">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().save_changes()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		
		html += '</td>';
			html += '<td valign="top" align="left" style="vertical-align:top; text-align:left;">';
				// gravar profile image and edit button
				html += '<fieldset style="width:150px; margin-left:40px; background:white; border:1px solid #ddd; box-shadow:none;"><legend>Profile Picture</legend>';
				if (app.config.external_users) {
					html += '<div id="d_ma_image" style="width:128px; height:128px; margin:5px auto 0 auto; background-image:url('+app.getUserAvatarURL(128)+'); cursor:default;"></div>';
				}
				else {
					html += '<div id="d_ma_image" style="width:128px; height:128px; margin:5px auto 0 auto; background-image:url('+app.getUserAvatarURL(128)+'); cursor:pointer;" onMouseUp="$P().edit_gravatar()"></div>';
					html += '<div class="button mini" style="margin:10px auto 5px auto;" onMouseUp="$P().edit_gravatar()">Edit Image...</div>';
					html += '<div style="font-size:11px; color:#888; text-align:center; margin-bottom:5px;">Image services provided by <a href="https://en.gravatar.com/connect/" target="_blank">Gravatar.com</a>.</div>';
				}
				html += '</fieldset>';
			html += '</td>';
		html += '</tr></table>';
		
		html += '</div>'; // table wrapper div
				
		this.div.html( html );
		
		setTimeout( function() {
			app.password_strengthify( '#fe_ma_new_password' );
			
			if (app.config.external_users) {
				app.showMessage('warning', "Users are managed by an external system, so you cannot make changes here.");
				self.div.find('input').prop('disabled', true);
			}
		}, 1 );
	},
	
	edit_gravatar: function() {
		// edit profile pic at gravatar.com
		window.open( 'https://en.gravatar.com/connect/' );
	},
	
	save_changes: function(force) {
		// save changes to user info
		app.clearError();
		if (app.config.external_users) {
			return app.doError("Users are managed by an external system, so you cannot make changes here.");
		}
		if (!$('#fe_ma_old_password').val()) return app.badField('#fe_ma_old_password', "Please enter your current account password to make changes.");
		
		if ($('#fe_ma_new_password').val() && !force && (app.last_password_strength.score < 3)) {
			app.confirm( '<span style="color:red">Insecure Password Warning</span>', app.get_password_warning(), "Proceed", function(result) {
				if (result) $P().save_changes('force');
			} );
			return;
		} // insecure password
		
		app.showProgress( 1.0, "Saving account..." );
		
		app.api.post( 'user/update', {
			username: app.username,
			full_name: trim($('#fe_ma_fullname').val()),
			email: trim($('#fe_ma_email').val()),
			old_password: $('#fe_ma_old_password').val(),
			new_password: $('#fe_ma_new_password').val()
		}, 
		function(resp) {
			// save complete
			app.hideProgress();
			app.showMessage('success', "Your account settings were updated successfully.");
			
			$('#fe_ma_old_password').val('');
			$('#fe_ma_new_password').val('');
			
			app.user = resp.user;
			app.updateHeaderInfo();
			
			$('#d_ma_image').css( 'background-image', 'url('+app.getUserAvatarURL(128)+')' );
		} );
	},
	
	show_delete_account_dialog: function() {
		// show dialog confirming account delete action
		var self = this;
		
		app.clearError();
		if (app.config.external_users) {
			return app.doError("Users are managed by an external system, so you cannot make changes here.");
		}
		if (!$('#fe_ma_old_password').val()) return app.badField('#fe_ma_old_password', "Please enter your current account password.");
		
		app.confirm( "Delete My Account", "Are you sure you want to <b>permanently delete</b> your user account?  There is no way to undo this action, and no way to recover your data.", "Delete", function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Account..." );
				app.api.post( 'user/delete', {
					username: app.username,
					password: $('#fe_ma_old_password').val()
				}, 
				function(resp) {
					// finished deleting, immediately log user out
					app.doUserLogout();
				} );
			}
		} );
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		// this.div.html( '' );
		return true;
	}
	
} );

Class.subclass( Page.Base, "Page.Admin", {	
	
	usernames: null,
	default_sub: 'activity',
	
	onInit: function() {
		// called once at page load
		var html = '';
		this.div.html( html );
	},
	
	onActivate: function(args) {
		// page activation
		if (!this.requireLogin(args)) return true;
		if (!app.isAdmin()) {
			setTimeout( function() { Nav.go('Home'); }, 1 );
			return true;
		}
		
		if (!args) args = {};
		if (!args.sub) args.sub = this.default_sub;
		this.args = args;
		
		app.showTabBar(true);
		this.tab[0]._page_id = Nav.currentAnchor();
		
		this.div.addClass('loading');
		this['gosub_'+args.sub](args);
		
		return true;
	},
	
	onDataUpdate: function(key, value) {
		// recieved data update (websocket), see if sub-page cares about it
		switch (key) {
			case 'users':
				if (this.args.sub == 'users') this.gosub_users(this.args);
			break;
			
			case 'categories':
				if (this.args.sub == 'categories') this.gosub_categories(this.args);
			break;
			
			case 'server_groups':
			case 'servers':
			case 'nearby':
				if (this.args.sub == 'servers') this.gosub_servers(this.args);
			break;
			
			case 'plugins':
				if (this.args.sub == 'plugins') this.gosub_plugins(this.args);
			break;
			
			case 'state':
			case 'schedule':
				if (this.args.sub == 'servers') this.gosub_servers(this.args);
			break;
			
			case 'api_keys':
				if (this.args.sub == 'api_keys') this.gosub_api_keys(this.args);
			break;
		}
	},
	
	onStatusUpdate: function(data) {
		// received status update (websocket), update sub-page if needed
		if (data.jobs_changed && (this.args.sub == 'servers')) this.gosub_servers(this.args);
		if (data.servers_changed && (this.args.sub == 'servers')) this.gosub_servers(this.args);
	},
	
	onResizeDelay: function(size) {
		// called 250ms after latest window resize
		// so we can run more expensive redraw operations
		switch (this.args.sub) {
			case 'users': 
				if (this.lastUsersResp) {
					this.receive_users(this.lastUsersResp); 
				}
			break;
			case 'categories': 
				this.gosub_categories(this.args); 
			break;
			case 'servers': 
				this.gosub_servers(this.args); 
			break;
			case 'plugins': 
				this.gosub_plugins(this.args); 
			break;
			case 'api_keys':
				if (this.lastAPIKeysResp) {
					this.receive_keys( this.lastAPIKeysResp );
				}
			break;
			case 'activity':
				if (this.lastActivityResp) {
					this.receive_activity( this.lastActivityResp );
				}
			break;
		}
	},
	
	onDeactivate: function() {
		// called when page is deactivated
		// this.div.html( '' );
		return true;
	}
	
} );

// Cronicle Admin Page -- Categories

Class.add( Page.Admin, {
	
	gosub_categories: function(args) {
		// show category list
		this.div.removeClass('loading');
		app.setWindowTitle( "Categories" );
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 5 );
		
		var html = '';
		
		html += this.getSidebarTabs( 'categories',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		var cols = ['Title', 'Description', 'Assigned Events', 'Max Concurrent', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Event Categories';
			// html += '<div class="clear"></div>';
		html += '</div>';
		
		// sort by title ascending
		this.categories = app.categories.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		// render table
		var self = this;
		html += this.getBasicTable( this.categories, cols, 'category', function(cat, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_category('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_category('+idx+')"><b>Delete</b></span>'
			];
			
			var cat_events = find_objects( app.schedule, { category: cat.id } );
			var num_events = cat_events.length;
			
			var tds = [
				'<div class="td_big"><span class="link" onMouseUp="$P().edit_category('+idx+')">' + self.getNiceCategory(cat, col_width) + '</span></div>',
				'<div class="ellip" style="max-width:'+col_width+'px;">' + encode_entities(cat.description || '(No description)') + '</div>',
				num_events ? commify( num_events ) : '(None)',
				cat.max_children ? commify(cat.max_children) : '(No limit)',
				actions.join(' | ')
			];
			
			if (cat && cat.color) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += cat.color;
			}
			
			if (!cat.enabled) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += 'disabled';
			}
			
			return tds;
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_category(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Category...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	edit_category: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_category&id=' + this.categories[idx].id );
		else Nav.go( '#Admin?sub=new_category' );
	},
	
	delete_category: function(idx) {
		// delete key from search results
		this.category = this.categories[idx];
		this.show_delete_category_dialog();
	},
	
	gosub_new_category: function(args) {
		// create new Category
		var html = '';
		app.setWindowTitle( "New Category" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_category',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['new_category', "New Category"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Add New Category</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.category = {
			title: "",
			description: "",
			max_children: 0,
			enabled: 1
		};
		
		html += this.get_category_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_category_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_category()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Category</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ec_title').focus();
		}, 1 );
	},
	
	cancel_category_edit: function() {
		// cancel editing category and return to list
		Nav.go( 'Admin?sub=categories' );
	},
	
	do_new_category: function(force) {
		// create new category
		app.clearError();
		var category = this.get_category_form_json();
		if (!category) return; // error
		
		// pro-tip: embed id in title as bracketed prefix
		if (category.title.match(/^\[(\w+)\]\s*(.+)$/)) {
			category.id = RegExp.$1;
			category.title = RegExp.$2;
		}
		
		this.category = category;
		
		app.showProgress( 1.0, "Creating category..." );
		app.api.post( 'app/create_category', category, this.new_category_finish.bind(this) );
	},
	
	new_category_finish: function(resp) {
		// new Category created successfully
		app.hideProgress();
		
		// Can't nav to edit_category yet, websocket may not have received update yet
		// Nav.go('Admin?sub=edit_category&id=' + resp.id);
		Nav.go('Admin?sub=categories');
		
		setTimeout( function() {
			app.showMessage('success', "The new category was created successfully.");
		}, 150 );
	},
	
	gosub_edit_category: function(args) {
		// edit existing Category
		var html = '';
		this.category = find_object( app.categories, { id: args.id } );
		
		app.setWindowTitle( "Editing Category \"" + (this.category.title) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_category',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['edit_category', "Edit Category"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing Category &ldquo;' + (this.category.title) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_category_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_category_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_category_dialog()">Delete Category...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_category()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_save_category: function() {
		// save changes to category
		app.clearError();
		var category = this.get_category_form_json();
		if (!category) return; // error
		
		this.category = category;
		
		app.showProgress( 1.0, "Saving category..." );
		app.api.post( 'app/update_category', category, this.save_category_finish.bind(this) );
	},
	
	save_category_finish: function(resp, tx) {
		// new category saved successfully
		var self = this;
		var category = this.category;
		
		app.hideProgress();
		app.showMessage('success', "The category was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// copy active jobs to array
		var jobs = [];
		for (var id in app.activeJobs) {
			var job = app.activeJobs[id];
			if ((job.category == category.id) && !job.detached) jobs.push( job );
		}
		
		// if the cat was disabled and there are running jobs, ask user to abort them
		if (!category.enabled && jobs.length) {
			app.confirm( '<span style="color:red">Abort Jobs</span>', "There " + ((jobs.length != 1) ? 'are' : 'is') + " currently still " + jobs.length + " active " + pluralize('job', jobs.length) + " using the disabled category <b>"+category.title+"</b>.  Do you want to abort " + ((jobs.length != 1) ? 'these' : 'it') + " now?", "Abort", function(result) {
				if (result) {
					app.showProgress( 1.0, "Aborting " + pluralize('Job', jobs.length) + "..." );
					app.api.post( 'app/abort_jobs', { category: category.id }, function(resp) {
						app.hideProgress();
						if (resp.count > 0) {
							app.showMessage('success', "The " + pluralize('job', resp.count) + " " + ((resp.count != 1) ? 'were' : 'was') + " aborted successfully.");
						}
						else {
							app.showMessage('warning', "No jobs were aborted.  It is likely they completed while the dialog was up.");
						}
					} );
				} // clicked Abort
			} ); // app.confirm
		} // disabled + jobs
	},
	
	show_delete_category_dialog: function() {
		// show dialog confirming category delete action
		var self = this;
		var category = this.category;
		var cat = this.category;
		
		// check for events first
		var cat_events = find_objects( app.schedule, { category: cat.id } );
		var num_events = cat_events.length;
		if (num_events) return app.doError("Sorry, you cannot delete a category that has events assigned to it.");
		
		// proceed with delete
		var self = this;
		app.confirm( '<span style="color:red">Delete Category</span>', "Are you sure you want to delete the category <b>"+cat.title+"</b>?  There is no way to undo this action.", "Delete", function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Category..." );
				app.api.post( 'app/delete_category', cat, self.delete_category_finish.bind(self) );
			}
		} );
	},
	
	delete_category_finish: function(resp, tx) {
		// finished deleting category
		var self = this;
		app.hideProgress();
		
		Nav.go('Admin?sub=categories', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The category '"+self.category.title+"' was deleted successfully.");
		}, 150 );
	},
	
	get_category_edit_html: function() {
		// get html for editing a category (or creating a new one)
		var html = '';
		var category = this.category;
		var cat = this.category;
		
		// Internal ID
		if (cat.id && this.isAdmin()) {
			html += get_form_table_row( 'Category ID', '<div style="font-size:14px;">' + cat.id + '</div>' );
			html += get_form_table_caption( "The internal Category ID used for API calls.  This cannot be changed." );
			html += get_form_table_spacer();
		}
		
		// title
		html += get_form_table_row('Category Title:', '<input type="text" id="fe_ec_title" size="25" value="'+escape_text_field_value(cat.title)+'"/>') + 
			get_form_table_caption("Enter a title for the category, short and sweet.") + 
			get_form_table_spacer();
		
		// cat enabled
		html += get_form_table_row( 'Active', '<input type="checkbox" id="fe_ec_enabled" value="1" ' + (cat.enabled ? 'checked="checked"' : '') + '/><label for="fe_ec_enabled">Category Enabled</label>' );
		html += get_form_table_caption( "Select whether events in this category should be enabled or disabled in the schedule." );
		html += get_form_table_spacer();
		
		// description
		html += get_form_table_row('Description:', '<textarea id="fe_ec_desc" style="width:500px; height:50px; resize:vertical;">'+escape_text_field_value(cat.description)+'</textarea>') + 
			get_form_table_caption("Optionally enter a description for the category.") + 
			get_form_table_spacer();
		
		// max concurrent
		html += get_form_table_row('Max Concurrent:', '<select id="fe_ec_max_children">' + render_menu_options([ [0,'No Limit'], 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 ], cat.max_children, true) + '</select>') + 
			get_form_table_caption("Select the maximum number of jobs allowed to run concurrently in this category.");
		html += get_form_table_spacer();
		
		// color
		var current_color = cat.color || 'plain';
		var swatch_html = '';
		var colors = ['plain', 'red', 'green', 'blue', 'skyblue', 'yellow', 'purple', 'orange'];
		for (var idx = 0, len = colors.length; idx < len; idx++) {
			var color = colors[idx];
			swatch_html += '<div class="swatch ' + color + ' ' + ((current_color == color) ? 'active' : '') + '" onMouseUp="$P().select_color(\''+color+'\')"></div>';
		}
		swatch_html += '<div class="clear"></div>';
		
		html += get_form_table_row( 'Highlight Color', swatch_html );
		html += get_form_table_caption( "Optionally select a highlight color for the category, which will show on the schedule." );
		html += get_form_table_spacer();
		
		// default notification options
		var notif_expanded = !!(cat.notify_success || cat.notify_fail || cat.web_hook);
		html += get_form_table_row( 'Notification', 
			'<div style="font-size:13px;'+(notif_expanded ? 'display:none;' : '')+'"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Default Notification Options</span></div>' + 
			'<fieldset style="padding:10px 10px 0 10px; margin-bottom:5px;'+(notif_expanded ? '' : 'display:none;')+'"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Default Notification Options</legend>' + 
				'<div class="plugin_params_label">Default Email on Success:</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ec_notify_success" size="50" value="'+escape_text_field_value(cat.notify_success)+'" placeholder="email@sample.com" spellcheck="false" onChange="$P().update_add_remove_me($(this))"/><span class="link addme" onMouseUp="$P().add_remove_me($(this).prev())"></span></div>' + 
				
				'<div class="plugin_params_label">Default Email on Failure:</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ec_notify_fail" size="50" value="'+escape_text_field_value(cat.notify_fail)+'" placeholder="email@sample.com" spellcheck="false" onChange="$P().update_add_remove_me($(this))"/><span class="link addme" onMouseUp="$P().add_remove_me($(this).prev())"></span></div>' + 
				
				'<div class="plugin_params_label">Default Web Hook URL:</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ec_web_hook" size="60" value="'+escape_text_field_value(cat.web_hook)+'" placeholder="http://" spellcheck="false"/></div>' + 
			'</fieldset>'
		);
		html += get_form_table_caption( "Optionally enter default e-mail addresses for notification, and/or a web hook URL.<br/>Note that events can override any of these notification settings." );
		html += get_form_table_spacer();
		
		// default resource limits
		var res_expanded = !!(cat.memory_limit || cat.memory_sustain || cat.cpu_limit || cat.cpu_sustain || cat.log_max_size);
		html += get_form_table_row( 'Limits', 
			'<div style="font-size:13px;'+(res_expanded ? 'display:none;' : '')+'"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Default Resource Limits</span></div>' + 
			'<fieldset style="padding:10px 10px 0 10px; margin-bottom:5px;'+(res_expanded ? '' : 'display:none;')+'"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Default Resource Limits</legend>' + 
				
				'<div class="plugin_params_label">Default CPU Limit:</div>' + 
				'<div class="plugin_params_content"><table cellspacing="0" cellpadding="0" class="fieldset_params_table"><tr>' + 
					'<td style="padding-right:2px"><input type="checkbox" id="fe_ec_cpu_enabled" value="1" '+(cat.cpu_limit ? 'checked="checked"' : '')+' /></td>' + 
					'<td><label for="fe_ec_cpu_enabled">Abort job if CPU exceeds</label></td>' + 
					'<td><input type="text" id="fe_ec_cpu_limit" style="width:30px;" value="'+(cat.cpu_limit || 0)+'"/>%</td>' + 
					'<td>for</td>' + 
					'<td>' + this.get_relative_time_combo_box( 'fe_ec_cpu_sustain', cat.cpu_sustain, 'fieldset_params_table' ) + '</td>' + 
				'</tr></table></div>' + 
				
				'<div class="plugin_params_label">Default Memory Limit:</div>' + 
				'<div class="plugin_params_content"><table cellspacing="0" cellpadding="0" class="fieldset_params_table"><tr>' + 
					'<td style="padding-right:2px"><input type="checkbox" id="fe_ec_memory_enabled" value="1" '+(cat.memory_limit ? 'checked="checked"' : '')+' /></td>' + 
					'<td><label for="fe_ec_memory_enabled">Abort job if memory exceeds</label></td>' + 
					'<td>' + this.get_relative_size_combo_box( 'fe_ec_memory_limit', cat.memory_limit, 'fieldset_params_table' ) + '</td>' + 
					'<td>for</td>' + 
					'<td>' + this.get_relative_time_combo_box( 'fe_ec_memory_sustain', cat.memory_sustain, 'fieldset_params_table' ) + '</td>' + 
				'</tr></table></div>' + 
				
				'<div class="plugin_params_label">Default Log Size Limit:</div>' + 
				'<div class="plugin_params_content"><table cellspacing="0" cellpadding="0" class="fieldset_params_table"><tr>' + 
					'<td style="padding-right:2px"><input type="checkbox" id="fe_ec_log_enabled" value="1" '+(cat.log_max_size ? 'checked="checked"' : '')+' /></td>' + 
					'<td><label for="fe_ec_log_enabled">Abort job if log file exceeds</label></td>' + 
					'<td>' + this.get_relative_size_combo_box( 'fe_ec_log_limit', cat.log_max_size, 'fieldset_params_table' ) + '</td>' + 
				'</tr></table></div>' + 
				
			'</fieldset>'
		);
		html += get_form_table_caption( 
			"Optionally set default CPU load, memory usage and log size limits for the category.<br/>Note that events can override any of these limits."
		);
		html += get_form_table_spacer();
		
		setTimeout( function() {
			$P().update_add_remove_me( $('#fe_ec_notify_success, #fe_ec_notify_fail') );
		}, 1 );
		
		return html;
	},
	
	select_color: function(color) {
		// click on a color swatch
		this.category.color = (color == 'plain') ? '' : color;
		$('.swatch').removeClass('active');
		$('.swatch.'+color).addClass('active');
	},
	
	get_category_form_json: function() {
		// get category elements from form, used for new or edit
		var category = this.category;
		
		category.title = $('#fe_ec_title').val();
		if (!category.title.length) {
			return app.badField('#fe_ec_title', "Please enter a title for the category.");
		}
		
		category.enabled = $('#fe_ec_enabled').is(':checked') ? 1 : 0;
		category.description = $('#fe_ec_desc').val();
		category.max_children = parseInt( $('#fe_ec_max_children').val() );
		category.notify_success = $('#fe_ec_notify_success').val();
		category.notify_fail = $('#fe_ec_notify_fail').val();
		category.web_hook = $('#fe_ec_web_hook').val();
		
		// cpu limit
		if ($('#fe_ec_cpu_enabled').is(':checked')) {
			category.cpu_limit = parseInt( $('#fe_ec_cpu_limit').val() );
			if (isNaN(category.cpu_limit)) return app.badField('fe_ec_cpu_limit', "Please enter an integer value for the CPU limit.");
			if (category.cpu_limit < 0) return app.badField('fe_ec_cpu_limit', "Please enter a positive integer for the CPU limit.");
			
			category.cpu_sustain = parseInt( $('#fe_ec_cpu_sustain').val() ) * parseInt( $('#fe_ec_cpu_sustain_units').val() );
			if (isNaN(category.cpu_sustain)) return app.badField('fe_ec_cpu_sustain', "Please enter an integer value for the CPU sustain period.");
			if (category.cpu_sustain < 0) return app.badField('fe_ec_cpu_sustain', "Please enter a positive integer for the CPU sustain period.");
		}
		else {
			category.cpu_limit = 0;
			category.cpu_sustain = 0;
		}
		
		// mem limit
		if ($('#fe_ec_memory_enabled').is(':checked')) {
			category.memory_limit = parseInt( $('#fe_ec_memory_limit').val() ) * parseInt( $('#fe_ec_memory_limit_units').val() );
			if (isNaN(category.memory_limit)) return app.badField('fe_ec_memory_limit', "Please enter an integer value for the memory limit.");
			if (category.memory_limit < 0) return app.badField('fe_ec_memory_limit', "Please enter a positive integer for the memory limit.");
			
			category.memory_sustain = parseInt( $('#fe_ec_memory_sustain').val() ) * parseInt( $('#fe_ec_memory_sustain_units').val() );
			if (isNaN(category.memory_sustain)) return app.badField('fe_ec_memory_sustain', "Please enter an integer value for the memory sustain period.");
			if (category.memory_sustain < 0) return app.badField('fe_ec_memory_sustain', "Please enter a positive integer for the memory sustain period.");
		}
		else {
			category.memory_limit = 0;
			category.memory_sustain = 0;
		}
		
		// job log file size limit
		if ($('#fe_ec_log_enabled').is(':checked')) {
			category.log_max_size = parseInt( $('#fe_ec_log_limit').val() ) * parseInt( $('#fe_ec_log_limit_units').val() );
			if (isNaN(category.log_max_size)) return app.badField('fe_ec_log_limit', "Please enter an integer value for the log size limit.");
			if (category.log_max_size < 0) return app.badField('fe_ec_log_limit', "Please enter a positive integer for the log size limit.");
		}
		else {
			category.log_max_size = 0;
		}
		
		return category;
	}
	
});
// Cronicle Admin Page -- Servers

Class.add( Page.Admin, {
	
	gosub_servers: function(args) {
		// show server list, server groups
		this.div.removeClass('loading');
		app.setWindowTitle( "Servers" );
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 400) / 9 );
		
		var html = '';
		
		html += this.getSidebarTabs( 'servers',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		// Active Server Cluster
		
		var cols = ['Hostname', 'IP Address', 'Groups', 'Status', 'Active Jobs', 'Uptime', 'CPU', 'Mem', 'Actions'];
		
		html += '<div class="subtitle">';
			html += 'Server Cluster';
			// html += '<div class="clear"></div>';
		html += '</div>';
		
		this.servers = [];
		var hostnames = hash_keys_to_array( app.servers ).sort();
		for (var idx = 0, len = hostnames.length; idx < len; idx++) {
			this.servers.push( app.servers[ hostnames[idx] ] );
		}
		
		// include nearby servers under main server list
		if (app.nearby) {
			var hostnames = hash_keys_to_array( app.nearby ).sort();
			for (var idx = 0, len = hostnames.length; idx < len; idx++) {
				var server = app.nearby[ hostnames[idx] ];
				if (!app.servers[server.hostname]) {
					server.nearby = 1;
					this.servers.push( server );
				}
			}
		}
		
		// render table
		var self = this;
		html += this.getBasicTable( this.servers, cols, 'server', function(server, idx) {
			
			// render nearby servers differently
			if (server.nearby) {
				var tds = [
					'<div class="td_big" style="font-weight:normal"><div class="ellip" style="max-width:'+col_width+'px;"><i class="fa fa-eye">&nbsp;</i>' + server.hostname.replace(/\.[\w\-]+\.\w+$/, '') + '</div></div>',
					(server.ip || 'n/a').replace(/^\:\:ffff\:(\d+\.\d+\.\d+\.\d+)$/, '$1'),
					'-', '(Nearby)', '-', '-', '-', '-',
					'<span class="link" onMouseUp="$P().add_server_from_list('+idx+')"><b>Add Server</b></span>'
				];
				tds.className = 'blue';
				return tds;
			} // nearby
			
			var actions = [
				'<span class="link" onMouseUp="$P().restart_server('+idx+')"><b>Restart</b></span>',
				'<span class="link" onMouseUp="$P().shutdown_server('+idx+')"><b>Shutdown</b></span>'
			];
			if (server.disabled) actions = [];
			if (!server.master) {
				actions.push( '<span class="link" onMouseUp="$P().remove_server('+idx+')"><b>Remove</b></span>' );
			}
			
			var group_names = [];
			var eligible = false;
			for (var idx = 0, len = app.server_groups.length; idx < len; idx++) {
				var group = app.server_groups[idx];
				var regexp = new RegExp( group.regexp, "i" );
				if (server.hostname.match(regexp)) {
					group_names.push( group.title );
					if (group.master) eligible = true;
				}
			}
			
			var jobs = find_objects( app.activeJobs, { hostname: server.hostname } );
			var num_jobs = jobs.length;
			
			var cpu = 0;
			var mem = 0;
			if (server.data && server.data.cpu) cpu += server.data.cpu;
			if (server.data && server.data.mem) mem += server.data.mem;
			for (idx = 0, len = jobs.length; idx < len; idx++) {
				var job = jobs[idx];
				if (job.cpu && job.cpu.current) cpu += job.cpu.current;
				if (job.mem && job.mem.current) mem += job.mem.current;
			}
			
			var tds = [
				'<div class="td_big">' + self.getNiceGroup(null, server.hostname, col_width) + '</div>',
				(server.ip || 'n/a').replace(/^\:\:ffff\:(\d+\.\d+\.\d+\.\d+)$/, '$1'),
				group_names.length ? group_names.join(', ') : '(None)',
				server.master ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Primary</span>' : (eligible ? '<span class="color_label purple">Backup</span>' : '<span class="color_label blue">Worker</span>'),
				num_jobs ? commify( num_jobs ) : '(None)',
				get_text_from_seconds( server.uptime, true, true ).replace(/\bday\b/, 'days'),
				short_float(cpu) + '%',
				get_text_from_bytes(mem),
				actions.join(' | ')
			];
			
			if (server.disabled) tds.className = 'disabled';
			
			return tds;
		} );
		
		html += '<div style="height:25px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().add_server()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Server...</div></td>';
		html += '</tr></table></center>';
		
		html += '<div style="height:30px;"></div>';
		
		// Server Groups
		
		var col_width = Math.floor( ((size.width * 0.9) + 300) / 6 );
		
		var cols = ['Title', 'Hostname Match', '# of Servers', '# of Events', 'Class', 'Actions'];
		
		html += '<div class="subtitle">';
			html += 'Server Groups';
			// html += '<div class="clear"></div>';
		html += '</div>';
		
		// sort by title ascending
		this.server_groups = app.server_groups.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		// render table
		var self = this;
		html += this.getBasicTable( this.server_groups, cols, 'group', function(group, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_group('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_group('+idx+')"><b>Delete</b></span>'
			];
			
			var regexp = new RegExp( group.regexp, "i" );
			var num_servers = 0;
			for (var hostname in app.servers) {
				if (hostname.match(regexp)) num_servers++;
			}
			
			var group_events = find_objects( app.schedule, { target: group.id } );
			var num_events = group_events.length;
			
			return [
				'<div class="td_big" style="white-space:nowrap;"><span class="link" onMouseUp="$P().edit_group('+idx+')">' + self.getNiceGroup(group, null, col_width) + '</span></div>',
				'<div class="ellip" style="font-family:monospace; max-width:'+col_width+'px;">/' + encode_entities(group.regexp) + '/</div>',
				// group.description || '(No description)',
				num_servers ? commify( num_servers) : '(None)',
				num_events ? commify( num_events ) : '(None)',
				group.master ? '<b>Primary Eligible</b>' : 'Worker Only',
				actions.join(' | ')
			];
		} );
		
		html += '<div style="height:25px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_group(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add Group...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	add_server_from_list: function(idx) {
		// add a server right away, from the nearby list
		var server = this.servers[idx];
		
		app.showProgress( 1.0, "Adding server..." );
		app.api.post( 'app/add_server', { hostname: server.ip || server.hostname }, function(resp) {
			app.hideProgress();
			app.showMessage('success', "Server was added successfully.");
			// self['gosub_servers'](self.args);
		} ); // api.post
	},
	
	add_server: function() {
		// show dialog allowing user to enter an arbitrary hostname to add
		var html = '';
		
		// html += '<div style="font-size:12px; color:#777; margin-bottom:15px;">Typically, servers should automatically add themselves to the cluster, if they are within UDP broadcast range (i.e. on the same LAN).  You should only need to manually add a server in special circumstances, e.g. if it is remotely hosted in another datacenter or network.</div>';
		
		// html += '<div style="font-size:12px; color:#777; margin-bottom:20px;">Note that the new server cannot already be a master server, nor part of another '+app.name+' server cluster, and the current master server must be able to reach it.</div>';
		
		html += '<center><table>' + 
			// get_form_table_spacer() + 
			get_form_table_row('Hostname or IP:', '<input type="text" id="fe_as_hostname" style="width:280px" value="" spellcheck="false"/>') + 
			get_form_table_caption("Enter the hostname or IP of the server you want to add.") + 
		'</table></center>';
		
		app.confirm( '<i class="mdi mdi-desktop-tower mdi-lg">&nbsp;&nbsp;</i>Add Server', html, "Add Server", function(result) {
			app.clearError();
			
			if (result) {
				var hostname = $('#fe_as_hostname').val().toLowerCase();
				if (!hostname) return app.badField('fe_as_hostname', "Please enter a server hostname or IP address.");
				if (!hostname.match(/^[\w\-\.]+$/)) return app.badField('fe_as_hostname', "Please enter a valid server hostname or IP address.");
				if (app.servers[hostname]) return app.badField('fe_as_hostname', "That server is already in the cluster.");
				Dialog.hide();
				
				app.showProgress( 1.0, "Adding server..." );
				app.api.post( 'app/add_server', { hostname: hostname }, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Server was added successfully.");
					// self['gosub_servers'](self.args);
				} ); // api.post
			} // user clicked add
		} ); // app.confirm
		
		setTimeout( function() { 
			$('#fe_as_hostname').focus();
		}, 1 );
	},
	
	remove_server: function(idx) {
		// remove manual server after user confirmation
		var server = this.servers[idx];
		
		var jobs = find_objects( app.activeJobs, { hostname: server.hostname } );
		if (jobs.length) return app.doError("Sorry, you cannot remove a server that has active jobs running on it.");
		
		// proceed with remove
		var self = this;
		app.confirm( '<span style="color:red">Remove Server</span>', "Are you sure you want to remove the server <b>"+server.hostname+"</b>?", "Remove", function(result) {
			if (result) {
				app.showProgress( 1.0, "Removing server..." );
				app.api.post( 'app/remove_server', server, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Server was removed successfully.");
					// self.gosub_servers(self.args);
				} );
			}
		} );
	},
	
	edit_group: function(idx) {
		// edit group (-1 == new group)
		var self = this;
		var group = (idx > -1) ? this.server_groups[idx] : {
			title: "",
			regexp: "",
			master: 0
		};
		var edit = (idx > -1) ? true : false;
		var html = '';
		
		html += '<table>';
		
		// Internal ID
		if (edit && this.isAdmin()) {
			html += get_form_table_row( 'Group ID', '<div style="font-size:14px;">' + group.id + '</div>' );
			html += get_form_table_caption( "The internal Group ID used for API calls.  This cannot be changed." );
			html += get_form_table_spacer();
		}
		
		html += 
			get_form_table_row('Group Title:', '<input type="text" id="fe_eg_title" size="25" value="'+escape_text_field_value(group.title)+'"/>') + 
			get_form_table_caption("Enter a title for the server group, short and sweet.") + 
			get_form_table_spacer() + 
			get_form_table_row('Hostname Match:', '<input type="text" id="fe_eg_regexp" size="30" style="font-family:monospace; font-size:13px;" value="'+escape_text_field_value(group.regexp)+'" spellcheck="false"/>') + 
			get_form_table_caption("Enter a regular expression to auto-assign servers to this group by their hostnames, e.g. \"^mtx\\d+\\.\".") + 
			get_form_table_spacer() + 
			get_form_table_row('Server Class:', '<select id="fe_eg_master">' + render_menu_options([ [1,'Primary Eligible'], [0,'Worker Only'] ], group.master, false) + '</select>') + 
			get_form_table_caption("Select whether servers in the group are eligible to become the primary server, or run as workers only.") + 
		'</table>';
		
		app.confirm( '<i class="mdi mdi-server-network">&nbsp;&nbsp;</i>' + (edit ? "Edit Server Group" : "Add Server Group"), html, edit ? "Save Changes" : "Add Group", function(result) {
			app.clearError();
			
			if (result) {
				group.title = $('#fe_eg_title').val();
				if (!group.title) return app.badField('fe_eg_title', "Please enter a title for the server group.");
				group.regexp = $('#fe_eg_regexp').val().replace(/^\/(.+)\/$/, '$1');
				if (!group.regexp) return app.badField('fe_eg_regexp', "Please enter a regular expression for the server group.");
				
				try { new RegExp(group.regexp); }
				catch(err) {
					return app.badField('fe_eg_regexp', "Invalid regular expression: " + err);
				}
				
				group.master = parseInt( $('#fe_eg_master').val() );
				Dialog.hide();
				
				// pro-tip: embed id in title as bracketed prefix
				if (!edit && group.title.match(/^\[(\w+)\]\s*(.+)$/)) {
					group.id = RegExp.$1;
					group.title = RegExp.$2;
				}
				
				app.showProgress( 1.0, edit ? "Saving group..." : "Adding group..." );
				app.api.post( edit ? 'app/update_server_group' : 'app/create_server_group', group, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Server group was " + (edit ? "saved" : "added") + " successfully.");
					// self['gosub_servers'](self.args);
				} ); // api.post
			} // user clicked add
		} ); // app.confirm
		
		setTimeout( function() { 
			if (!$('#fe_eg_title').val()) $('#fe_eg_title').focus();
		}, 1 );
	},
	
	delete_group: function(idx) {
		// delete selected server group
		var group = this.server_groups[idx];
		
		// make sure user isn't deleting final master group
		if (group.master) {
			var num_masters = 0;
			for (var idx = 0, len = this.server_groups.length; idx < len; idx++) {
				if (this.server_groups[idx].master) num_masters++;
			}
			if (num_masters == 1) {
				return app.doError("Sorry, you cannot delete the last Primary Eligible server group.");
			}
		}
		
		// check for events first
		var group_events = find_objects( app.schedule, { target: group.id } );
		var num_events = group_events.length;
		if (num_events) return app.doError("Sorry, you cannot delete a group that has events assigned to it.");
		
		// proceed with delete
		var self = this;
		app.confirm( '<span style="color:red">Delete Server Group</span>', "Are you sure you want to delete the server group <b>"+group.title+"</b>?  There is no way to undo this action.", "Delete", function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting group..." );
				app.api.post( 'app/delete_server_group', group, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Server group was deleted successfully.");
					// self.gosub_servers(self.args);
				} );
			}
		} );
	},
	
	restart_server: function(idx) {
		// restart server after confirmation
		var self = this;
		var server = this.servers[idx];
		
		app.confirm( '<span style="color:red">Restart Server</span>', "Are you sure you want to restart the server <b>"+server.hostname+"</b>?  All server jobs will be aborted.", "Restart", function(result) {
			if (result) {
				app.showProgress( 1.0, "Restarting server..." );
				app.api.post( 'app/restart_server', server, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Server is being restarted in the background.");
					// self.gosub_servers(self.args);
				} );
			}
		} );
	},
	
	shutdown_server: function(idx) {
		// shutdown server after confirmation
		var self = this;
		var server = this.servers[idx];
		
		app.confirm( '<span style="color:red">Shutdown Server</span>', "Are you sure you want to shutdown the server <b>"+server.hostname+"</b>?  All server jobs will be aborted.", "Shutdown", function(result) {
			if (result) {
				app.showProgress( 1.0, "Shutting down server..." );
				app.api.post( 'app/shutdown_server', server, function(resp) {
					app.hideProgress();
					app.showMessage('success', "Server is being shut down in the background.");
					// self.gosub_servers(self.args);
				} );
			}
		} );
	}
	
});
// Cronicle Admin Page -- Users

Class.add( Page.Admin, {
	
	gosub_users: function(args) {
		// show user list
		app.setWindowTitle( "User List" );
		this.div.addClass('loading');
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = 25;
		app.api.post( 'user/admin_get_users', copy_object(args), this.receive_users.bind(this) );
	},
	
	receive_users: function(resp) {
		// receive page of users from server, render it
		this.lastUsersResp = resp;
		
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 7 );
		
		this.users = [];
		if (resp.rows) this.users = resp.rows;
		
		html += this.getSidebarTabs( 'users',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		var cols = ['Username', 'Full Name', 'Email Address', 'Status', 'Type', 'Created', 'Actions'];
		
		// html += '<div style="padding:5px 15px 15px 15px;">';
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'User Accounts';
			// html += '<div class="subtitle_widget"><span class="link" onMouseUp="$P().refresh_user_list()"><b>Refresh</b></span></div>';
			html += '<div class="subtitle_widget"><i class="fa fa-search">&nbsp;</i><input type="text" id="fe_ul_search" size="15" placeholder="Find username..." style="border:0px;"/></div>';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getPaginatedTable( resp, cols, 'user', function(user, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_user('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_user('+idx+')"><b>Delete</b></span>'
			];
			return [
				'<div class="td_big">' + self.getNiceUsername(user, true, col_width) + '</div>',
				'<div class="ellip" style="max-width:'+col_width+'px;">' + encode_entities(user.full_name) + '</div>',
				'<div class="ellip" style="max-width:'+col_width+'px;"><a href="mailto:'+user.email+'">'+encode_entities(user.email)+'</a></div>',
				user.active ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Active</span>' : '<span class="color_label red"><i class="fa fa-warning">&nbsp;</i>Suspended</span>',
				user.privileges.admin ? '<span class="color_label purple"><i class="fa fa-lock">&nbsp;</i>Admin</span>' : '<span class="color_label gray">Standard</span>',
				'<span title="'+get_nice_date_time(user.created, true)+'">'+get_nice_date(user.created, true)+'</span>',
				actions.join(' | ')
			];
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_user(-1)"><i class="fa fa-user-plus">&nbsp;&nbsp;</i>Add User...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ul_search').keypress( function(event) {
				if (event.keyCode == '13') { // enter key
					event.preventDefault();
					$P().do_user_search( $('#fe_ul_search').val() );
				}
			} )
			.blur( function() { app.hideMessage(250); } )
			.keydown( function() { app.hideMessage(); } );
		}, 1 );
	},
	
	do_user_search: function(username) {
		// see if user exists, edit if so
		app.api.post( 'user/admin_get_user', { username: username }, 
			function(resp) {
				Nav.go('Admin?sub=edit_user&username=' + username);
			},
			function(resp) {
				app.doError("User not found: " + username, 10);
			}
		);
	},
	
	edit_user: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_user&username=' + this.users[idx].username );
		else if (app.config.external_users) {
			app.doError("Users are managed by an external system, so you cannot add users from here.");
		}
		else Nav.go( '#Admin?sub=new_user' );
	},
	
	delete_user: function(idx) {
		// delete user from search results
		this.user = this.users[idx];
		this.show_delete_account_dialog();
	},
	
	gosub_new_user: function(args) {
		// create new user
		var html = '';
		app.setWindowTitle( "Add New User" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_user',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"],
				['new_user', "Add New User"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Add New User</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.user = { 
			privileges: copy_object( config.default_privileges )
		};
		
		html += this.get_user_edit_html();
		
		// notify user
		html += get_form_table_row( 'Notify', '<input type="checkbox" id="fe_eu_send_email" value="1" checked="checked"/><label for="fe_eu_send_email">Send Welcome Email</label>' );
		html += get_form_table_caption( "Select notification options for the new user." );
		html += get_form_table_spacer();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_user_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				if (config.debug) {
					html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().populate_random_user()">Randomize...</div></td>';
					html += '<td width="50">&nbsp;</td>';
				}
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_user()"><i class="fa fa-user-plus">&nbsp;&nbsp;</i>Create User</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_eu_username').focus();
		}, 1 );
	},
	
	cancel_user_edit: function() {
		// cancel editing user and return to list
		Nav.go( 'Admin?sub=users' );
	},
	
	populate_random_user: function() {
		// grab random user data (for testing only)
		var self = this;
		
		$.ajax({
			url: 'http://api.randomuser.me/',
			dataType: 'json',
			success: function(data){
				// console.log(data);
				if (data.results && data.results[0] && data.results[0].user) {
					var user = data.results[0].user;
					$('#fe_eu_username').val( user.username );
					$('#fe_eu_email').val( user.email );
					$('#fe_eu_fullname').val( ucfirst(user.name.first) + ' ' + ucfirst(user.name.last) );
					$('#fe_eu_send_email').prop( 'checked', false );
					self.generate_password();
					self.checkUserExists('eu');
				}
			}
		});
	},
	
	do_new_user: function(force) {
		// create new user
		app.clearError();
		var user = this.get_user_form_json();
		if (!user) return; // error
		
		if (!user.username.length) {
			return app.badField('#fe_eu_username', "Please enter a username for the new account.");
		}
		if (!user.username.match(/^[\w\-\.]+$/)) {
			return app.badField('#fe_eu_username', "Please make sure the username contains only alphanumerics, periods and dashes.");
		}
		if (!user.email.length) {
			return app.badField('#fe_eu_email', "Please enter an e-mail address where the user can be reached.");
		}
		if (!user.email.match(/^\S+\@\S+$/)) {
			return app.badField('#fe_eu_email', "The e-mail address you entered does not appear to be correct.");
		}
		if (!user.full_name.length) {
			return app.badField('#fe_eu_fullname', "Please enter the user's first and last names.");
		}
		if (!user.password.length) {
			return app.badField('#fe_eu_password', "Please enter a secure password to protect the account.");
		}
		
		user.send_email = $('#fe_eu_send_email').is(':checked') ? 1 : 0;
		
		this.user = user;
		
		app.showProgress( 1.0, "Creating user..." );
		app.api.post( 'user/admin_create', user, this.new_user_finish.bind(this) );
	},
	
	new_user_finish: function(resp) {
		// new user created successfully
		app.hideProgress();
		
		Nav.go('Admin?sub=edit_user&username=' + this.user.username);
		
		setTimeout( function() {
			app.showMessage('success', "The new user account was created successfully.");
		}, 150 );
	},
	
	gosub_edit_user: function(args) {
		// edit user subpage
		this.div.addClass('loading');
		app.api.post( 'user/admin_get_user', { username: args.username }, this.receive_user.bind(this) );
	},
	
	receive_user: function(resp) {
		// edit existing user
		var html = '';
		app.setWindowTitle( "Editing User \"" + (this.args.username) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_user',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"],
				['edit_user', "Edit User"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing User &ldquo;' + (this.args.username) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		this.user = resp.user;
		
		html += this.get_user_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_user_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_account_dialog()">Delete Account...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_user()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_eu_username').attr('disabled', true);
			
			if (app.config.external_users) {
				app.showMessage('warning', "Users are managed by an external system, so making changes here may have little effect.");
				// self.div.find('input').prop('disabled', true);
			}
		}, 1 );
	},
	
	do_save_user: function() {
		// create new user
		app.clearError();
		var user = this.get_user_form_json();
		if (!user) return; // error
		
		// if changing password, give server a hint
		if (user.password) {
			user.new_password = user.password;
			delete user.password;
		}
		
		this.user = user;
		
		app.showProgress( 1.0, "Saving user account..." );
		app.api.post( 'user/admin_update', user, this.save_user_finish.bind(this) );
	},
	
	save_user_finish: function(resp, tx) {
		// new user created successfully
		app.hideProgress();
		app.showMessage('success', "The user was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// if we edited ourself, update header
		if (this.args.username == app.username) {
			app.user = resp.user;
			app.updateHeaderInfo();
		}
		
		$('#fe_eu_password').val('');
	},
	
	show_delete_account_dialog: function() {
		// show dialog confirming account delete action
		var self = this;
		
		var msg = "Are you sure you want to <b>permanently delete</b> the user account \""+this.user.username+"\"?  There is no way to undo this action, and no way to recover the data.";
		
		if (app.config.external_users) {
			msg = "Are you sure you want to delete the user account \""+this.user.username+"\"?  Users are managed by an external system, so this will have little effect here.";
			// return app.doError("Users are managed by an external system, so you cannot make changes here.");
		}
		
		app.confirm( '<span style="color:red">Delete Account</span>', msg, 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Account..." );
				app.api.post( 'user/admin_delete', {
					username: self.user.username
				}, self.delete_user_finish.bind(self) );
			}
		} );
	},
	
	delete_user_finish: function(resp, tx) {
		// finished deleting, immediately log user out
		var self = this;
		app.hideProgress();
		
		Nav.go('Admin?sub=users', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The user account '"+self.user.username+"' was deleted successfully.");
		}, 150 );
	},
	
	get_user_edit_html: function() {
		// get html for editing a user (or creating a new one)
		var html = '';
		var user = this.user;
		
		// user id
		html += get_form_table_row( 'Username', 
			'<table cellspacing="0" cellpadding="0"><tr>' + 
				'<td><input type="text" id="fe_eu_username" size="20" style="font-size:14px;" value="'+escape_text_field_value(user.username)+'" spellcheck="false" onChange="$P().checkUserExists(\'eu\')"/></td>' + 
				'<td><div id="d_eu_valid" style="margin-left:5px; font-weight:bold;"></div></td>' + 
			'</tr></table>'
		);
		html += get_form_table_caption( "Enter the username which identifies this account.  Once entered, it cannot be changed. " );
		html += get_form_table_spacer();
		
		// account status
		html += get_form_table_row( 'Account Status', '<select id="fe_eu_status">' + render_menu_options([['1','Active'], ['0','Suspended']], user.active) + '</select>' );
		html += get_form_table_caption( "'Suspended' means that the account remains in the system, but the user cannot log in." );
		html += get_form_table_spacer();
		
		// full name
		html += get_form_table_row( 'Full Name', '<input type="text" id="fe_eu_fullname" size="30" value="'+escape_text_field_value(user.full_name)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "User's first and last name.  They will not be shared with anyone outside the server.");
		html += get_form_table_spacer();
		
		// email
		html += get_form_table_row( 'Email Address', '<input type="text" id="fe_eu_email" size="30" value="'+escape_text_field_value(user.email)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "This can be used to recover the password if the user forgets.  It will not be shared with anyone outside the server." );
		html += get_form_table_spacer();
		
		// password
		html += get_form_table_row( user.password ? 'Change Password' : 'Password', '<input type="text" id="fe_eu_password" size="20" value="" spellcheck="false"/>&nbsp;<span class="link addme" onMouseUp="$P().generate_password()">&laquo; Generate Random</span>' );
		html += get_form_table_caption( user.password ? "Optionally enter a new password here to reset it.  Please make it secure." : "Enter a password for the account.  Please make it secure." );
		html += get_form_table_spacer();
		
		// privilege list
		var priv_html = '';
		var user_is_admin = !!user.privileges.admin;
		
		for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
			var priv = config.privilege_list[idx];
			var has_priv = !!user.privileges[ priv.id ];
			var priv_visible = (priv.id == 'admin') || !user_is_admin;
			var priv_class = (priv.id == 'admin') ? 'priv_group_admin' : 'priv_group_other';
			
			priv_html += '<div class="'+priv_class+'" style="margin-top:4px; margin-bottom:4px; '+(priv_visible ? '' : 'display:none;')+'">';
			priv_html += '<input type="checkbox" id="fe_eu_priv_'+priv.id+'" value="1" ' + 
				(has_priv ? 'checked="checked" ' : '') + ((priv.id == 'admin') ? 'onChange="$P().change_admin_checkbox()"' : '') + '>';
			priv_html += '<label for="fe_eu_priv_'+priv.id+'">'+priv.title+'</label>';
			priv_html += '</div>';
		}
		
		// user can be limited to certain categories
		var priv = { id: "cat_limit", title: "Limit to Categories" };
		var has_priv = !!user.privileges[ priv.id ];
		var priv_visible = !user_is_admin;
		
		priv_html += '<div class="priv_group_other" style="margin-top:4px; margin-bottom:4px; '+(priv_visible ? '' : 'display:none;')+'">';
		priv_html += '<input type="checkbox" id="fe_eu_priv_'+priv.id+'" value="1" ' + 
			(has_priv ? 'checked="checked" ' : '') + 'onChange="$P().change_cat_checkbox()"' + '>';
		priv_html += '<label for="fe_eu_priv_'+priv.id+'">'+priv.title+'</label>';
		priv_html += '</div>';
		
		priv_html += '<div class="priv_group_other">';
		
		// sort by title ascending
		var categories = app.categories.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		for (var idx = 0, len = categories.length; idx < len; idx++) {
			var cat = categories[idx];
			var priv = { id: 'cat_' + cat.id, title: cat.title };
			var has_priv = !!user.privileges[ priv.id ];
			var priv_visible = !!user.privileges.cat_limit;
			
			priv_html += '<div class="priv_group_cat" style="margin-top:4px; margin-bottom:4px; margin-left:20px; '+(priv_visible ? '' : 'display:none;')+'">';
			priv_html += '<input type="checkbox" id="fe_eu_priv_'+priv.id+'" value="1" ' + 
				(has_priv ? 'checked="checked" ' : '') + '>';
			priv_html += '<label for="fe_eu_priv_'+priv.id+'" style="font-weight:normal"><i class="fa fa-folder-open-o">&nbsp;</i>'+priv.title+'</label>';
			priv_html += '</div>';
		}
		
		priv_html += '</div>';
		
		// user can be limited to certain server groups
		var priv = { id: "grp_limit", title: "Limit to Server Groups" };
		var has_priv = !!user.privileges[ priv.id ];
		var priv_visible = !user_is_admin;
		
		priv_html += '<div class="priv_group_other" style="margin-top:4px; margin-bottom:4px; '+(priv_visible ? '' : 'display:none;')+'">';
		priv_html += '<input type="checkbox" id="fe_eu_priv_'+priv.id+'" value="1" ' + 
			(has_priv ? 'checked="checked" ' : '') + 'onChange="$P().change_grp_checkbox()"' + '>';
		priv_html += '<label for="fe_eu_priv_'+priv.id+'">'+priv.title+'</label>';
		priv_html += '</div>';
		
		priv_html += '<div class="priv_group_other">';
		
		// sort by title ascending
		var groups = app.server_groups.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		for (var idx = 0, len = groups.length; idx < len; idx++) {
			var group = groups[idx];
			var priv = { id: 'grp_' + group.id, title: group.title };
			var has_priv = !!user.privileges[ priv.id ];
			var priv_visible = !!user.privileges.grp_limit;
			
			priv_html += '<div class="priv_group_grp" style="margin-top:4px; margin-bottom:4px; margin-left:20px; '+(priv_visible ? '' : 'display:none;')+'">';
			priv_html += '<input type="checkbox" id="fe_eu_priv_'+priv.id+'" value="1" ' + 
				(has_priv ? 'checked="checked" ' : '') + '>';
			priv_html += '<label for="fe_eu_priv_'+priv.id+'" style="font-weight:normal"><i class="fa fa-folder-open-o">&nbsp;</i>'+priv.title+'</label>';
			priv_html += '</div>';
		}
		
		priv_html += '</div>';
		
		html += get_form_table_row( 'Privileges', priv_html );
		html += get_form_table_caption( "Select which privileges the user account should have. Administrators have all privileges." );
		html += get_form_table_spacer();
		
		return html;
	},
	
	change_admin_checkbox: function() {
		// toggle admin checkbox
		var is_checked = $('#fe_eu_priv_admin').is(':checked');
		if (is_checked) $('div.priv_group_other').hide(250);
		else $('div.priv_group_other').show(250);
	},
	
	change_cat_checkbox: function() {
		// toggle category limit checkbox
		var is_checked = $('#fe_eu_priv_cat_limit').is(':checked');
		if (is_checked) $('div.priv_group_cat').show(250);
		else $('div.priv_group_cat').hide(250);
	},
	
	change_grp_checkbox: function() {
		// toggle server group limit checkbox
		var is_checked = $('#fe_eu_priv_grp_limit').is(':checked');
		if (is_checked) $('div.priv_group_grp').show(250);
		else $('div.priv_group_grp').hide(250);
	},
	
	get_user_form_json: function() {
		// get user elements from form, used for new or edit
		var user = {
			username: trim($('#fe_eu_username').val().toLowerCase()),
			active: parseInt($('#fe_eu_status').val()),
			full_name: trim($('#fe_eu_fullname').val()),
			email: trim($('#fe_eu_email').val()),
			password: $('#fe_eu_password').val(),
			privileges: {}
		};
		
		user.privileges.admin = $('#fe_eu_priv_admin').is(':checked') ? 1 : 0;
		
		if (!user.privileges.admin) {
			for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
				var priv = config.privilege_list[idx];
				user.privileges[ priv.id ] = $('#fe_eu_priv_'+priv.id).is(':checked') ? 1 : 0;
			}
			
			// category limit privs
			user.privileges.cat_limit = $('#fe_eu_priv_cat_limit').is(':checked') ? 1 : 0;
			
			if (user.privileges.cat_limit) {
				var num_cat_privs = 0;
				for (var idx = 0, len = app.categories.length; idx < len; idx++) {
					var cat = app.categories[idx];
					var priv = { id: 'cat_' + cat.id };
					if ($('#fe_eu_priv_'+priv.id).is(':checked')) {
						user.privileges[ priv.id ] = 1;
						num_cat_privs++;
					}
				}
				
				if (!num_cat_privs) return app.doError("Please select at least one category privilege.");
			} // cat limit
			
			// server group limit privs
			user.privileges.grp_limit = $('#fe_eu_priv_grp_limit').is(':checked') ? 1 : 0;
			
			if (user.privileges.grp_limit) {
				var num_grp_privs = 0;
				for (var idx = 0, len = app.server_groups.length; idx < len; idx++) {
					var grp = app.server_groups[idx];
					var priv = { id: 'grp_' + grp.id };
					if ($('#fe_eu_priv_'+priv.id).is(':checked')) {
						user.privileges[ priv.id ] = 1;
						num_grp_privs++;
					}
				}
				
				if (!num_grp_privs) return app.doError("Please select at least one server group privilege.");
			} // grp limit
		} // not admin
		
		return user;
	},
	
	generate_password: function() {
		// generate random password
		$('#fe_eu_password').val( b64_md5(get_unique_id()).substring(0, 8) );
	}
	
});

// Cronicle Admin Page -- Plugins

Class.add( Page.Admin, {
	
	ctype_labels: {
		text: "Text Field",
		textarea: "Text Box",
		checkbox: "Checkbox",
		hidden: "Hidden",
		select: "Menu"
	},
	
	gosub_plugins: function(args) {
		// show plugin list
		this.div.removeClass('loading');
		app.setWindowTitle( "Plugins" );
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 500) / 6 );
		
		var html = '';
		
		this.plugins = app.plugins;
		
		html += this.getSidebarTabs( 'plugins',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		var cols = ['Plugin Name', 'Author', '# of Events', 'Created', 'Modified', 'Actions'];
		
		// html += '<div style="padding:5px 15px 15px 15px;">';
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Plugins';
			// html += '<div class="clear"></div>';
		html += '</div>';
		
		// sort by title ascending
		this.plugins = app.plugins.sort( function(a, b) {
			// return (b.title < a.title) ? 1 : -1;
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		var self = this;
		html += this.getBasicTable( this.plugins, cols, 'plugin', function(plugin, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_plugin('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_plugin('+idx+')"><b>Delete</b></span>'
			];
			
			var plugin_events = find_objects( app.schedule, { plugin: plugin.id } );
			var num_events = plugin_events.length;
			
			var tds = [
				'<div class="td_big"><a href="#Admin?sub=edit_plugin&id='+plugin.id+'">' + self.getNicePlugin(plugin, col_width) + '</a></div>',
				self.getNiceUsername(plugin, true, col_width),
				num_events ? commify( num_events ) : '(None)',
				'<span title="'+get_nice_date_time(plugin.created, true)+'">'+get_nice_date(plugin.created, true)+'</span>',
				'<span title="'+get_nice_date_time(plugin.modified, true)+'">'+get_nice_date(plugin.modified, true)+'</span>',
				actions.join(' | ')
			];
			
			if (!plugin.enabled) {
				if (tds.className) tds.className += ' '; else tds.className = '';
				tds.className += 'disabled';
			}
			
			return tds;
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:140px;" onMouseUp="$P().edit_plugin(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add New Plugin...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	edit_plugin: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_plugin&id=' + this.plugins[idx].id );
		else Nav.go( '#Admin?sub=new_plugin' );
	},
	
	delete_plugin: function(idx) {
		// delete key from search results
		this.plugin = this.plugins[idx];
		this.show_delete_plugin_dialog();
	},
	
	show_delete_plugin_dialog: function() {
		// delete selected plugin
		var plugin = this.plugin;
		
		// check for events first
		var plugin_events = find_objects( app.schedule, { plugin: plugin.id } );
		var num_events = plugin_events.length;
		if (num_events) return app.doError("Sorry, you cannot delete a plugin that has events assigned to it.");
		
		// proceed with delete
		var self = this;
		app.confirm( '<span style="color:red">Delete Plugin</span>', "Are you sure you want to delete the plugin <b>"+plugin.title+"</b>?  There is no way to undo this action.", "Delete", function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting Plugin..." );
				app.api.post( 'app/delete_plugin', plugin, function(resp) {
					app.hideProgress();
					app.showMessage('success', "The Plugin '"+self.plugin.title+"' was deleted successfully.");
					// self.gosub_plugins(self.args);
					
					Nav.go('Admin?sub=plugins', 'force');
				} );
			}
		} );
	},
	
	gosub_new_plugin: function(args) {
		// create new plugin
		var html = '';
		app.setWindowTitle( "Add New Plugin" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_plugin',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['new_plugin', "Add New Plugin"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Add New Plugin</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		if (this.plugin_copy) {
			this.plugin = this.plugin_copy;
			delete this.plugin_copy;
		}
		else {
			this.plugin = { params: [], enabled: 1 };
		}
		
		html += this.get_plugin_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_plugin_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_plugin()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Create Plugin</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		html += '</table></center>';
		
		html += '</div>'; // table wrapper div
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ep_title').focus();
		}, 1 );
	},
	
	cancel_plugin_edit: function() {
		// cancel edit, nav back to plugin list
		Nav.go('Admin?sub=plugins');
	},
	
	do_new_plugin: function(force) {
		// create new plugin
		app.clearError();
		var plugin = this.get_plugin_form_json();
		if (!plugin) return; // error
		
		// pro-tip: embed id in title as bracketed prefix
		if (plugin.title.match(/^\[(\w+)\]\s*(.+)$/)) {
			plugin.id = RegExp.$1;
			plugin.title = RegExp.$2;
		}
		
		this.plugin = plugin;
		
		app.showProgress( 1.0, "Creating plugin..." );
		app.api.post( 'app/create_plugin', plugin, this.new_plugin_finish.bind(this) );
	},
	
	new_plugin_finish: function(resp) {
		// new plugin created successfully
		app.hideProgress();
		
		Nav.go('Admin?sub=plugins');
		
		setTimeout( function() {
			app.showMessage('success', "The new plugin was created successfully.");
		}, 150 );
	},
	
	gosub_edit_plugin: function(args) {
		// edit plugin subpage
		var plugin = find_object( app.plugins, { id: args.id } );
		if (!plugin) return app.doError("Could not locate Plugin with ID: " + args.id);
		
		// make local copy so edits don't affect main app list until save
		this.plugin = deep_copy_object( plugin );
		
		var html = '';
		app.setWindowTitle( "Editing Plugin \"" + plugin.title + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_plugin',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['edit_plugin', "Edit Plugin"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing Plugin &ldquo;' + plugin.title + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_plugin_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_plugin_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().show_delete_plugin_dialog()">Delete Plugin...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().do_copy_plugin()">Copy Plugin...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_plugin()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_copy_plugin: function() {
		// copy plugin to new
		app.clearError();
		var plugin = this.get_plugin_form_json();
		if (!plugin) return; // error
		
		delete plugin.id;
		delete plugin.created;
		delete plugin.modified;
		delete plugin.username;
		
		plugin.title = "Copy of " + plugin.title;
		
		this.plugin_copy = plugin;
		Nav.go('Admin?sub=new_plugin');
	},
	
	do_save_plugin: function() {
		// save changes to existing plugin
		app.clearError();
		var plugin = this.get_plugin_form_json();
		if (!plugin) return; // error
		
		this.plugin = plugin;
		
		app.showProgress( 1.0, "Saving plugin..." );
		app.api.post( 'app/update_plugin', plugin, this.save_plugin_finish.bind(this) );
	},
	
	save_plugin_finish: function(resp, tx) {
		// existing plugin saved successfully
		var self = this;
		var plugin = this.plugin;
		
		app.hideProgress();
		app.showMessage('success', "The plugin was saved successfully.");
		window.scrollTo( 0, 0 );
		
		// copy active jobs to array
		var jobs = [];
		for (var id in app.activeJobs) {
			var job = app.activeJobs[id];
			if ((job.plugin == plugin.id) && !job.detached) jobs.push( job );
		}
		
		// if the plugin was disabled and there are running jobs, ask user to abort them
		if (!plugin.enabled && jobs.length) {
			app.confirm( '<span style="color:red">Abort Jobs</span>', "There " + ((jobs.length != 1) ? 'are' : 'is') + " currently still " + jobs.length + " active " + pluralize('job', jobs.length) + " using the disabled plugin <b>"+plugin.title+"</b>.  Do you want to abort " + ((jobs.length != 1) ? 'these' : 'it') + " now?", "Abort", function(result) {
				if (result) {
					app.showProgress( 1.0, "Aborting " + pluralize('Job', jobs.length) + "..." );
					app.api.post( 'app/abort_jobs', { plugin: plugin.id }, function(resp) {
						app.hideProgress();
						if (resp.count > 0) {
							app.showMessage('success', "The " + pluralize('job', resp.count) + " " + ((resp.count != 1) ? 'were' : 'was') + " aborted successfully.");
						}
						else {
							app.showMessage('warning', "No jobs were aborted.  It is likely they completed while the dialog was up.");
						}
					} );
				} // clicked Abort
			} ); // app.confirm
		} // disabled + jobs
	},
	
	get_plugin_edit_html: function() {
		// get html for editing a plugin (or creating a new one)
		var html = '';
		var plugin = this.plugin;
		
		// Internal ID
		if (plugin.id && this.isAdmin()) {
			html += get_form_table_row( 'Plugin ID', '<div style="font-size:14px;">' + plugin.id + '</div>' );
			html += get_form_table_caption( "The internal Plugin ID used for API calls.  This cannot be changed." );
			html += get_form_table_spacer();
		}
		
		// plugin title
		html += get_form_table_row( 'Plugin Name', '<input type="text" id="fe_ep_title" size="35" value="'+escape_text_field_value(plugin.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter a name for the Plugin.  Ideally it should be somewhat short, and Title Case." );
		html += get_form_table_spacer();
		
		// plugin enabled
		html += get_form_table_row( 'Active', '<input type="checkbox" id="fe_ep_enabled" value="1" ' + (plugin.enabled ? 'checked="checked"' : '') + '/><label for="fe_ep_enabled">Plugin Enabled</label>' );
		html += get_form_table_caption( "Select whether events using this Plugin should be enabled or disabled in the schedule." );
		html += get_form_table_spacer();
		
		// command
		html += get_form_table_row('Executable:', '<textarea id="fe_ep_command" style="width:550px; height:50px; resize:vertical;" spellcheck="false" onkeydown="return $P().stopEnter(this,event)">'+escape_text_field_value(plugin.command)+'</textarea>');
		html += get_form_table_caption(
			'Enter the filesystem path to your executable, including any command-line arguments.<br/>' + 
			'Do not include any pipes or redirects -- for those, please use the <b>Shell Plugin</b>.' 
		);
		html += get_form_table_spacer();
		
		// params editor
		html += get_form_table_row( 'Parameters:', '<div id="d_ep_params">' + this.get_plugin_params_html() + '</div>' );
		html += get_form_table_caption( 
			'<div style="margin-top:5px;">Parameters are passed to your Plugin via JSON, and as environment variables.<br/>' + 
			'For example, you can use this to customize the PATH variable, if your Plugin requires it.</div>' 
		);
		html += get_form_table_spacer();
		
		// advanced options
		var adv_expanded = !!(plugin.cwd || plugin.uid);
		html += get_form_table_row( 'Advanced', 
			'<div style="font-size:13px;'+(adv_expanded ? 'display:none;' : '')+'"><span class="link addme" onMouseUp="$P().expand_fieldset($(this))"><i class="fa fa-plus-square-o">&nbsp;</i>Advanced Options</span></div>' + 
			'<fieldset style="padding:10px 10px 0 10px; margin-bottom:5px;'+(adv_expanded ? '' : 'display:none;')+'"><legend class="link addme" onMouseUp="$P().collapse_fieldset($(this))"><i class="fa fa-minus-square-o">&nbsp;</i>Advanced Options</legend>' + 
				'<div class="plugin_params_label">Working Directory (CWD):</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ep_cwd" size="50" value="'+escape_text_field_value(plugin.cwd)+'" placeholder="" spellcheck="false"/></div>' + 
				
				'<div class="plugin_params_label">Run as User (UID):</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ep_uid" size="20" value="'+escape_text_field_value(plugin.uid)+'" placeholder="" spellcheck="false"/></div>' + 
				
				'<div class="plugin_params_label">Run as Group (GID):</div>' + 
				'<div class="plugin_params_content"><input type="text" id="fe_ep_gid" size="20" value="'+escape_text_field_value(plugin.gid)+'" placeholder="" spellcheck="false"/></div>' + 
				
			'</fieldset>'
		);
		html += get_form_table_caption(
			"Optionally enter a working directory path, and/or a custom UID/GID for the Plugin.<br>" + 
			"The UID/GID may be either numerical or strings ('root', 'wheel', etc.)." 
		);
		html += get_form_table_spacer();
		
		return html;
	},
	
	stopEnter: function(item, e) {
		// prevent user from hitting enter in textarea
		var c = e.which ? e.which : e.keyCode;
		if (c == 13) {
			if (e.preventDefault) e.preventDefault();
			// setTimeout("document.getElementById('"+item.id+"').focus();",0);	
			return false;
		}
	},
	
	get_plugin_params_html: function() {
		// return HTML for editing plugin params
		var params = this.plugin.params;
		var html = '';
		var ctype_labels = this.ctype_labels;
		
		var cols = ['Param ID', 'Label', 'Control Type', 'Description', 'Actions'];
		
		html += '<table class="data_table" width="100%">';
		html += '<tr><th>' + cols.join('</th><th>').replace(/\s+/g, '&nbsp;') + '</th></tr>';
		for (var idx = 0, len = params.length; idx < len; idx++) {
			var param = params[idx];
			var actions = [
				'<span class="link" onMouseUp="$P().edit_plugin_param('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_plugin_param('+idx+')"><b>Delete</b></span>'
			];
			html += '<tr>';
			html += '<td><span class="link" style="font-family:monospace; font-weight:bold; white-space:nowrap;" onMouseUp="$P().edit_plugin_param('+idx+')"><i class="fa fa-cog">&nbsp;&nbsp;</i>' + param.id + '</span></td>';
			// html += '<td><span class="link" style="font-weight:bold" onMouseUp="$P().edit_plugin_param('+idx+')">' + param.title + '</span></td>';
			if (param.title) html += '<td><b>&ldquo;' + param.title + '&rdquo;</b></td>';
			else html += '<td>(n/a)</td>';
			
			html += '<td>' + ctype_labels[param.type] + '</td>';
			
			var pairs = [];
			switch (param.type) {
				case 'text':
					pairs.push([ 'Size', param.size ]);
					if ('value' in param) pairs.push([ 'Default', '&ldquo;' + param.value + '&rdquo;' ]);
				break;
				
				case 'textarea':
					pairs.push([ 'Rows', param.rows ]);
				break;
				
				case 'checkbox':
					pairs.push([ 'Default', param.value ? 'Checked' : 'Unchecked' ]);
				break;
				
				case 'hidden':
					pairs.push([ 'Value', '&ldquo;' + param.value + '&rdquo;' ]);
				break;
				
				case 'select':
					pairs.push([ 'Items', '(' + param.items.join(', ') + ')' ]);
					if ('value' in param) pairs.push([ 'Default', '&ldquo;' + param.value + '&rdquo;' ]);
				break;
			}
			for (var idy = 0, ley = pairs.length; idy < ley; idy++) {
				pairs[idy] = '<b>' + pairs[idy][0] + ':</b> ' + pairs[idy][1];
			}
			html += '<td>' + pairs.join(', ') + '</td>';
			
			html += '<td>' + actions.join(' | ') + '</td>';
			html += '</tr>';
		} // foreach param
		if (!params.length) {
			html += '<tr><td colspan="'+cols.length+'" align="center" style="padding-top:10px; padding-bottom:10px; font-weight:bold;">';
			html += 'No params found.';
			html += '</td></tr>';
		}
		html += '</table>';
		
		html += '<div class="button mini" style="width:110px; margin:10px 0 0 0" onMouseUp="$P().edit_plugin_param(-1)">Add Parameter...</div>';
		
		return html;
	},
	
	edit_plugin_param: function(idx) {
		// show dialog to edit or add plugin param
		var self = this;
		var param = (idx > -1) ? this.plugin.params[idx] : {
			id: "",
			type: "text",
			title: "",
			size: 20,
			value: ""
		};
		this.plugin_param = param;
		
		var edit = (idx > -1) ? true : false;
		var html = '';
		
		var ctype_labels = this.ctype_labels;
		var ctype_options = [
			['text', ctype_labels.text],
			['textarea', ctype_labels.textarea],
			['checkbox', ctype_labels.checkbox],
			['select', ctype_labels.select],
			['hidden', ctype_labels.hidden]
		];
		
		html += '<table>' + 
			get_form_table_row('Parameter ID:', '<input type="text" id="fe_epp_id" size="20" value="'+escape_text_field_value(param.id)+'"/>') + 
			get_form_table_caption("Enter an ID for the parameter, which will be the JSON key.") + 
			get_form_table_spacer() + 
			get_form_table_row('Label:', '<input type="text" id="fe_epp_title" size="35" value="'+escape_text_field_value(param.title)+'"/>') + 
			get_form_table_caption("Enter a label, which will be displayed next to the control.") + 
			// get_form_table_spacer() + 
			// get_form_table_row('Control Type:', '<select id="fe_epp_ctype" onChange="$P().change_plugin_control_type()">' + render_menu_options(ctype_options, param.type, false) + '</select>') + 
			// get_form_table_caption("Select the type of control you want to display.") + 
		'</table>';
		
		html += '<fieldset style="margin-top:20px;">';
			html += '<legend><table cellspacing="0" cellpadding="0"><tr><td>Control&nbsp;Type:&nbsp;</td><td><select id="fe_epp_ctype" onChange="$P().change_plugin_control_type()">' + render_menu_options(ctype_options, param.type, false) + '</select></td></tr></table></legend>';
			html += '<div id="d_epp_editor" style="margin:5px 10px 5px 10px;">' + this.get_plugin_param_editor_html() + '</div>';
		html += '</fieldset>';
		
		app.confirm( '<i class="fa fa-cog">&nbsp;&nbsp;</i>' + (edit ? "Edit Parameter" : "Add Parameter"), html, edit ? "OK" : "Add", function(result) {
			app.clearError();
			
			if (result) {
				param = self.get_plugin_param_values();
				if (!param) return;
				
				if (edit) {
					// edit existing
					self.plugin.params[idx] = param;
				}
				else {
					// add new, check for unique id
					if (find_object(self.plugin.params, { id: param.id })) {
						return add.badField('fe_epp_id', "That parameter ID is already taken.  Please enter a unique value.");
					}
					
					self.plugin.params.push( param );
				}
				
				Dialog.hide();
				
				// refresh param list
				self.refresh_plugin_params();
				
			} // user clicked add
		} ); // app.confirm
		
		if (!edit) setTimeout( function() {
			$('#fe_epp_id').focus();
		}, 1 );
	},
	
	get_plugin_param_editor_html: function() {
		// get html for editing one plugin param, new or edit
		var param = this.plugin_param;
		var html = '<table>';
		
		switch (param.type) {
			case 'text':
				html += get_form_table_row('Size:', '<input type="text" id="fe_epp_text_size" size="5" value="'+escape_text_field_value(param.size)+'"/>');
				html += get_form_table_caption("Enter the size of the text field, in characters.");
				html += get_form_table_spacer('short transparent');
				html += get_form_table_row('Default Value:', '<input type="text" id="fe_epp_text_value" size="35" value="'+escape_text_field_value(param.value)+'" spellcheck="false"/>');
				html += get_form_table_caption("Enter the default value for the text field.");
			break;
			
			case 'textarea':
				html += get_form_table_row('Rows:', '<input type="text" id="fe_epp_textarea_rows" size="5" value="'+escape_text_field_value(param.rows || 5)+'"/>');
				html += get_form_table_caption("Enter the number of visible rows to allocate for the text box.");
				html += get_form_table_spacer('short transparent');
				html += get_form_table_row('Default Text:', '<textarea id="fe_epp_textarea_value" style="width:99%; height:60px; resize:none;" spellcheck="false">'+escape_text_field_value(param.value)+'</textarea>');
				html += get_form_table_caption("Optionally enter default text for the text box.");
			break;
			
			case 'checkbox':
				html += get_form_table_row('Default State:', '<select id="fe_epp_checkbox_value">' + render_menu_options([[0,'Unchecked'], [1,'Checked']], param.value, false) + '</select>');
				html += get_form_table_caption("Select whether the checkbox should be initially checked or unchecked.");
			break;
			
			case 'hidden':
				html += get_form_table_row('Value:', '<input type="text" id="fe_epp_hidden_value" size="35" value="'+escape_text_field_value(param.value)+'" spellcheck="false"/>');
				html += get_form_table_caption("Enter the value for the hidden field.");
			break;
			
			case 'select':
				html += get_form_table_row('Menu Items:', '<input type="text" id="fe_epp_select_items" size="35" value="'+escape_text_field_value(param.items ? param.items.join(', ') : '')+'" spellcheck="false"/>');
				html += get_form_table_caption("Enter a comma-separated list of items for the menu.");
				html += get_form_table_spacer('short transparent');
				html += get_form_table_row('Selected Item:', '<input type="text" id="fe_epp_select_value" size="20" value="'+escape_text_field_value(param.value)+'" spellcheck="false"/>');
				html += get_form_table_caption("Optionally enter an item to be selected by default.");
			break;
		} // switch type
		
		html += '</table>';
		return html;
	},
	
	get_plugin_param_values: function() {
		// build up new 'param' object based on edit form (gen'ed from get_plugin_edit_controls())
		var param = { type: this.plugin_param.type };
		
		param.id = trim( $('#fe_epp_id').val() );
		if (!param.id) return app.badField('fe_epp_id', "Please enter an ID for the plugin parameter.");
		if (!param.id.match(/^\w+$/)) return app.badField('fe_epp_id', "The parameter ID needs to be alphanumeric.");
		
		param.title = trim( $('#fe_epp_title').val() );
		if ((param.type != 'hidden') && !param.title) return app.badField('fe_epp_title', "Please enter a label for the plugin parameter.");
		
		switch (param.type) {
			case 'text':
				param.size = trim( $('#fe_epp_text_size').val() );
				if (!param.size.match(/^\d+$/)) return app.badField('fe_epp_text_size', "Please enter a size for the text field.");
				param.size = parseInt( param.size );
				if (!param.size) return app.badField('fe_epp_text_size', "Please enter a size for the text field.");
				if (param.size > 40) return app.badField('fe_epp_text_size', "The text field size needs to be between 1 and 40 characters.");
				param.value = trim( $('#fe_epp_text_value').val() );
			break;
			
			case 'textarea':
				param.rows = trim( $('#fe_epp_textarea_rows').val() );
				if (!param.rows.match(/^\d+$/)) return app.badField('fe_epp_textarea_rows', "Please enter a number of rows for the text box.");
				param.rows = parseInt( param.rows );
				if (!param.rows) return app.badField('fe_epp_textarea_rows', "Please enter a number of rows for the text box.");
				if (param.rows > 50) return app.badField('fe_epp_textarea_rows', "The text box rows needs to be between 1 and 50.");
				param.value = trim( $('#fe_epp_textarea_value').val() );
			break;
			
			case 'checkbox':
				param.value = parseInt( trim( $('#fe_epp_checkbox_value').val() ) );
			break;
			
			case 'hidden':
				param.value = trim( $('#fe_epp_hidden_value').val() );
			break;
			
			case 'select':
				if (!$('#fe_epp_select_items').val().match(/\S/)) return app.badField('fe_epp_select_items', "Please enter a comma-separated list of items for the menu.");
				param.items = trim( $('#fe_epp_select_items').val() ).split(/\,\s*/);
				param.value = trim( $('#fe_epp_select_value').val() );
				if (param.value && !find_in_array(param.items, param.value)) return app.badField('fe_epp_select_value', "The default value you entered was not found in the list of menu items.");
			break;
		}
		
		return param;
	},
	
	change_plugin_control_type: function() {
		// change dialog to new control type
		// render, resize and reposition dialog
		var new_type = $('#fe_epp_ctype').val();
		this.plugin_param.type = new_type;
		
		$('#d_epp_editor').html( this.get_plugin_param_editor_html() );
		
		// Dialog.autoResize();
	},
	
	delete_plugin_param: function(idx) {
		// delete selected plugin param, but do not save
		// don't prompt either, giving a UX hint that save did not occur
		this.plugin.params.splice( idx, 1 );
		this.refresh_plugin_params();
	},
	
	refresh_plugin_params: function() {
		// redraw plugin param area after change
		$('#d_ep_params').html( this.get_plugin_params_html() );
	},
	
	get_plugin_form_json: function() {
		// get plugin elements from form, used for new or edit
		var plugin = this.plugin;
		
		plugin.title = trim( $('#fe_ep_title').val() );
		if (!plugin.title) return app.badField('fe_ep_title', "Please enter a title for the Plugin.");
		
		plugin.enabled = $('#fe_ep_enabled').is(':checked') ? 1 : 0;
		
		plugin.command = trim( $('#fe_ep_command').val() );
		if (!plugin.command) return app.badField('fe_ep_command', "Please enter a filesystem path to the executable command for the Plugin.");
		if (plugin.command.match(/[\n\r]/)) return app.badField('fe_ep_command', "You must not include any newlines (EOLs) in your command.  Please consider using the built-in Shell Plugin.");
		
		plugin.cwd = trim( $('#fe_ep_cwd').val() );
		plugin.uid = trim( $('#fe_ep_uid').val() );
		plugin.gid = trim( $('#fe_ep_gid').val() );
		
		if (plugin.uid.match(/^\d+$/)) plugin.uid = parseInt( plugin.uid );
		if (plugin.gid.match(/^\d+$/)) plugin.gid = parseInt( plugin.gid );
		
		return plugin;
	}
	
});

// Cronicle Admin Page -- Activity Log

Class.add( Page.Admin, {
	
	activity_types: {
		'^cat': '<i class="fa fa-folder-open-o">&nbsp;</i>Category',
		'^group': '<i class="mdi mdi-server-network">&nbsp;</i>Group',
		'^plugin': '<i class="fa fa-plug">&nbsp;</i>Plugin',
		// '^apikey': '<i class="fa fa-key">&nbsp;</i>API Key',	
		'^apikey': '<i class="mdi mdi-key-variant">&nbsp;</i>API Key',	
		'^event': '<i class="fa fa-clock-o">&nbsp;</i>Event',
		'^user': '<i class="fa fa-user">&nbsp;&nbsp;</i>User',
		'server': '<i class="mdi mdi-desktop-tower mdi-lg">&nbsp;</i>Server',
		'^job': '<i class="fa fa-pie-chart">&nbsp;</i>Job',
		'^state': '<i class="mdi mdi-calendar-clock">&nbsp;</i>Scheduler', // mdi-lg
		'^error': '<i class="fa fa-exclamation-triangle">&nbsp;</i>Error',
		'^warning': '<i class="fa fa-exclamation-circle">&nbsp;</i>Warning'
	},
	
	gosub_activity: function(args) {
		// show activity log
		app.setWindowTitle( "Activity Log" );
		
		if (!args.offset) args.offset = 0;
		if (!args.limit) args.limit = 25;
		app.api.post( 'app/get_activity', copy_object(args), this.receive_activity.bind(this) );
	},
	
	receive_activity: function(resp) {
		// receive page of activity from server, render it
		this.lastActivityResp = resp;
		
		var html = '';
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'activity',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		this.events = [];
		if (resp.rows) this.events = resp.rows;
		
		var cols = ['Date/Time', 'Type', 'Description', 'Username', 'IP Address', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'Activity Log';
			// html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getPaginatedTable( resp, cols, 'item', function(item, idx) {
			// figure out icon first
			if (!item.action) item.action = 'unknown';
			
			var item_type = '';
			for (var key in self.activity_types) {
				var regexp = new RegExp(key);
				if (item.action.match(regexp)) {
					item_type = self.activity_types[key];
					break;
				}
			}
			
			// compose nice description
			var desc = '';
			var actions = [];
			var color = '';
			var safe_text = function(text) {
				return encode_entities( (text == null) ? '' : '' + text );
			};
			var safe_url = function(text) {
				return encodeURIComponent( (text == null) ? '' : '' + text );
			};

			// Activity rows are assembled as HTML below, so encode user-provided text here.
			switch (item.action) {
				
				// categories
				case 'cat_create':
					desc = 'New category created: <b>' + safe_text(item.cat.title) + '</b>';
				break;
				case 'cat_update':
					desc = 'Category updated: <b>' + safe_text(item.cat.title) + '</b>';
				break;
				case 'cat_delete':
					desc = 'Category deleted: <b>' + safe_text(item.cat.title) + '</b>';
				break;
				
				// groups
				case 'group_create':
					desc = 'New server group created: <b>' + safe_text(item.group.title) + '</b>';
				break;
				case 'group_update':
					desc = 'Server group updated: <b>' + safe_text(item.group.title) + '</b>';
				break;
				case 'group_delete':
					desc = 'Server group deleted: <b>' + safe_text(item.group.title) + '</b>';
				break;
				
				// plugins
				case 'plugin_create':
					desc = 'New Plugin created: <b>' + safe_text(item.plugin.title) + '</b>';
				break;
				case 'plugin_update':
					desc = 'Plugin updated: <b>' + safe_text(item.plugin.title) + '</b>';
				break;
				case 'plugin_delete':
					desc = 'Plugin deleted: <b>' + safe_text(item.plugin.title) + '</b>';
				break;
				
				// api keys
				case 'apikey_create':
					desc = 'New API Key created: <b>' + safe_text(item.api_key.title) + '</b> (Key: ' + safe_text(item.api_key.key) + ')';
					actions.push( '<a href="#Admin?sub=edit_api_key&id='+safe_url(item.api_key.id)+'">Edit Key</a>' );
				break;
				case 'apikey_update':
					desc = 'API Key updated: <b>' + safe_text(item.api_key.title) + '</b> (Key: ' + safe_text(item.api_key.key) + ')';
					actions.push( '<a href="#Admin?sub=edit_api_key&id='+safe_url(item.api_key.id)+'">Edit Key</a>' );
				break;
				case 'apikey_delete':
					desc = 'API Key deleted: <b>' + safe_text(item.api_key.title) + '</b> (Key: ' + safe_text(item.api_key.key) + ')';
				break;
				
				// events
				case 'event_create':
					desc = 'New event added: <b>' + safe_text(item.event.title) + '</b>';
					desc += " (" + safe_text(summarize_event_timing(item.event.timing, item.event.timezone)) + ")";
					actions.push( '<a href="#Schedule?sub=edit_event&id='+safe_url(item.event.id)+'">Edit Event</a>' );
				break;
				case 'event_update':
					desc = 'Event updated: <b>' + safe_text(item.event.title) + '</b>';
					actions.push( '<a href="#Schedule?sub=edit_event&id='+safe_url(item.event.id)+'">Edit Event</a>' );
				break;
				case 'event_delete':
					desc = 'Event deleted: <b>' + safe_text(item.event.title) + '</b>';
				break;
				
				// users
				case 'user_create':
					desc = 'New user account created: <b>' + safe_text(item.user.username) + "</b> (" + safe_text(item.user.full_name) + ")";
					actions.push( '<a href="#Admin?sub=edit_user&username='+safe_url(item.user.username)+'">Edit User</a>' );
				break;
				case 'user_update':
					desc = 'User account updated: <b>' + safe_text(item.user.username) + "</b> (" + safe_text(item.user.full_name) + ")";
					actions.push( '<a href="#Admin?sub=edit_user&username='+safe_url(item.user.username)+'">Edit User</a>' );
				break;
				case 'user_delete':
					desc = 'User account deleted: <b>' + safe_text(item.user.username) + "</b> (" + safe_text(item.user.full_name) + ")";
				break;
				case 'user_login':
					desc = "User logged in: <b>" + safe_text(item.user.username) + "</b> (" + safe_text(item.user.full_name) + ")";
				break;
				
				// servers
				case 'add_server': // legacy
				case 'server_add': // current
					desc = 'Server '+(item.manual ? 'manually ' : '')+'added to cluster: <b>' + safe_text(item.hostname) + '</b>';
				break;
				case 'remove_server': // legacy
				case 'server_remove': // current
					desc = 'Server '+(item.manual ? 'manually ' : '')+'removed from cluster: <b>' + safe_text(item.hostname) + '</b>';
				break;
				case 'master_server': // legacy
				case 'server_master': // current
					desc = 'Server has become primary: <b>' + safe_text(item.hostname) + '</b>';
				break;
				
				case 'server_restart': 
					desc = 'Server restarted: <b>' + safe_text(item.hostname) + '</b>';
				break;
				case 'server_shutdown': 
					desc = 'Server shut down: <b>' + safe_text(item.hostname) + '</b>';
				break;
				
				case 'server_disable': 
					desc = 'Lost connectivity to server: <b>' + safe_text(item.hostname) + '</b>';
					color = 'yellow';
				break;
				case 'server_enable': 
					desc = 'Reconnected to server: <b>' + safe_text(item.hostname) + '</b>';
				break;
				
				// jobs
				case 'job_run':
					var event = find_object( app.schedule, { id: item.event } ) || { title: 'Unknown Event' };
					desc = 'Job <b>#'+safe_text(item.id)+'</b> ('+safe_text(event.title)+') manually started';
					actions.push( '<a href="#JobDetails?id='+safe_url(item.id)+'">Job Details</a>' );
				break;
				case 'job_complete':
					var event = find_object( app.schedule, { id: item.event } ) || { title: 'Unknown Event' };
					if (!item.code) {
						desc = 'Job <b>#'+safe_text(item.id)+'</b> ('+safe_text(event.title)+') on server <b>'+safe_text((item.hostname || '').replace(/\.[\w\-]+\.\w+$/, ''))+'</b> completed successfully';
					}
					else {
						desc = 'Job <b>#'+safe_text(item.id)+'</b> ('+safe_text(event.title)+') on server <b>'+safe_text((item.hostname || '').replace(/\.[\w\-]+\.\w+$/, ''))+'</b> failed with error: ' + safe_text(item.description || 'Unknown Error');
						if (desc.match(/\n/)) desc = desc.split(/\n/).shift() + "...";
						color = 'red';
					}
					actions.push( '<a href="#JobDetails?id='+safe_url(item.id)+'">Job Details</a>' );
				break;
				case 'job_delete':
					var event = find_object( app.schedule, { id: item.event } ) || { title: 'Unknown Event' };
					desc = 'Job <b>#'+safe_text(item.id)+'</b> ('+safe_text(event.title)+') manually deleted';
				break;
				
				// scheduler
				case 'state_update':
					desc = 'Scheduler was <b>' + (item.enabled ? 'enabled' : 'disabled') + '</b>';
				break;
				
				// errors
				case 'error':
					desc = safe_text( item.description );
					color = 'red';
				break;
				
				// warnings
				case 'warning':
					desc = safe_text( item.description );
					color = 'yellow';
				break;
				
			} // action
			
			var tds = [
				'<div style="white-space:nowrap;">' + get_nice_date_time( item.epoch || 0, false, true ) + '</div>',
				'<div class="td_big" style="white-space:nowrap; font-size:12px; font-weight:normal;">' + item_type + '</div>',
				'<div class="activity_desc">' + desc + '</div>',
				'<div style="white-space:nowrap;">' + self.getNiceUsername(item, true) + '</div>',
				(item.ip || 'n/a').replace(/^\:\:ffff\:(\d+\.\d+\.\d+\.\d+)$/, '$1'),
				'<div style="white-space:nowrap;">' + actions.join(' | ') + '</div>'
			];
			if (color) tds.className = color;
			
			return tds;
		} );
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	}
	
});

// Cronicle Admin Page -- API Keys

Class.add( Page.Admin, {
	
	gosub_api_keys: function(args) {
		// show API Key list
		app.setWindowTitle( "API Keys" );
		this.div.addClass('loading');
		app.api.post( 'app/get_api_keys', copy_object(args), this.receive_keys.bind(this) );
	},
	
	receive_keys: function(resp) {
		// receive all API Keys from server, render them sorted
		this.lastAPIKeysResp = resp;
		
		var html = '';
		this.div.removeClass('loading');
		
		var size = get_inner_window_size();
		var col_width = Math.floor( ((size.width * 0.9) + 200) / 7 );
		
		if (!resp.rows) resp.rows = [];
		
		// sort by title ascending
		this.api_keys = resp.rows.sort( function(a, b) {
			return a.title.toLowerCase().localeCompare( b.title.toLowerCase() );
		} );
		
		html += this.getSidebarTabs( 'api_keys',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		var cols = ['App Title', 'API Key', 'Status', 'Author', 'Created', 'Actions'];
		
		html += '<div style="padding:20px 20px 30px 20px">';
		
		html += '<div class="subtitle">';
			html += 'API Keys';
			html += '<div class="clear"></div>';
		html += '</div>';
		
		var self = this;
		html += this.getBasicTable( this.api_keys, cols, 'key', function(item, idx) {
			var actions = [
				'<span class="link" onMouseUp="$P().edit_api_key('+idx+')"><b>Edit</b></span>',
				'<span class="link" onMouseUp="$P().delete_api_key('+idx+')"><b>Delete</b></span>'
			];
			return [
				'<div class="td_big">' + self.getNiceAPIKey(item, true, col_width) + '</div>',
				'<div style="">' + encode_entities(item.key) + '</div>',
				item.active ? '<span class="color_label green"><i class="fa fa-check">&nbsp;</i>Active</span>' : '<span class="color_label red"><i class="fa fa-warning">&nbsp;</i>Suspended</span>',
				self.getNiceUsername(item.username, true, col_width),
				'<span title="'+get_nice_date_time(item.created, true)+'">'+get_nice_date(item.created, true)+'</span>',
				actions.join(' | ')
			];
		} );
		
		html += '<div style="height:30px;"></div>';
		html += '<center><table><tr>';
			html += '<td><div class="button" style="width:130px;" onMouseUp="$P().edit_api_key(-1)"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Add API Key...</div></td>';
		html += '</tr></table></center>';
		
		html += '</div>'; // padding
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	edit_api_key: function(idx) {
		// jump to edit sub
		if (idx > -1) Nav.go( '#Admin?sub=edit_api_key&id=' + this.api_keys[idx].id );
		else Nav.go( '#Admin?sub=new_api_key' );
	},
	
	delete_api_key: function(idx) {
		// delete key from search results
		this.api_key = this.api_keys[idx];
		this.show_delete_api_key_dialog();
	},
	
	gosub_new_api_key: function(args) {
		// create new API Key
		var html = '';
		app.setWindowTitle( "New API Key" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'new_api_key',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['new_api_key', "New API Key"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">New API Key</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center><table style="margin:0;">';
		
		this.api_key = { privileges: {}, key: get_unique_id() };
		
		html += this.get_api_key_edit_html();
		
		// buttons at bottom
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:120px; font-weight:normal;" onMouseUp="$P().cancel_api_key_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				
				html += '<td><div class="button" style="width:120px;" onMouseUp="$P().do_new_api_key()"><i class="fa fa-plus-circle">&nbsp;&nbsp;</i>Create Key</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table></center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
		
		setTimeout( function() {
			$('#fe_ak_title').focus();
		}, 1 );
	},
	
	cancel_api_key_edit: function() {
		// cancel editing API Key and return to list
		Nav.go( 'Admin?sub=api_keys' );
	},
	
	do_new_api_key: function(force) {
		// create new API Key
		app.clearError();
		var api_key = this.get_api_key_form_json();
		if (!api_key) return; // error
		
		if (!api_key.title.length) {
			return app.badField('#fe_ak_title', "Please enter an app title for the new API Key.");
		}
		
		this.api_key = api_key;
		
		app.showProgress( 1.0, "Creating API Key..." );
		app.api.post( 'app/create_api_key', api_key, this.new_api_key_finish.bind(this) );
	},
	
	new_api_key_finish: function(resp) {
		// new API Key created successfully
		app.hideProgress();
		
		Nav.go('Admin?sub=edit_api_key&id=' + resp.id);
		
		setTimeout( function() {
			app.showMessage('success', "The new API Key was created successfully.");
		}, 150 );
	},
	
	gosub_edit_api_key: function(args) {
		// edit API Key subpage
		this.div.addClass('loading');
		app.api.post( 'app/get_api_key', { id: args.id }, this.receive_key.bind(this) );
	},
	
	receive_key: function(resp) {
		// edit existing API Key
		var html = '';
		this.api_key = resp.api_key;
		
		app.setWindowTitle( "Editing API Key \"" + (this.api_key.title) + "\"" );
		this.div.removeClass('loading');
		
		html += this.getSidebarTabs( 'edit_api_key',
			[
				['activity', "Activity Log"],
				['api_keys', "API Keys"],
				['edit_api_key', "Edit API Key"],
				['categories', "Categories"],
				['plugins', "Plugins"],
				['servers', "Servers"],
				['users', "Users"]
			]
		);
		
		html += '<div style="padding:20px;"><div class="subtitle">Editing API Key &ldquo;' + (this.api_key.title) + '&rdquo;</div></div>';
		
		html += '<div style="padding:0px 20px 50px 20px">';
		html += '<center>';
		html += '<table style="margin:0;">';
		
		html += this.get_api_key_edit_html();
		
		html += '<tr><td colspan="2" align="center">';
			html += '<div style="height:30px;"></div>';
			
			html += '<table><tr>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().cancel_api_key_edit()">Cancel</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px; font-weight:normal;" onMouseUp="$P().show_delete_api_key_dialog()">Delete Key...</div></td>';
				html += '<td width="50">&nbsp;</td>';
				html += '<td><div class="button" style="width:130px;" onMouseUp="$P().do_save_api_key()"><i class="fa fa-floppy-o">&nbsp;&nbsp;</i>Save Changes</div></td>';
			html += '</tr></table>';
			
		html += '</td></tr>';
		
		html += '</table>';
		html += '</center>';
		html += '</div>'; // table wrapper div
		
		html += '</div>'; // sidebar tabs
		
		this.div.html( html );
	},
	
	do_save_api_key: function() {
		// save changes to api key
		app.clearError();
		var api_key = this.get_api_key_form_json();
		if (!api_key) return; // error
		
		this.api_key = api_key;
		
		app.showProgress( 1.0, "Saving API Key..." );
		app.api.post( 'app/update_api_key', api_key, this.save_api_key_finish.bind(this) );
	},
	
	save_api_key_finish: function(resp, tx) {
		// new API Key saved successfully
		app.hideProgress();
		app.showMessage('success', "The API Key was saved successfully.");
		window.scrollTo( 0, 0 );
	},
	
	show_delete_api_key_dialog: function() {
		// show dialog confirming api key delete action
		var self = this;
		app.confirm( '<span style="color:red">Delete API Key</span>', "Are you sure you want to <b>permanently delete</b> the API Key \""+this.api_key.title+"\"?  There is no way to undo this action.", 'Delete', function(result) {
			if (result) {
				app.showProgress( 1.0, "Deleting API Key..." );
				app.api.post( 'app/delete_api_key', self.api_key, self.delete_api_key_finish.bind(self) );
			}
		} );
	},
	
	delete_api_key_finish: function(resp, tx) {
		// finished deleting API Key
		var self = this;
		app.hideProgress();
		
		Nav.go('Admin?sub=api_keys', 'force');
		
		setTimeout( function() {
			app.showMessage('success', "The API Key '"+self.api_key.title+"' was deleted successfully.");
		}, 150 );
	},
	
	get_api_key_edit_html: function() {
		// get html for editing an API Key (or creating a new one)
		var html = '';
		var api_key = this.api_key;
		
		// API Key
		html += get_form_table_row( 'API Key', '<input type="text" id="fe_ak_key" size="35" value="'+escape_text_field_value(api_key.key)+'" spellcheck="false"/>&nbsp;<span class="link addme" onMouseUp="$P().generate_key()">&laquo; Generate Random</span>' );
		html += get_form_table_caption( "The API Key string is used to authenticate API calls." );
		html += get_form_table_spacer();
		
		// status
		html += get_form_table_row( 'Status', '<select id="fe_ak_status">' + render_menu_options([[1,'Active'], [0,'Disabled']], api_key.active) + '</select>' );
		html += get_form_table_caption( "'Disabled' means that the API Key remains in the system, but it cannot be used for any API calls." );
		html += get_form_table_spacer();
		
		// title
		html += get_form_table_row( 'App Title', '<input type="text" id="fe_ak_title" size="30" value="'+escape_text_field_value(api_key.title)+'" spellcheck="false"/>' );
		html += get_form_table_caption( "Enter the title of the application that will be using the API Key.");
		html += get_form_table_spacer();
		
		// description
		html += get_form_table_row('App Description', '<textarea id="fe_ak_desc" style="width:550px; height:50px; resize:vertical;">'+escape_text_field_value(api_key.description)+'</textarea>');
		html += get_form_table_caption( "Optionally enter a more detailed description of the application." );
		html += get_form_table_spacer();
		
		// privilege list
		var priv_html = '';
		for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
			var priv = config.privilege_list[idx];
			if (priv.id != 'admin') {
				var has_priv = !!api_key.privileges[ priv.id ];
				priv_html += '<div style="margin-top:4px; margin-bottom:4px;">';
				priv_html += '<input type="checkbox" id="fe_ak_priv_'+priv.id+'" value="1" '+(has_priv ? 'checked="checked"' : '')+'>';
				priv_html += '<label for="fe_ak_priv_'+priv.id+'">'+priv.title+'</label>';
				priv_html += '</div>';
			}
		}
		html += get_form_table_row( 'Privileges', priv_html );
		html += get_form_table_caption( "Select which privileges the API Key should have." );
		html += get_form_table_spacer();
		
		return html;
	},
	
	get_api_key_form_json: function() {
		// get api key elements from form, used for new or edit
		var api_key = this.api_key;
		
		api_key.key = $('#fe_ak_key').val();
		api_key.active = parseInt( $('#fe_ak_status').val() );
		api_key.title = $('#fe_ak_title').val();
		api_key.description = $('#fe_ak_desc').val();
		
		if (!api_key.key.length) {
			return app.badField('#fe_ak_key', "Please enter an API Key string, or generate a random one.");
		}
		
		for (var idx = 0, len = config.privilege_list.length; idx < len; idx++) {
			var priv = config.privilege_list[idx];
			api_key.privileges[ priv.id ] = $('#fe_ak_priv_'+priv.id).is(':checked') ? 1 : 0;
		}
		
		return api_key;
	},
	
	generate_key: function() {
		// generate random api key
		$('#fe_ak_key').val( get_unique_id() );
	}
	
});

