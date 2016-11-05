(function($) {
	$.fn.fadeUpdate = function(orig, time, background) {
		if (typeof background !== 'undefined') {
			this.css("background-color", "#0A0");
			this.animate({ 'background-color': orig }, time);
		} else {
			this.css('color', '#0A0');
			this.animate({ color: orig }, time);
		}
	}
})(jQuery);

function GetCookie(name)
{
	var value = "; " + document.cookie;
	var parts = value.split("; " + name + "=");
	if (parts.length == 2) return parts.pop().split(";").shift();
}

var origColors = [];

function WSTextChange(e, text, updateTime)
{
	console.log("WSTextChange " + e.text() + " -> " + text);
	if (e.text() == text) {
		console.log("WSTextChange DROP");
		return;
	}
	console.log("WSTextChange OK");
	e.text(text);
	for (var x = 0;x < origColors.length;x++) {
		if (origColors[x][0] == e) {
			e.fadeUpdate(origColors[x][1], updateTime);
			return;
		}
	}
	var color = e.css('color');
	origColors.push([e, color]);
	e.fadeUpdate(color, updateTime);
	console.log("pushed orig color " + color);
}

function getUint64(Bs, Offset) {
	return (Bs.getUint32(Offset) << 32) |
		Bs.getUint32(Offset + 4);
}

function IntToBin(Int, bytes) {
	var bin = "";
	for (var x = 0;x < bytes;x++) {
		var byte = Int & 0xff;
		bin += String.fromCharCode(byte);
		Int = (Int - byte) / 256;
	}
	
	return bin;
}

function ProxyTypeString(type) {
	switch (type) {
		case 1:
			return "HTTP";
		break;
		case 2:
			return "HTTPS";
		break;
		case 4:
			return "SOCKS4";
		break;
		case 8:
			return "SOCKS4A";
		break;
		case 16:
			return "SOCKS5";
		break;
		case 32:
			return "SOCKS4 -> SSL";
		break;
		case 64:
			return "SOCKS4A -> SSL";
		break;
		case 128:
			return "SOCKS5 -> SSL";
		break;
		case 256:
			return "SOCKS5 UDP";
		break;
	}
	return "N/A";
}

function ProxyAnonymityString(anon) {
	switch (anon) {
		case 0:
			return "N/A";
		break;
		case 1:
			return "Transparent";
		break;
		case 2:
			return "Anonymous";
		break;
		case 3:
			return "Max";
		break;
	}
	return "N/A ?";
}

function FormatTime(strUnixTimeMs) {
	var date = new Date(parseInt(strUnixTimeMs));
	return date.getFullYear() + "-" + date.getMonth() + "-" + date.getDate() + " " + date.getHours() + ":" + date.getMinutes() + ":" + date.getSeconds();
}

function IPParse(ipData, ipType) {
	var ip;
	if (ipType == 0x04) {
		var ipBs = new DataView(ipData);
		ip = ipBs.getUint8(0) + "." + ipBs.getUint8(1) + "." + ipBs.getUint8(2) + "." + ipBs.getUint8(3);
	} else {
		var ipv6 = "";
		var ipv6Map = new Int16Array(ipData);
		for (var x = 0;x < 8;x++)
			ipv6 += (x == 0 ? "" : ":") + ("000" + ipv6Map[x].toString(16)).slice(-4);
		var stage1 = ipv6.replace(/:0{1,3}/g, ":");
		var stage2 = stage1.match(/((:0){1,})/g);
		for (var x = 0, max = 0;x < stage2.length;x++) {
			if (stage2[x].length > max) {
				max = stage2[x].length;
				ip = stage2[x];
			}
		}
		ip = stage1.replace(max, ":");
	}
	return ip;
}

var wsAuthed = false;
var wsConn;

function WSInitialize(subscriptions, cookieName, fxMessage)
{
	wsConn = new WebSocket((location.protocol == 'http:' ? 'ws:' : 'wss:')+'//'+(location.hostname+(location.port ? ':'+location.port: ''))+'/wsn');
	wsConn.binaryType = 'arraybuffer';
	
	wsConn.onopen = function() {
		console.log("auth send");
		wsConn.send(IntToBin(subscriptions, 4) + GetCookie(cookieName), { binary: true });
	};
	
	wsConn.onmessage = function(e) {
		var bs = new DataView(e.data);
		if (!wsAuthed) {
			var answer = bs.getUint8(0);
			if (answer != 0x01) {
				if (answer == 0x01)
					alert("Wrong websocket authentication token");
				else if (answer == 0x02)
					alert("Websocket already authenticated");
				else
					alert("Something happened"); // This should not happen!
			
			} else
				wsAuthed = true;
			return;
		}
		
		fxMessage(bs.getUint32(0), e.data.slice(4, e.data.length));
	};
} 

/*function WSPull(subscription) {
	wsConn.send('P' + IntToBin(subscription, 4), { binary: true });
}*/
