(function($) {
	$.fn.fadeUpdate = function(orig, time) {
		this.animate({ color: "#0A0" }, 1).animate({ color: orig }, time);
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
	e.fadeUpdate(e.css('color'), updateTime);
	origColors.push([e, e.css('color')]);
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

function WSPull(subscription, current) {
	wsConn.send('P' + IntToBin(subscription, 4) + current, { binary: true });
}
