var dgram = require('dgram');
var net = require('net');
var readline = require('readline');
var NodeRSA = require('node-rsa');
var readline = require('readline');
var crypto = require('crypto');

var fs = require('fs');

var settings = JSON.parse(fs.readFileSync('settings.json', 'utf8'));

var privateKey = new NodeRSA(settings.privatekey);

var remoteName = process.argv[2];
var clientName = "";
var rendezvous = {
	address: settings.serverip,
	port: settings.serverport
};

var client = {
	ack: false,
	connection: {}
};

var settings = {
	serverPublic: "",
	userPublic: "",
	linfo: {}
}

var udp_in = dgram.createSocket('udp4');

var getNetworkIP = function(callback) {
	var socket = net.createConnection(80, rendezvous.address);
	socket.on('connect', function() {
		callback(undefined, socket.address().address);
			socket.end();
	});
	socket.on('error', function(e) {
		callback(e, 'error');
	});
}

var send = function(connection, msg, cb) {
	var data = new Buffer(JSON.stringify(msg));

	udp_in.send(data, 0, data.length, connection.port, connection.address, function(err, bytes) {
		if (err) {
			udp_in.close();
			console.log('# stopped due to error: %s', err);
		} else {
			//console.log('# sent %s to %s:%s', msg.type, connection.address, connection.port);
			if (cb) cb();
		}
	});
}

function login(username, _callback){
	var signature = privateKey.sign(username, 'base64');
	var usernameEncrypted = settings.serverPublic.encrypt(username, "BASE64");
	_callback({type: "login", signature: signature, username: usernameEncrypted});
}

function encryptMessage(message, _callback){
	var hash = crypto.createHash('md5').update(message).digest('hex');
    var hash = privateKey.sign(hash, 'base64');
    var message = client.userPublic.encrypt(message, "BASE64");
    _callback({
    	type: "message",
    	hash: hash,
    	message: message,
    	from: clientName
    });
}

function decryptMessage(data, _callback){
	var message = privateKey.decrypt(data.message, 'utf8');
	var hash = crypto.createHash('md5').update(message).digest('hex');
	if(client.userPublic.verify(hash, new Buffer.from(JSON.stringify(data.hash), 'base64'))){
		_callback(message);
	} else {
		console.log("Could not verify message");
	}
}

function enableChat(){
    var rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
  	rl.on('line', (input) => {
		encryptMessage(input, function(message){
			send(client.connection, message);
		});
	});
}

udp_in.on("listening", function() {
	var linfo = { port: udp_in.address().port };
	settings.linfo = linfo;
	getNetworkIP(function(error, ip) {
		if (error) return console.log("! Unable to obtain connection information!");
		linfo.address = ip;
		console.log('# listening %s:%s', linfo.address, linfo.port);
		send(rendezvous, {type: 'getpub'});
	});
});

udp_in.on('message', function(data, rinfo) {
	try {
		data = JSON.parse(data);
	} catch (e) {
		console.log('! Couldn\'t parse data(%s):\n%s', e, data);
		return;
	}
	if (data.type == "pubkey"){
		settings.serverPublic = new NodeRSA(data.key);

		const rl = readline.createInterface({
		  	input: process.stdin,
		  	output: process.stdout
		});

		rl.question('Please enter your username: ', function(username){
			clientName = username;
			login(username, function(message){
				message.linfo = settings.linfo;
				message.to = remoteName,
				send(rendezvous, message);
		  		rl.close();
			});
		});
	} if (data.type == 'connection') {
		console.log('# connecting with %s@[%s:%s | %s:%s]', data.client.name, data.client.connections.local.address, data.client.connections.local.port, data.client.connections.public.address, data.client.connections.public.port);
		remoteName = data.client.name;
		client.userPublic = new NodeRSA(data.userKey);
		var punch = { type: 'punch', from: clientName, to: remoteName };
		for (var con in data.client.connections) {
			doUntilAck(1000, function() {
				send(data.client.connections[con], punch);
			});
		}
	} else if (data.type == 'punch' && data.to == clientName) {
		var ack = { type: 'ack', from: clientName };
		console.log("# got punch, sending ACK");
		send(rinfo, ack);
	} else if (data.type == 'ack' && !client.ack) {
		client.ack = true;
		client.connection = rinfo;
		console.log("# got ACK, sending MSG");
		send(client.connection, {
			type: 'message',
			from: clientName,
			msg: 'Connected with, ' + clientName + '!'
		});
		enableChat();
	} else if (data.type == 'message') {
		if(data.hash){
			decryptMessage(data, function(message){
				console.log('> %s: %s', data.from, message);
			});
		} else {
			console.log('> %s: %s', data.from, data.msg);
		}
	}
});


var doUntilAck = function(interval, fn) {
	if (client.ack) return;
	fn();
	setTimeout(function() {
		doUntilAck(interval, fn);
	}, interval);
}

udp_in.bind();
