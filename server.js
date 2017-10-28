var dgram = require('dgram');
var NodeRSA = require('node-rsa');
var jsonfile = require('jsonfile');
var mysql = require('mysql');
var fs = require('fs');

var serverSettings = JSON.parse(fs.readFileSync('serverSettings.json', 'utf8'));

const EventEmitter = require('events');

var udp_port = serverSettings.port;

var clients = {};

class Key extends EventEmitter {
	constructor() {
		super();
		this.private;
		this.public;
		this.getKey();
	}

	getKey() {
		var thus = this;
		jsonfile.readFile("key.json", function(err, obj) {
			if(obj == undefined){
				thus.generateKey();
			} else {
				thus.private = new NodeRSA(obj.private);
				thus.public = obj.public;
			}
			console.log("[+] Imported keypair");
			thus.emit("done");
		});
	}

	saveKey() {
		jsonfile.writeFile("key.json", {"private": this.privatePlain, "public": this.public}, function(err){
			console.log("[+] Keys saved");
		});
	}

	generateKey(){
		console.log("[*] Generating key pair");
		var key = new NodeRSA({b: 2048});
		this.privatePlain = key.exportKey("private");
		this.private = new NodeRSA(key.exportKey("private"));
		this.public = key.exportKey("public");
		this.saveKey();
	}
}

function getPubkey(user, _callback){
	var con = mysql.createConnection({
		host: serverSettings.mysql.host,
		user: serverSettings.mysql.user,
		password: serverSettings.mysql.password,
		database: serverSettings.mysql.database
	});

	con.connect(function(err) {
		if (err) throw err;
		con.query("SELECT pubkey FROM users WHERE username = '" + user + "'", function (err, result, fields) {
			if (err) throw err;
			var key = NodeRSA(result[0].pubkey);
			_callback(key);
		});
	});
}

function setupListening(){
	var udp_matchmaker = dgram.createSocket('udp4');

	udp_matchmaker.on('listening', function() {
		var address = udp_matchmaker.address();
		console.log('# listening [%s:%s]', address.address, address.port);
	});

	udp_matchmaker.on('message', function(data, rinfo) {
		try {
			data = JSON.parse(data);
		} catch (e) {
			return console.log('! Couldn\'t parse data (%s):\n%s', e, data);
		}
		if(data.type == "getpub"){
			send(rinfo.address, rinfo.port, {
				type: "pubkey",
				key: key.public
			});
		} else if (data.type == "login"){
			var username = key.private.decrypt(data.username, 'utf8');
			 getPubkey(username, function(key){
				if(key.verify(username, new Buffer.from(JSON.stringify(data.signature), 'base64'))){
					console.log("verified");
					clients[username] = {
							name: username,
							connections: {
								local: data.linfo,
								public: rinfo
							}
					};

					getPubkey(data.to, function(userKey){
						var couple = [ clients[username], clients[data.to] ]
						for (var i=0; i<couple.length; i++) {
							if (!couple[i]) return console.log('Client unknown!');
						}

						for (var i=0; i<couple.length; i++) {
							send(couple[i].connections.public.address, couple[i].connections.public.port, {
								type: 'connection',
								userKey: userKey.exportKey("public"),
								client: couple[(i+1)%couple.length],
							});
						}
					});

				} else {
					console.log("no acces");
				}
			});
		} else if (data.type == 'register') {
			clients[data.name] = {
					name: data.name,
					connections: {
						local: data.linfo,
						public: rinfo
					}
			};
			console.log('# Client registered: %s@[%s:%s | %s:%s]', data.name, rinfo.address, rinfo.port, data.linfo.address, data.linfo.port);
		} else if (data.type == 'connect') {
			var couple = [ clients[data.from], clients[data.to] ]
			for (var i=0; i<couple.length; i++) {
				if (!couple[i]) return console.log('Client unknown!');
			}

			for (var i=0; i<couple.length; i++) {
				send(couple[i].connections.public.address, couple[i].connections.public.port, {
					type: 'connection',
					client: couple[(i+1)%couple.length],
				});
			}
		}
	});

	var send = function(host, port, msg, cb) {
		var data = new Buffer(JSON.stringify(msg));
		udp_matchmaker.send(data, 0, data.length, port, host, function(err, bytes) {
			if (err) {
				udp_matchmaker.close();
				console.log('# stopped due to error: %s', err);
			} else {
				console.log('# sent '+msg.type);
				if (cb) cb();
			}
		});
	}

	udp_matchmaker.bind(udp_port);
}

var key = new Key();

key.on("done", function(){
	setupListening();
});
