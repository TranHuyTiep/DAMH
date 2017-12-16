var socket = require('socket.io')
var mqtt = require('mqtt')
var sodium = require('libsodium-wrappers');

var io
var client1 = null
var url_client1_publicKey = 'chat/client1/publicKey'
var url_client1_publicKey_massage2 = 'chat/client1/publicKey/massage2'
var url_client1_message = 'chat/client1/message'
var client2 = null
var url_client2_publicKey = 'chat/client2/publicKey'
var url_client2_message = 'chat/client2/message'
var url_client2_publicKey_massage2 = 'chat/client2/publicKey/massage2'

var client  = mqtt.connect('mqtt://test.mosquitto.org')

client.on('connect', function () {
    client.subscribe(url_client1_publicKey)
    client.subscribe(url_client1_message)
    client.subscribe(url_client1_publicKey_massage2)
})

client.on('message', function (topic, message) {
    // message is Buffer
    if(topic===url_client1_publicKey){
        client1 = message.toString()
    }
})


/**
 * get message
 * @returns {Promise}
 */
function get_message(){
    return new Promise(function (fulfill, reject){
        client.on('message', function (topic, message) {
            // message is Buffer
            if(topic==='chat/client1/publicKey'){
                fulfill = message.toString()
            }
        })
    });
}

/**
 * creater server socket
 * @param http
 */
function startSocketServer(http) {
    io = require('socket.io')(http);
    waitConnection(io)
}


/**
 * lang nghe connect
 * @param io
 */
function waitConnection(io) {
    io.on('connection',function (socket) {
        console.log('user connect');
        hardleSocket(socket);
    })
}


/**
 * su ly socket
 * @param socket
 */
function hardleSocket(socket) {
   // gui message tu Ia toi client
   socket.on('html_send',function (msg,err) {
       if(msg){
           client.publish(url_client2_message, msg, qos=2)
       }
   })
    //gui publicKey tu Ia toi client
    //va gui nguoc lai public key Ib cho Ia
    socket.on('html_publickey',function (msg,err) {
        client2 = msg
        client.publish(url_client2_publicKey,msg)
        if(client1!=null){
            socket.emit('py_send_publicKey',client1, qos=2)
        }
    })

    socket.on('massage2',function (msg,err) {
        // massage2 = msg
        client.publish(url_client2_publicKey_massage2,msg)
        
    })

    client.on('message', function (topic, message) {
        if(client2&&topic===url_client1_publicKey_massage2){
            socket.emit('publicKey_massage2',message.toString(), qos=2)
        }else if(topic===url_client1_message) {
            var mes = message.toString()
            socket.emit('py_send',mes)
        }
    })

    disconnection(socket)
}


/**
 * lang nghe disconnect
 * @param socket
 * @param name
 */
function disconnection(socket) {
    socket.on('disconnect', function(){

        console.log('user disconnected');
    });
}

exports.startSocketServer = startSocketServer
