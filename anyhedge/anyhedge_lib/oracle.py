import asyncio
import json 
import zmq.asyncio

from async_timeout import timeout

# Handles the network call to General Protocols for the oracle price request.
class OracleRequester:
    PORT_REQUEST = 12345  # Default port
    DEFAULT_SEND_TIMEOUT = 5000  # 5 seconds, in milliseconds
    DEFAULT_RECEIVE_TIMEOUT = 5000  # 5 seconds, in milliseconds
    request_lock = asyncio.Lock()  # Mutex lock for requests
    request_sockets = {}  # Cache for socket connections

    @staticmethod
    def get_socket_url(address, port):
        return f"tcp://{address}:{port}"

    @staticmethod
    async def request(content, address, port=PORT_REQUEST, send_timeout=DEFAULT_SEND_TIMEOUT, receive_timeout=DEFAULT_RECEIVE_TIMEOUT):
        async with OracleRequester.request_lock:  # Ensure one request at a time
            ctx = zmq.asyncio.Context.instance()
            socket_url = OracleRequester.get_socket_url(address, port)
           
            if socket_url not in OracleRequester.request_sockets:
                OracleRequester.request_sockets[socket_url] = ctx.socket(zmq.REQ)
                OracleRequester.request_sockets[socket_url].setsockopt(zmq.RCVTIMEO, receive_timeout)
                OracleRequester.request_sockets[socket_url].setsockopt(zmq.SNDTIMEO, send_timeout)
                OracleRequester.request_sockets[socket_url].connect(socket_url)
            try:
                await OracleRequester.request_sockets[socket_url].send_json(content)
                with timeout(receive_timeout / 3000):  
                    response = await OracleRequester.request_sockets[socket_url].recv_json()
                return response
            except Exception as e:
                print(f"Failed to get/send a response for request sent to {address}:{port}. Error: {str(e)}")
                OracleRequester.request_sockets[socket_url].close()
                del OracleRequester.request_sockets[socket_url]
                return None

