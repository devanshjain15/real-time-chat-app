import net from "net";
import crypto from "crypto";

function computeAcceptKey(secWebSocketKey: string): string {
  // concatenate the client's key with the magic string
  const magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const combined = secWebSocketKey.concat(magicString);
  // compute the SHA-1 hash of the combined string and encode it in base64
  const acceptKey = crypto.createHash("sha1").update(combined).digest("base64");

  return acceptKey;
}

let server = net.createServer((socket) => {
  socket.on("data", (buffer) => {
    let request = buffer.toString();
    let upgrade = false;
    let secWebSocketKey: string | null = null;
    for (const line of request.split(/\r?\n/)) {
      let [key, value] = line.split(":");
      if (key && key == "Upgrade" && value && value.trim() == "websocket") {
        upgrade = true;
      }

      if (key == "Sec-WebSocket-Key") {
        secWebSocketKey = value.trim();
      }
    }

    if (upgrade && secWebSocketKey) {
      let acceptKey = computeAcceptKey(secWebSocketKey);
      let response = `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey}\r\n\r\n`;
      console.log("sending switching protocols response");
      socket.write(response);
    } else {
      // bad request, close the connection
      socket.end();
    }
  });

  socket.on("end", () => {
    console.log("Client disconnected");
  });
});

server.listen(8000, () => {
  console.log("Server is up at http://localhost:8000");
});
