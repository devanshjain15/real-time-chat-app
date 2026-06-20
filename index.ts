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

function parseFrame(buffer: Buffer): string {
  let opcode = "";
  let payloadLength = 0;
  let maskingKey = Buffer.alloc(4);
  let payloadData = Buffer.alloc(0);
  buffer.forEach((byte, i) => {
    if (i == 0) {
      opcode = byte.toString(2).padStart(8, "0").slice(4);
    } else if (i == 1) {
      payloadLength = parseInt(byte.toString(2).padStart(8, "0").slice(1), 2);
    } else if (i >= 2 && i < 6) {
      maskingKey[i - 2] = byte;
    }

    if (i >= 6 && payloadLength == 0) {
      return;
    } else if (i >= 6 && payloadLength > 0) {
      let maskedByte = byte;
      let unmaskedByte = maskedByte ^ maskingKey[(i - 6) % 4];
      payloadData = Buffer.concat([payloadData, Buffer.from([unmaskedByte])]);
    }
  });

  return payloadData.toString();
}

let server = net.createServer((socket) => {
  socket.once("data", (buffer: Buffer) => {
    // http request
    let request = buffer.toString();
    let upgrade = false;
    let secWebSocketKey: string | null = null;
    // checking for Upgrade to ws header
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
      // sending http response with 101 switching protocol
      let acceptKey = computeAcceptKey(secWebSocketKey);
      let response = `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey}\r\n\r\n`;
      console.log(`Hanhshake Complete!`);
      socket.write(response);
      socket.on("data", (buffer: Buffer) => {
        let payloadData = parseFrame(buffer);
        console.log(payloadData);
      });
    } else {
      // not ws handshake
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
