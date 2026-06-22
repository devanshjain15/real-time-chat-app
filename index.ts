import net from "net";
import crypto from "crypto";

let clients: Set<net.Socket> = new Set();

function computeAcceptKey(secWebSocketKey: string): string {
  // concatenate the client's key with the magic string
  const magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const combined = secWebSocketKey.concat(magicString);
  // compute the SHA-1 hash of the combined string and encode it in base64
  const acceptKey = crypto.createHash("sha1").update(combined).digest("base64");

  return acceptKey;
}

interface Frame {
  opcode: number | null;
  payloadBuffer: Buffer;
}

function parseFrame(buffer: Buffer): Frame {
  let opcode: number | null = null;
  let payloadLength = 0x0;
  let maskingKey = Buffer.alloc(4);
  let payloadBuffer = Buffer.alloc(0);

  // parsing logic
  buffer.forEach((byte, i) => {
    if (i === 0) {
      opcode = byte & 0x0f;
    } else if (i === 1) {
      payloadLength = byte & 0x7f;
      payloadBuffer = Buffer.alloc(payloadLength);
    } else if (i >= 2 && i < 6) {
      maskingKey[i - 2] = byte;
    }
    if (i >= 6 && payloadLength === 0x0) {
      return;
    } else if (i >= 6 && payloadLength > 0) {
      payloadBuffer[i - 6] = byte ^ maskingKey[(i - 6) % 4];
    }
  });

  return {
    opcode,
    payloadBuffer,
  };
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
      clients.add(socket);

      socket.on("data", (buffer: Buffer) => {
        // parsing recieved frame
        let { opcode, payloadBuffer } = parseFrame(buffer);
        let payloadLength = payloadBuffer.length;

        // handling based on different opcode
        if (!opcode) return;
        
        if (opcode == 0x8) { 
          let frame = Buffer.concat([
            Buffer.from([0x88, payloadLength & 0x7F]),
            payloadBuffer,
          ]);
          socket.write(frame);
          socket.end();
          return; 
        } else if (opcode == 0x9) {
          let frame = Buffer.concat([
            Buffer.from([0x8a, payloadLength & 0x7F]),
            payloadBuffer,
          ]);
          socket.write(frame);
          return;
        } 
        
        let frame: Buffer = Buffer.concat([
          Buffer.from([(0x80 & 0xf0) | (opcode & 0x0f), payloadLength & 0x7F]),
          payloadBuffer,
        ]);

        clients.forEach((client) => {
          if (client !== socket) {
            client.write(frame);
          }
        });
      });
    } else {
      // not ws handshake
      socket.end(() => {
        if (clients.has(socket)) {
          clients.delete(socket);
        }
      });
    }
  });

  socket.on("end", () => {
    clients.delete(socket);
    console.log("Connection closed!");
  });

  socket.on("error", (err) => {
    clients.delete(socket);
    console.log("Socket error:", err.message);
  });
});

server.listen(8000, () => {
  console.log("Server is up at http://localhost:8000");
});
