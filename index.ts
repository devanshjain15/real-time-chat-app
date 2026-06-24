import net from "net";
import crypto from "crypto";

let connections: Set<net.Socket> = new Set();
let clients: Map<net.Socket, string> = new Map();

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
  // parsing logic
  let offset = 0;

  const byte0 = buffer.readUInt8(offset);
  const opcode = buffer.readUInt8(offset) & 0x0f;
  offset += 1;

  const byte1 = buffer.readUInt8(offset);
  const masked = (byte1 & 0x80) !== 0;
  let payloadLength = byte1 & 0x7f;
  offset += 1;

  if (payloadLength === 0x7e) {
    payloadLength = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (payloadLength === 0x7f) {
    payloadLength = Number(buffer.readBigUInt64BE(offset));
    offset += 8;
  }

  let payloadBuffer = Buffer.alloc(payloadLength);
  if (masked && payloadLength !== 0x00) {
    let maskingKey = buffer.subarray(offset, offset + 4);
    offset += 4;
    for (let i = 0; i < payloadLength; i++) {
      let byte = buffer.readUInt8(offset + i);
      payloadBuffer[i] = byte ^ maskingKey[i % 4];
    }
  }

  return {
    opcode,
    payloadBuffer,
  };
}

function buildFrame(opcode: number, payloadBuffer: Buffer): Buffer {
  let byte1 = (0x80 & 0xf0) | (opcode & 0x0f);
  let payloadBufferLength = payloadBuffer.length;
  let payloadLength = 0;
  let extendedPayloadLength = Buffer.alloc(0);
  if (payloadBufferLength < 126) {
    payloadLength = payloadBufferLength;
  } else if (payloadBufferLength >= 126 && payloadBufferLength <= 65535) {
    payloadLength = 126;
    extendedPayloadLength = Buffer.alloc(2);
    extendedPayloadLength.writeUInt16BE(payloadBufferLength, 0);
  } else if (payloadBufferLength > 65535) {
    payloadLength = 127;
    extendedPayloadLength = Buffer.alloc(8);
    extendedPayloadLength.writeBigUInt64BE(BigInt(payloadBufferLength), 0);
  }

  let byte2 = payloadLength & 0x7f;

  return Buffer.concat([
    Buffer.from([byte1, byte2]),
    extendedPayloadLength,
    payloadBuffer,
  ]);
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
      socket.write(response);

      connections.add(socket);
      let isAuthenticated = false;
      console.log(`Hanhshake Complete!`);

      socket.on("data", (buffer: Buffer) => {
        // parsing recieved frame
        let { opcode, payloadBuffer } = parseFrame(buffer);

        // handling based on different opcode
        if (!opcode) return;

        if (opcode == 0x8) {
          socket.write(buildFrame(opcode, payloadBuffer));
          socket.end();
          return;
        } else if (opcode == 0x9) {
          socket.write(buildFrame(0xa, payloadBuffer));
          return;
        }

        let payloadJson = JSON.parse(payloadBuffer.toString());
        if (!isAuthenticated) {
          if (payloadJson.type === "message") {
            // send error frame
          }
          if (!clients.has(socket)) {
            clients.set(socket, payloadJson.username);
            isAuthenticated = true;
          } else {
            // send error frame because already authenicateds
          }
          return;
        }



        let username = clients.get(socket);
        if (payloadJson.type !== "message" || !username) return; // this should also return the error frame as this should not be possible

        let frame: Buffer = buildFrame(
          opcode,
          Buffer.from(JSON.stringify({ username, text: payloadJson.text })),
        );

        connections.forEach((conn) => {
          if (conn !== socket) {
            conn.write(frame);
          }
        });
      });
    } else {
      // not ws handshake
      socket.end(() => {
        if (connections.has(socket)) {
          connections.delete(socket);
          if (clients.has(socket)) {
            clients.delete(socket);
          }
        }
      });
    }
  });

  socket.on("end", () => {
    connections.delete(socket);
    if (clients.has(socket)) {
      clients.delete(socket);
    }
    console.log("Connection closed!");
  });

  socket.on("error", (err) => {
    connections.delete(socket);
    if (clients.has(socket)) {
      clients.delete(socket);
    }
    console.log("Socket error:", err.message);
  });
});

server.listen(8000, () => {
  console.log("Server is up at 127.0.0.1:8000");
});
