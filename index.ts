import net from "net";
import crypto from "crypto";
import { createClient } from "redis";

type RoomId = string;

interface Connection {
  username: string;
  roomId: RoomId;
}

enum PayloadType {
  "JOIN",
  "CHANGE",
  "MESSAGE",
}

interface Payload {
  type: PayloadType;
  message?: string;
  username?: string;
  roomId?: string;
}

interface Frame {
  opcode: number | null;
  payloadBuffer: Buffer;
}

let rooms: Map<RoomId, Set<net.Socket>> = new Map();
let clients: Map<net.Socket, Connection> = new Map();

let publisher = createClient();
let subscriber = createClient();

async function main() {
  await publisher.connect();
  await subscriber.connect();

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

        let isAuthenticated = false;
        console.log(`Hanhshake Complete!`);

        socket.on("data", async (buffer: Buffer) => {
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

          let payloadJson: Payload = JSON.parse(payloadBuffer.toString());
          if (!isAuthenticated) {
            if (
              payloadJson.type === PayloadType.MESSAGE ||
              payloadJson.type === PayloadType.CHANGE
            ) {
              // send error frame
              return;
            }
            if (
              !clients.has(socket) &&
              payloadJson.username &&
              payloadJson.roomId
            ) {
              let { username, roomId } = payloadJson;
              ensureRoomSubscribed(roomId);
              rooms.get(roomId)?.add(socket);
              clients.set(socket, {
                username,
                roomId,
              });
              isAuthenticated = true;

              // send username joined message to every other client in that room!
              sendJoinMessage(socket);
            } else {
              // send error frame because already authenicateds
              return;
            }
            return;
          }

          let conn = clients.get(socket);
          if (payloadJson.type === PayloadType.JOIN || !conn) return; // this should also return the error frame as this should not be possible

          if (payloadJson.type === PayloadType.CHANGE) {
            changeRoom(socket, payloadJson.roomId as RoomId);
          } else if (payloadJson.type === PayloadType.MESSAGE) {
            let frame: Buffer = buildFrame(
              opcode,
              Buffer.from(
                JSON.stringify({
                  username: conn.username,
                  message: payloadJson.message,
                }),
              ),
            );
            // let roomId = clients.get(socket)?.roomId;

            await publisher.publish(
              conn.roomId,
              JSON.stringify({ socketId: "", frame: frame.toString("base64") }),
            );
          }
        });
      } else {
        // not ws handshake
        socket.end(() => {
          const connection = clients.get(socket);
          if (connection) {
            removeFromRoom(socket);
            clients.delete(socket);
          }
        });
      }
    });

    socket.on("end", () => {
      const connection = clients.get(socket);
      if (connection) {
        removeFromRoom(socket);
        clients.delete(socket);
      }
      console.log("Connection closed!");
    });

    socket.on("error", (err) => {
      const connection = clients.get(socket);
      if (connection) {
        removeFromRoom(socket);
        clients.delete(socket);
      }
      console.log("Socket error:", err.message);
    });
  });

  const PORT = process.argv[2];
  server.listen(PORT, () => {
    console.log(`Server is up at 127.0.0.1:${PORT}`);
  });
}

function computeAcceptKey(secWebSocketKey: string): string {
  // concatenate the client's key with the magic string
  const magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const combined = secWebSocketKey.concat(magicString);
  // compute the SHA-1 hash of the combined string and encode it in base64
  const acceptKey = crypto.createHash("sha1").update(combined).digest("base64");

  return acceptKey;
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

function changeRoom(socket: net.Socket, newRoomId: RoomId) {
  if (
    rooms.get(newRoomId)?.has(socket) ||
    clients.get(socket)?.roomId === newRoomId
  )
    // already in that room
    return;

  let connection = clients.get(socket);
  // checking if client exists or not
  if (!connection) return;

  removeFromRoom(socket);
  connection.roomId = newRoomId;
  ensureRoomSubscribed(newRoomId);
  let room = rooms.get(newRoomId);
  if (!room) return;
  room.add(socket);

  sendJoinMessage(socket);
}

async function sendJoinMessage(socket: net.Socket) {
  let conn = clients.get(socket);
  if (!conn) return;
  let frame = buildFrame(0x1, Buffer.from(`${conn.username} joined the chat!`));
  await publisher.publish(
    conn.roomId,
    JSON.stringify({ socketId: "", frame: frame.toString("base64") }),
  );
}

function removeFromRoom(socket: net.Socket) {
  let connection = clients.get(socket);
  if (!connection) return;
  rooms.get(connection.roomId)?.delete(socket);
  if (rooms.get(connection.roomId)?.size === 0) {
    rooms.delete(connection.roomId);
  }
}

async function ensureRoomSubscribed(roomId: RoomId) {
  if (rooms.has(roomId)) return;

  rooms.set(roomId, new Set());
  await subscriber.subscribe(roomId, (message) => {
    let { socketId, frame } = JSON.parse(message);
    rooms.get(roomId)?.forEach((client) => {
      client.write(Buffer.from(frame, "base64"));
    });
  });
}

main();
