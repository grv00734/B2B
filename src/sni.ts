/**
 * Minimal TLS ClientHello SNI extractor.
 *
 * In transparent (iptables REDIRECT) mode, connections arrive already
 * TCP-connected with the TLS ClientHello as their first bytes — there is no
 * CONNECT line telling us the destination. We recover the target hostname from
 * the Server Name Indication extension so we can decide MITM vs blind-tunnel and
 * know where to forward. Pure parsing, no decryption, no native code.
 */
import type { Socket } from "node:net";

type SniResult = { state: "ok"; host: string } | { state: "none" } | { state: "need-more" };

const MAX_PEEK = 16384;

export function extractSNI(data: Buffer): SniResult {
  if (data.length < 5) return { state: "need-more" };
  if (data[0] !== 0x16) return { state: "none" }; // not a TLS handshake record

  const recordLen = data.readUInt16BE(3);
  if (data.length < 5 + recordLen) return { state: "need-more" };

  let p = 5;
  if (data[p] !== 0x01) return { state: "none" }; // not a ClientHello
  const hsLen = (data[p + 1]! << 16) | (data[p + 2]! << 8) | data[p + 3]!;
  p += 4;
  const hsEnd = Math.min(p + hsLen, data.length);

  p += 2 + 32; // client_version (2) + random (32)
  if (p + 1 > hsEnd) return { state: "none" };
  p += 1 + data[p]!; // session_id
  if (p + 2 > hsEnd) return { state: "none" };
  p += 2 + data.readUInt16BE(p); // cipher_suites
  if (p + 1 > hsEnd) return { state: "none" };
  p += 1 + data[p]!; // compression_methods
  if (p + 2 > hsEnd) return { state: "none" }; // no extensions present

  const extEnd = Math.min(p + 2 + data.readUInt16BE(p), hsEnd);
  p += 2;

  while (p + 4 <= extEnd) {
    const type = data.readUInt16BE(p);
    const len = data.readUInt16BE(p + 2);
    const body = p + 4;
    if (type === 0x0000) {
      // server_name extension
      let q = body;
      if (q + 2 > body + len) return { state: "none" };
      const listEnd = Math.min(q + 2 + data.readUInt16BE(q), body + len);
      q += 2;
      while (q + 3 <= listEnd) {
        const nameType = data[q]!;
        const nameLen = data.readUInt16BE(q + 1);
        q += 3;
        if (nameType === 0) {
          if (q + nameLen > listEnd) return { state: "none" };
          return { state: "ok", host: data.toString("utf8", q, q + nameLen) };
        }
        q += nameLen;
      }
      return { state: "none" };
    }
    p = body + len;
  }
  return { state: "none" };
}

/**
 * Read just enough of the socket to learn the SNI host, then resolve with the
 * host (or null if none) plus the bytes consumed so they can be replayed to the
 * real destination or fed into the TLS terminator.
 */
export function peekSni(socket: Socket): Promise<{ host: string | null; buffered: Buffer }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const finish = (host: string | null): void => {
      if (settled) return;
      settled = true;
      socket.off("readable", onReadable);
      socket.off("error", onError);
      socket.off("end", onEnd);
      clearTimeout(timer);
      resolve({ host, buffered: Buffer.concat(chunks) });
    };

    const onReadable = (): void => {
      let chunk: Buffer | null;
      while ((chunk = socket.read() as Buffer | null) !== null) {
        chunks.push(chunk);
        total += chunk.length;
      }
      const buf = Buffer.concat(chunks);
      const r = extractSNI(buf);
      if (r.state === "ok") finish(r.host);
      else if (r.state === "none") finish(null);
      else if (total >= MAX_PEEK) finish(null);
    };

    const onError = (): void => finish(null);
    const onEnd = (): void => finish(null);
    const timer = setTimeout(() => finish(null), 5000);

    socket.on("readable", onReadable);
    socket.on("error", onError);
    socket.on("end", onEnd);
    onReadable(); // handle bytes already buffered
  });
}
