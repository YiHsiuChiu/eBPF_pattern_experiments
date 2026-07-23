const dns = require('dns2');
const { Packet } = dns;

const MAX_QPS = 1000;

// Map to store rate limit state for each client IP + domain name hash
// Key: "client_ip:qname_hash"
// Value: { lastSec: number, count: number }
const limitMap = new Map();

/**
 * Calculates the DJB2 hash of the QNAME wire format for a given domain name.
 * This matches the logic in xdp_dns_limiter.bpf.c.
 * 
 * @param {string} domain - Domain name (e.g., "www.google.com")
 * @returns {number} 32-bit unsigned DJB2 hash
 */
function getQNameHash(domain) {
  if (!domain) return 5381;

  // Convert domain to standard DNS QNAME wire format bytes
  // e.g. "www.google.com" -> [3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm']
  const parts = domain.split('.');
  const bytes = [];
  for (const part of parts) {
    bytes.push(part.length);
    for (let i = 0; i < part.length; i++) {
      bytes.push(part.charCodeAt(i));
    }
  }

  // Implement DJB2 hash
  let hash = 5381;
  // BPF code restricts QNAME parsing to 32 bytes max
  const limit = Math.min(bytes.length, 32);
  for (let i = 0; i < limit; i++) {
    hash = ((hash << 5) + hash) + bytes[i];
    hash = hash & 0xffffffff; // Force 32-bit unsigned integer
  }
  return hash;
}

const server = dns.createUDPServer((request, send, rinfo) => {
  const response = Packet.createResponseFromRequest(request);
  const nowMs = Date.now();
  const currentSec = Math.floor(nowMs / 1000);
  const currentHour = new Date(nowMs).getUTCHours();

  let shouldDrop = false;

  // Check limit for each question (matches BPF loop)
  for (const question of request.questions) {
    const { name } = question;
    const qnameHash = getQNameHash(name);

    const key = `${rinfo.address}:${qnameHash}`;
    // console.log("key:", key);
    const record = limitMap.get(key);

    if (record !== undefined) {
      if (record.lastSec === currentSec) {
        // 同在一秒內
        // console.log("record count:", record.count);
        if (record.count >= MAX_QPS) {
          // Rule: No limits between 00:00 and 05:59 UTC (hour < 6)
          // console.log(currentHour);
          if (currentHour >= 1) {
            shouldDrop = true;
            // console.log(`[Rate Limiter] DROP: Client ${rinfo.address} queried "${name}" (Count ${record.count} >= ${MAX_QPS}). Current UTC Hour: ${currentHour}`);
            break;
          }
        } else {
          record.count++;
        }
      } else {
        // 進入新的一秒，重置計數
        record.lastSec = currentSec;
        record.count = 1;
      }
    } else {
      // 首次查詢，初始化
      limitMap.set(key, { lastSec: currentSec, count: 1 });
    }
  }

  if (shouldDrop) {
    // Simulating XDP_DROP: Do not send any response back
    return;
  }

  const [question] = request.questions || [];
  if (question) {
    const { name } = question;
    response.answers.push({
      name,
      type: Packet.TYPE.A,
      class: Packet.CLASS.IN,
      ttl: 300,
      address: '8.8.8.8',
    });
  }
  send(response);
});

server.on('request', (request, response, rinfo) => {
  // console.log(`[Request] ID: ${request.header.id}, Question:`, request.questions[0] ? request.questions[0].name : 'None');
});

server.listen(5333);
console.log('Limited DNS Server is listening on port 5333...');
