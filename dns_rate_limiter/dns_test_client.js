const dns2 = require('dns2');

// 讀取命令列參數
const TARGET_IP = process.argv[2] || '127.0.0.1';
const DOMAIN = process.argv[3] || 'www.google.com';

console.log(`[DNS Client (using dns2)] Target Server: ${TARGET_IP}`);
console.log(`[DNS Client (using dns2)] Query Domain: ${DOMAIN}`);
console.log('--------------------------------------------------');

// 建立 dns2 客戶端實例
const dns = new dns2({
  dns: TARGET_IP,
  port: 5333
});

// 發送 DNS 查詢並等待回應的 Helper
function sendQuery(id, delayMs, domain = DOMAIN) {
  return new Promise((resolve) => {
    setTimeout(async () => {
      const startTime = Date.now();

      // 使用 Promise.race 來實現自訂的 2 秒超時限制
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('TIMEOUT')), 2000);
      });

      try {
        const queryPromise = dns.resolveA(domain);
        const result = await Promise.race([queryPromise, timeoutPromise]);
        
        const duration = Date.now() - startTime;
        console.log(`[Query #${id}] 發送網域: "${domain}" -> 收到回應 (耗時 ${duration}ms) 成功!`);
        resolve(true);
      } catch (err) {
        if (err.message === 'TIMEOUT') {
          console.log(`[Query #${id}] 發送網域: "${domain}" -> 超時 (無回應，可能被 XDP 丟棄) ❌`);
        } else {
          console.log(`[Query #${id}] 發送網域: "${domain}" -> 查詢失敗 (錯誤: ${err.message}) ❌`);
        }
        resolve(false);
      }
    }, delayMs);
  });
}

async function runTest() {
  console.log('[Test] 1. 發送第 1 個查詢...');
  await sendQuery(1001, 0);

  console.log('\n[Test] 2. 立即發送第 2 個查詢 (間隔 100ms)...');
  await sendQuery(1002, 100, "www.nccu.edu.tw")
  await sendQuery(1003, 0);

  console.log('\n[Test] 3. 等待超過 1 秒後，發送第 3 個查詢 (間隔 1500ms)...');
  await sendQuery(1004, 1500);
}

runTest();
