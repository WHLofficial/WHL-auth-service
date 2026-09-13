// QQ 绑定通道冒烟（P0-8，TECH_DESIGN §7）：真跑 auth 8792（本地 dev）。
// 覆盖：绑定页生成码 → 插件视角 HMAC claim 建绑定 → 复用/伪签/格式负例 →
//       qq_bound / user_bound（直插库构造场景码）→ unbind → 重绑 → audit_log 落行。
// 前置：
//   1) npm run db:migrate:local（0004_bind.sql 起生效）
//   2) .dev.vars 配 BIND_SECRET（脚本从这里读，与 dev 服务同源）
//   3) node scripts/seed-local-users.mjs && node scripts/seed-local-oidc.mjs，
//      然后起 npm run dev（8792）
// 本地账号：oidctour-admin(901) / oidctour-coach(902) / oidctour-viewer(903)，
// 密码 TestPass123；脚本开头先解绑清场，可重复跑。
// 说明：HTTP 断言全部走 dev 服务；只有构造 user_bound/过期码场景行与审计核对用
//       wrangler 直连本地 sqlite（独立短暂连接，与 dev 的 miniflare 并行实测无锁冲突）。
import { execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const AUTH = 'http://127.0.0.1:8792';

let pass = 0;
const fails = [];
function ok(cond, label, extra = '') {
  if (cond) pass++;
  else fails.push(label);
  console.log(`${cond ? '✓' : '✗'} ${label}${cond || !extra ? '' : ` —— ${extra}`}`);
}

// ---- 小件 ----

function devVar(name) {
  const line = readFileSync(fileURLToPath(new URL('../.dev.vars', import.meta.url)), 'utf8')
    .split('\n')
    .find((l) => l.startsWith(`${name}=`));
  return line ? line.slice(name.length + 1).trim() : '';
}

const BIND_SECRET = devVar('BIND_SECRET');
if (!BIND_SECRET) {
  console.error('✗ .dev.vars 缺 BIND_SECRET，无法验签');
  process.exit(1);
}

function sign(method, pathWithQuery, rawBody, ts) {
  return createHmac('sha256', BIND_SECRET).update(`${method}|${pathWithQuery}|${ts}|${rawBody}`).digest('hex');
}

async function machinePost(path, bodyObj, { tsOffsetSec = 0, secret = BIND_SECRET } = {}) {
  const raw = JSON.stringify(bodyObj);
  const ts = Math.floor(Date.now() / 1000) + tsOffsetSec;
  const headers = {
    'content-type': 'application/json',
    'x-timestamp': String(ts),
    'x-sign': sign('POST', path, raw, ts),
  };
  if (secret === null) { delete headers['x-timestamp']; delete headers['x-sign']; }
  return fetch(`${AUTH}${path}`, { method: 'POST', headers, body: raw });
}

class Jar {
  #m = new Map();
  absorb(res) {
    for (const line of res.headers.getSetCookie()) {
      const pair = line.split(';')[0];
      const eq = pair.indexOf('=');
      this.#m.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
  header() {
    return [...this.#m].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function req(jar, url, { method = 'GET', form } = {}) {
  const res = await fetch(url, {
    method,
    redirect: 'manual',
    headers: {
      ...(jar?.header() ? { cookie: jar.header() } : {}),
      ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
    },
    body: form ? new URLSearchParams(form) : undefined,
  });
  if (jar) jar.absorb(res);
  return res;
}

async function loginAs(name) {
  const jar = new Jar();
  const page = await req(jar, `${AUTH}/login`);
  const csrf = /name="csrf" value="([^"]+)"/.exec(await page.text())?.[1];
  const res = await req(jar, `${AUTH}/login`, { method: 'POST', form: { csrf, name, password: 'TestPass123', next: '' } });
  if (res.status !== 303) throw new Error(`${name} 登录失败：HTTP ${res.status}`);
  return jar;
}

async function pageCsrf(jar, path) {
  const page = await req(jar, `${AUTH}${path}`);
  return { res: page, csrf: /name="csrf" value="([^"]+)"/.exec(await page.text())?.[1] };
}

// 直插/查询本地 D1（miniflare sqlite）：构造场景行与验证审计
function d1(sql) {
  const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
  return execFileSync(process.execPath, [wrangler, 'd1', 'execute', 'whl-auth', '--local', '--json', '--command', sql], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    encoding: 'utf8',
  });
}
function d1Rows(sql) {
  const out = JSON.parse(d1(sql));
  return out[0]?.results ?? [];
}
const { createHash } = await import('node:crypto');
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// ---- 冒烟主体 ----

// 0) 清场：解绑测试 QQ、清测试码，保证可重跑
const QQ_A = '314159261', QQ_B = '271828182', QQ_C = '161803398';
for (const qq of [QQ_A, QQ_B, QQ_C]) await machinePost('/api/identity/unbind', { qq_id: qq }).catch(() => {});
d1(`DELETE FROM bind_code WHERE account_id IN (901, 902, 903);`);

// 1) 登录 + 绑定页初始态
const jar1 = await loginAs('oidctour-admin');
const bind0 = await req(jar1, `${AUTH}/bind`);
const bind0Html = await bind0.text();
ok(bind0.status === 200 && bind0Html.includes('生成绑定码'), '登录后 /bind 显示未绑定态');

// 2) 生成码 → 插件 HMAC claim 建绑定
const gen1 = await req(jar1, `${AUTH}/bind/code`, { method: 'POST', form: { csrf: (await pageCsrf(jar1, '/bind')).csrf } });
const code1 = /绑定 (\d{6})/.exec(await gen1.text())?.[1];
ok(gen1.status === 200 && /^\d{6}$/.test(code1 ?? ''), 'POST /bind/code 生成 6 位码', `status=${gen1.status} code=${code1}`);
const claim1 = await machinePost('/api/bind/claim', { code: code1, qq_id: QQ_A });
const claim1Body = await claim1.json().catch(() => ({}));
ok(claim1.status === 200 && claim1Body.ok === true && claim1Body.displayName === 'oidctour-admin',
  'claim 200 {ok, displayName}', JSON.stringify(claim1Body));
const bind1Html = await (await req(jar1, `${AUTH}/bind`)).text();
ok(bind1Html.includes(QQ_A), '绑定页显示已绑定 QQ');

// 3) 负例：码复用 / 伪码 / 伪签 / 缺头 / 时间窗外 / qq 格式
ok((await machinePost('/api/bind/claim', { code: code1, qq_id: QQ_B })).status === 400, '已用码再 claim 被拒（400）');
ok((await machinePost('/api/bind/claim', { code: '000000', qq_id: QQ_B })).status === 400, '伪码 claim 被拒（400）');
const noSign = await fetch(`${AUTH}/api/bind/claim`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ code: '000000', qq_id: QQ_B }),
});
ok(noSign.status === 401, '缺签名头 401');
const badSignRes = await fetch(`${AUTH}/api/bind/claim`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-timestamp': '123', 'x-sign': 'deadbeef' },
  body: JSON.stringify({ code: '000000', qq_id: QQ_B }),
});
ok(badSignRes.status === 401, '坏签名 401');
ok((await machinePost('/api/bind/claim', { code: '000000', qq_id: QQ_B }, { tsOffsetSec: -301 })).status === 401, '时间窗外 401');
ok((await machinePost('/api/bind/claim', { code: '000000', qq_id: 'not-a-qq' })).status === 400, 'qq_id 非数字 400');

// 4) qq_bound：902 的码去绑已被 901 占用的 QQ_A
const jar2 = await loginAs('oidctour-coach');
const gen2 = await req(jar2, `${AUTH}/bind/code`, { method: 'POST', form: { csrf: (await pageCsrf(jar2, '/bind')).csrf } });
const code2 = /绑定 (\d{6})/.exec(await gen2.text())?.[1];
const qb = await machinePost('/api/bind/claim', { code: code2, qq_id: QQ_A });
const qbBody = await qb.json().catch(() => ({}));
ok(qb.status === 400 && qbBody.error === 'qq_bound', '一个 QQ 不能绑第二个账号（qq_bound）', JSON.stringify(qbBody));

// 5) user_bound：已绑定账号（901）名下出现活码时 claim 别的 QQ —— 直插场景码构造
d1(`INSERT INTO bind_code (code_hash, account_id, created_at, expires_at) VALUES ('${sha256('777777')}', 901, '${new Date().toISOString()}', '${new Date(Date.now() + 600000).toISOString()}');`);
const ub = await machinePost('/api/bind/claim', { code: '777777', qq_id: QQ_C });
const ubBody = await ub.json().catch(() => ({}));
ok(ub.status === 400 && ubBody.error === 'user_bound', '一个账号不能绑第二个 QQ（user_bound）', JSON.stringify(ubBody));

// 6) 过期码：直插一条已过期的码
d1(`INSERT INTO bind_code (code_hash, account_id, created_at, expires_at) VALUES ('${sha256('666666')}', 903, '${new Date().toISOString()}', '${new Date(Date.now() - 1000).toISOString()}');`);
ok((await machinePost('/api/bind/claim', { code: '666666', qq_id: QQ_B })).status === 400, '过期码 400');

// 7) unbind：解绑 QQ_A → 绑定页回未绑定态 → 重绑成功（换绑路径）
const ub1 = await machinePost('/api/identity/unbind', { qq_id: QQ_A });
const ub1Body = await ub1.json().catch(() => ({}));
ok(ub1.status === 200 && ub1Body.ok === true && ub1Body.displayName === 'oidctour-admin', 'unbind 200', JSON.stringify(ub1Body));
const bind2Html = await (await req(jar1, `${AUTH}/bind`)).text();
ok(!bind2Html.includes(QQ_A) && bind2Html.includes('生成绑定码'), '解绑后绑定页回未绑定态');
const nb = await machinePost('/api/identity/unbind', { qq_id: QQ_A });
const nbBody = await nb.json().catch(() => ({}));
ok(nb.status === 400 && nbBody.error === 'not_bound', '未绑定 QQ unbind 得 not_bound', JSON.stringify(nbBody));
const gen3 = await req(jar1, `${AUTH}/bind/code`, { method: 'POST', form: { csrf: (await pageCsrf(jar1, '/bind')).csrf } });
const code3 = /绑定 (\d{6})/.exec(await gen3.text())?.[1];
ok((await machinePost('/api/bind/claim', { code: code3, qq_id: QQ_A })).status === 200, '解绑后重绑成功（换绑）');

// 8) 审计行随业务写入原子落库
const audits = d1Rows(`SELECT event, COUNT(*) AS n FROM audit_log WHERE event IN ('bind.claim', 'bind.unbind') GROUP BY event;`);
const claimN = audits.find((r) => r.event === 'bind.claim')?.n ?? 0;
const unbindN = audits.find((r) => r.event === 'bind.unbind')?.n ?? 0;
ok(claimN >= 2 && unbindN >= 1, `audit_log 有 bind.claim×${claimN} / bind.unbind×${unbindN}（成功操作必有审计行）`);

console.log(`\n${fails.length ? `❌ ${fails.length} 项未过 / ` : ''}✅ ${pass} 项断言全过`);
process.exit(fails.length ? 1 : 0);
