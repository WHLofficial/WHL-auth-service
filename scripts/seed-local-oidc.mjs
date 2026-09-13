// 本地 OIDC 联调 fixture（只写本地 miniflare 库——生产白名单里绝不允许出现 localhost）：
//   SQL=$(node scripts/seed-local-oidc.mjs) && npx wrangler d1 execute whl-auth --local --command "$SQL"
// 做三件事：
//   1. 注册本地冒烟 RP（smoke-rp），back-channel 收端点固定在 127.0.0.1:8793（smoke-oidc.mjs 内置临时监听）；
//   2. 给 club 追加本地回调/登出地址（127.0.0.1:8795，club 项目 scripts/smoke-oidc-local.mjs 用）；
//   3. 给 guess 追加本地回调/登出地址（127.0.0.1:8796，guess 项目 scripts/smoke-oidc-local.mjs 用）。
//      guess 的 app 行若不存在先 INSERT（生产接入 guess 时由部署清单建行，这里保证本地可跑）。
// 注意：输出必须是单行——wrangler 的 --command 在 Windows 下多行实参会在换行处被截断。
const CLUB_LOCAL_REDIRECT = "http://127.0.0.1:8795/api/auth/callback";
const CLUB_LOCAL_POST_LOGOUT = "http://127.0.0.1:8795/";
const CLUB_LOCAL_BACKCHANNEL = "http://127.0.0.1:8795/api/auth/backchannel-logout";

const GUESS_LOCAL_REDIRECT = "http://127.0.0.1:8796/api/auth/callback";
const GUESS_LOCAL_POST_LOGOUT = "http://127.0.0.1:8796/";
const GUESS_LOCAL_BACKCHANNEL = "http://127.0.0.1:8796/api/auth/backchannel-logout";

const clubRedirectUris = JSON.stringify(["https://club.whleague.win/api/auth/callback", CLUB_LOCAL_REDIRECT]);
const clubPostLogouts = JSON.stringify(["https://club.whleague.win/", CLUB_LOCAL_POST_LOGOUT]);
const guessRedirectUris = JSON.stringify(["https://guess.whleague.win/api/auth/callback", GUESS_LOCAL_REDIRECT]);
const guessPostLogouts = JSON.stringify(["https://guess.whleague.win/", GUESS_LOCAL_POST_LOGOUT]);

const statements = [
  `INSERT INTO app (client_id, name, redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, created_at)
   VALUES ('smoke-rp', '本地冒烟 RP', '["http://127.0.0.1:8792/smoke-cb"]', '["http://127.0.0.1:8792/smoke-done"]', 'http://127.0.0.1:8793/backchannel', '2026-09-12T00:00:00.000Z')
   ON CONFLICT(client_id) DO UPDATE SET
     redirect_uris = excluded.redirect_uris,
     post_logout_redirect_uris = excluded.post_logout_redirect_uris,
     backchannel_logout_uri = excluded.backchannel_logout_uri`,
  `UPDATE app
   SET redirect_uris = '${clubRedirectUris}',
       post_logout_redirect_uris = '${clubPostLogouts}',
       backchannel_logout_uri = '${CLUB_LOCAL_BACKCHANNEL}'
   WHERE client_id = 'club'`,
  `INSERT INTO app (client_id, name, redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, created_at)
   VALUES ('guess', 'WHL 竞猜系统', '${guessRedirectUris}', '${guessPostLogouts}', '${GUESS_LOCAL_BACKCHANNEL}', '2026-09-13T00:00:00.000Z')
   ON CONFLICT(client_id) DO UPDATE SET
     redirect_uris = excluded.redirect_uris,
     post_logout_redirect_uris = excluded.post_logout_redirect_uris,
     backchannel_logout_uri = excluded.backchannel_logout_uri`,
];

console.log(statements.map((s) => s.replace(/\s+/g, " ").trim()).join("; ") + ";");
