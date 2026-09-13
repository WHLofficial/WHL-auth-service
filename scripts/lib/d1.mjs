// 脚本共用的 D1 读取辅助（seed-grants / migrate-accounts / verify-accounts）。
// 背景（P0-11 收口）：auth 的 wrangler.jsonc 不再绑定 TOUR_DB，跨仓库的「外部库」
// （tour 的 whl、guess 的 whl-guess）无法在本仓库按名解析。按真实 database_id 生成
// 临时 config（--config）供 wrangler 解析，并显式 --persist-to 锚定本地状态目录——
// 本地 D1 落盘按 database_id 定位文件，与源仓库同键同数据。
// whl-auth 走本仓库 wrangler.jsonc 正常解析（--remote 时用其真实 id，部署后填入）。
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const wrangler = join(repoRoot, "node_modules", "wrangler", "bin", "wrangler.js");

// 外部库的真实 database_id（与各源仓库 wrangler.jsonc 一致；配置事实，非密钥）
const FOREIGN_DB = {
  whl: "ec3cc695-70bc-47ab-a454-5ca62ec22dd6", // WHL-tournament-management-system 主库
  "whl-guess": "8f48bd5e-5d1b-4d62-ba4f-bf9b0cdb09eb", // WHL-Daily-Activities-System 主库
};

let configPath;
function foreignConfig() {
  if (configPath) return configPath;
  configPath = join(tmpdir(), "whl-auth-scripts-d1-config.json");
  writeFileSync(
    configPath,
    JSON.stringify({
      d1_databases: Object.entries(FOREIGN_DB).map(([database_name, database_id]) => ({
        binding: `X_${database_name.replace(/-/g, "_")}`,
        database_name,
        database_id,
      })),
    }),
  );
  return configPath;
}

export const REPO_STATE = join(repoRoot, ".wrangler", "state");
// 兄弟仓库的本地状态（读 guess 库的发起人名单等他仓库数据时用）
export const GUESS_STATE = resolve(repoRoot, "../WHL-Daily-Activities-System/.wrangler/state");

/**
 * @param {string} db 库名（whl-auth 或外部库 whl / whl-guess）
 * @param {string} sql 查询 SQL
 * @param {{remote?: boolean, persistTo?: string}} opts
 *   persistTo：本地状态目录锚点，默认本仓库 .wrangler/state
 */
export function d1Query(db, sql, { remote = false, persistTo } = {}) {
  const args = [wrangler, "d1", "execute", db, remote ? "--remote" : "--local", "--json", "--command", sql];
  if (FOREIGN_DB[db]) args.push("--config", foreignConfig());
  if (!remote) args.push("--persist-to", persistTo ?? REPO_STATE);
  const out = execFileSync(process.execPath, args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  const parsed = JSON.parse(out);
  return (Array.isArray(parsed) ? parsed[0]?.results : parsed?.results) ?? [];
}

/** 写库/执行任意 SQL（种子复位、迁移落库），不取结果 */
export function d1Exec(db, sql, { remote = false, persistTo } = {}) {
  const args = [wrangler, "d1", "execute", db, remote ? "--remote" : "--local", "--command", sql];
  if (FOREIGN_DB[db]) args.push("--config", foreignConfig());
  if (!remote) args.push("--persist-to", persistTo ?? REPO_STATE);
  execFileSync(process.execPath, args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}
