// 版本号单一真源 = package.json 的 version；wrangler 打包时把 JSON 内联进产物，无需构建步骤。
// 版本口径与历史判级见根目录 VERSIONS.md。
import pkg from "../package.json";

export const APP_VERSION: string = pkg.version;
