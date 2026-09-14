// Node 原生 TS 剥离不会为「省略扩展名的相对导入」补 .ts（wrangler/esbuild 会），
// 而 src/** 之间正是这么互相导入的。这里加一个解析钩子补上，单测才能直接 import src 模块。
// 只影响测试进程，不改变任何产品代码。
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
      try {
        return nextResolve(`${specifier}.ts`, context);
      } catch {
        /* 落到默认解析 */
      }
    }
    return nextResolve(specifier, context);
  },
});
