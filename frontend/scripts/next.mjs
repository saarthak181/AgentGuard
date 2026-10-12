import {spawn} from "node:child_process";
import {createRequire} from "node:module";
import {dirname,resolve} from "node:path";

const require=createRequire(import.meta.url);
const env={...process.env};
try{
  require("@next/swc-win32-x64-msvc");
}catch{
  // Some local hosts ship an incompatible native SWC binary. Next's matching
  // WASM build is slower but keeps development/build usable in that case.
  env.NEXT_TEST_WASM_DIR=dirname(require.resolve("@next/swc-wasm-nodejs/package.json"));
}

const cli=require.resolve("next/dist/bin/next");
const child=spawn(process.execPath,[cli,...process.argv.slice(2)],{cwd:process.cwd(),env,stdio:"inherit"});
child.on("error",error=>{console.error("Unable to start Next.js:",error.message);process.exitCode=1});
child.on("exit",(code,signal)=>{if(signal){process.kill(process.pid,signal);return}process.exitCode=code??1});
