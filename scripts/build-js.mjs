import * as esbuild from "esbuild";
import * as fs from "fs";
import * as path from "path";

const watch = process.argv.includes("--watch");

const options = {
  entryPoints: ["app/static/src/js/main.js"],
  bundle: true,
  minify: !watch,
  sourcemap: watch,
  target: ["es2020"],
  outfile: "app/static/dist/main.js",
  logLevel: "info",
};

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log("esbuild watching for changes...");
} else {
  await esbuild.build(options);
}

try {
  const jsSrc = path.join("node_modules", "altcha", "dist", "main", "altcha.js");
  const jsDst = path.join("app", "static", "dist", "altcha.js");
  fs.copyFileSync(jsSrc, jsDst);
  console.log("Copied altcha widget to app/static/dist/altcha.js");

  const cssSrc = path.join("node_modules", "altcha", "dist", "external", "altcha.css");
  const cssDst = path.join("app", "static", "dist", "altcha.css");
  fs.copyFileSync(cssSrc, cssDst);
  console.log("Copied altcha widget CSS to app/static/dist/altcha.css");
} catch (err) {
  console.error("Failed to copy altcha widget:", err);
  process.exitCode = 1;
}
