import * as esbuild from "esbuild";

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
