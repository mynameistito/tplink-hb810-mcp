import { defineConfig } from "oxlint";
import antiSlop from "ultracite/oxlint/anti-slop";
import core from "ultracite/oxlint/core";
import { selectJsPlugins } from "ultracite/oxlint/js-plugins";
import landmines from "ultracite/oxlint/landmines";

const jsPlugins = selectJsPlugins(["github", "sonarjs", "jsdoc-js", "tsdoc"]);

export default defineConfig({
  env: core.env,
  extends: [core, jsPlugins, landmines, antiSlop],
  ignorePatterns: core.ignorePatterns,
  jsPlugins: [...jsPlugins.jsPlugins, ...landmines.jsPlugins],
  options: { typeAware: true },
});
