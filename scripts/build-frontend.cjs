const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const output = path.join(root, "dist");
const configured = process.env.API_BASE_URL?.trim();
let apiOrigin;

try {
  const parsed = new URL(configured);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
      parsed.pathname !== "/" || parsed.search || parsed.hash) throw new Error();
  apiOrigin = parsed.origin;
} catch {
  console.error("Set API_BASE_URL to the backend HTTPS origin before building.");
  process.exit(1);
}

const files = ["index.html", "privacy.html", "css/style.css", "js/app.js", "js/analyzer.js"];
function checkOutput(directory, prefix = "") {
  if (!fs.existsSync(directory)) return;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix + entry.name;
    if (entry.isSymbolicLink()) throw new Error("Unexpected link in frontend output.");
    if (entry.isDirectory()) checkOutput(path.join(directory, entry.name), relative + "/");
    else if (!files.includes(relative)) fs.unlinkSync(path.join(directory, entry.name));
  }
}
checkOutput(output);
fs.mkdirSync(output, { recursive: true });

for (const file of files) {
  const destination = path.join(output, file);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  if (file === "index.html") {
    const html = fs.readFileSync(path.join(root, file), "utf8");
    const placeholder = '<meta name="api-base-url" content="" />';
    if (!html.includes(placeholder)) throw new Error("API configuration placeholder is missing.");
    fs.writeFileSync(destination, html.replace(placeholder,
      `<meta name="api-base-url" content="${apiOrigin}" />`));
  } else {
    fs.copyFileSync(path.join(root, file), destination);
  }
}

console.log("Frontend built in dist. Only public HTML, CSS and JavaScript were copied.");
