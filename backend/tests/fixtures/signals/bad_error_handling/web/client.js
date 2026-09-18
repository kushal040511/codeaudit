// Error-handling fixture: every JS rule, plus handled cases that must not be flagged.
const fs = require("fs");

function emptyCatch() {
  try {
    risky();
  } catch (e) {}
}

function emptyOptionalBinding() {
  try {
    risky();
  } catch {
    // ignored on purpose, still swallowed
  }
}

function consoleOnly() {
  try {
    risky();
  } catch (err) {
    console.error(err);
  }
}

function unhandledChain(url) {
  fetch(url).then((r) => r.json());
}

async function awaitOutsideTry(url) {
  const response = await fetch(url);
  return response.json();
}

// --- handled correctly: none of these may be flagged

function handledChain(url) {
  fetch(url)
    .then((r) => r.json())
    .catch((error) => report(error));
}

function thenWithRejection(p) {
  p.then(onOk, onError);
}

async function awaitInsideTry(path) {
  try {
    return await fs.promises.readFile(path, "utf8");
  } catch (error) {
    report(error);
    throw error;
  }
}

async function awaitNotIo(value) {
  return await compute(value);
}

function syncRead(path) {
  return fs.readFileSync(path, "utf8");
}

function risky() {}
function report() {}
function compute(v) {
  return v;
}
function onOk() {}
function onError() {}
