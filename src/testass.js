
const { SmartHasher } = require("./lib.js");

const hasher = new SmartHasher();

const ass = hasher.hash("assssssss");

console.log(ass);
