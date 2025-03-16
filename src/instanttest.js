async function run() {
    const { SmartHasher } = await import("../pkg/ironguard.js"); // Importing the module
    const hasher = new SmartHasher(); // This line fails
    const password = "test";
    const hash = hasher.hash(password);
    console.log("Hash:", hash);
    const verified = hasher.verify(password, hash);
    console.log("Verified:", verified);
}

run();