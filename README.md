bycrypt alternative in rust
<br/>
I used [same.dev](https://same.dev) to check out the source code behind [bycrypt package](https://github.com/kelektiv/node.bcrypt.js) btw, but just to be clear this is not a clone of it.

it is not a nodejs package yet, but it is certainly going to be.
-------
TODO
-------
- `rustup target add wasm32-unknown-unknown`
- `cargo install wasm-pack`
- `wasm-pack build --target nodejs`  <!-- generating pkg dir -->
- `cd pkg` then modifying the package.json file due to [here](1900885589882241497)