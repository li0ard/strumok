<p align="center">
    <b>@li0ard/strumok</b><br>
    <b>Strumok (DSTU 8845:2019) cipher implementation in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/strumok">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/strumok/actions/workflows/test.yml"><img src="https://github.com/li0ard/strumok/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/strumok/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/strumok" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/strumok"><img src="https://img.shields.io/npm/v/@li0ard/strumok" /></a>
    <a href="https://jsr.io/@li0ard/strumok"><img src="https://jsr.io/badges/@li0ard/strumok" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
# from NPM
npm i @li0ard/strumok

# from JSR
bunx jsr i @li0ard/strumok
```

## Supported modes
- [x] Strumok-256
- [x] Strumok-512

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with DSTU 8845:2019 standard
- Supports Bun, Node.js, Deno, Browsers

## Examples
```ts
import { Strumok } from "@li0ard/kupyna"

const key = new Uint8Array(64).fill(0xaa)
const iv = new Uint8Array(32).fill(0xbb)
const data = new Uint8Array(256).fill(0xcc);

const cipher = new Strumok(key, iv);
console.log(cipher.crypt(data)) // Uint8Array [...]
```