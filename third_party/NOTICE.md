# LaZer

The proof backend is [lazer-crypto/lazer](https://github.com/lazer-crypto/lazer),
at commit `10eafeca4cd53ff4fc54193dce904dbd0026fefd`.
The build script downloads its source into `.deps/lazer` and checks the bundled
archive hashes in `lazer.lock.json`. `lazer-arm64.patch` contains the local
platform changes. The generated L2 header comes from LaZer's parameter generator.

LaZer is distributed under the following MIT license. Its bundled dependencies
retain their own notices in the downloaded source tree.

Copyright (c) 2022-2024 IBM

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
