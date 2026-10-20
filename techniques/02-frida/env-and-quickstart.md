# frida Environment and Quick Start

> A frida primer for Android reverse engineering: installation, the two launch modes (spawn/attach), a custom frida-server port, quick tracing with frida-trace, and the basic Java.perform structure.

## 1. Installation

### 1.1 Install via python (most common)

```bash
pip install frida
pip install frida-tools
```

### 1.2 Install via npm (for TS type hints)

Pair this with your editor when writing scripts, to get completion for the frida-gum type definitions:

```bash
npm i @types/frida-gum
```

## 2. Run a Simple Piece of JS

First write a minimal runnable script to check whether the environment works:

```javascript
// 最小脚本:验证 Java 层可用
function main(){
    Java.perform(()=>{
        console.log("成功运行")
    })
}
setImmediate(main)
```

## 3. Launch Modes: spawn vs attach

### 3.1 spawn mode (-f pulls the process up from scratch)

```bash
frida -U -f 包名 -l 脚本.js
```

Here `-U` selects the device (a USB device), and `-f` launches in spawn mode. In spawn mode the script takes effect at the app's earliest stage, which suits hooking Application, packer initialization, JNI_OnLoad, and other early logic.

### 3.2 attach mode (-F attaches to the foreground app)

```bash
frida -H 192.168.0.100:14725 -F -l 脚本.js
```

`-F` launches in attach mode, and `-H` connects to that address; the frida-server side must also be switched to the matching port.

### 3.3 Custom frida-server port

Used together with `-H`; on the device, make frida-server listen on all interfaces:

```bash
frida-server -l 0.0.0.0:14725
```

These are basically the most-used run commands.

### 3.4 Non-app scenarios (plain executables)

Attach to an existing process:

```bash
frida -U -p 3173 -l your_script.js
```

Spawn an executable:

```bash
frida -U -f /path/to/your/executable -l your_script.js
```

## 4. Basic Java.perform Structure

All Java-layer hooks must be wrapped in `Java.perform` to run (executed once the VM is ready):

```javascript
Java.perform(function () {
    // 这里拿类、改 implementation
    var ExampleClass = Java.use('com.example.ExampleClass');
});
```

Combined with `setImmediate(main)` you can wrap the entry point into a function and schedule it uniformly.

Key points:
- `Java.use(class name)` gets the class wrapper object; `class.method.implementation = function(){...}` replaces the implementation.
- For same-named overloads, use `.overload('arg type', ...)` to pin down the exact signature.
- Call the original logic as `this.method(...)`.
- Create objects proactively with `class.$new()`; hook constructors via `class.$init`.

## 5. Quick Tracing with frida-trace

Use frida-trace when you want to quickly probe an app's native behavior without writing a script:

```bash
frida-trace -U -f com.lucky.luckyclient -a "libc.so!"
```

- The command above hooks every function under libc.so.
- It generates hook handler scripts for all libc.so functions in the `handlers/` directory of the current directory (auto-generated as `__handlers__/libc.so/xxx.js`); you can hand-edit these templates to change the printing logic.
- `-a "module!"` specifies the module to trace; you can also use `-i function-name` to trace only a single imported function.

## 6. Common Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Failed to spawn: unable to find process with name` | Wrong package name, or use `-F` to attach to the foreground app |
| Script has no effect after attaching | Packed app / multiple classLoaders; see the "hooking packed apps" section in `java-layer/crypto-and-self-dump.md` and `../03-unpacking/dex-unpacking.md` |
| Spawn crashes right away | The target has anti-debugging; start with `advanced/detection-bypass-snippets.md` |
| Remote `-H` will not connect | frida-server port not changed, not listening on 0.0.0.0, or the port is occupied |

## Related Docs

- Per-domain hook point quick reference: the 6 docs in the java-layer/ directory ([Network & WebView](java-layer/network-webview.md) / [Crypto & self-dump](java-layer/crypto-and-self-dump.md) / [Storage & system](java-layer/storage-and-system.md) / [UI & navigation](java-layer/ui-and-navigation.md) / [Strings & JSON](java-layer/strings-and-json.md) / [SSL pinning & certificates](java-layer/sslpinning-and-certificates.md))
- so-layer hook quick reference: [native-hook-cheatsheet.md](native-hook-cheatsheet.md)
- API details: [frida-api-reference.md](frida-api-reference.md)
- Stalker: [advanced/stalker.md](advanced/stalker.md) / GOT hook: [advanced/gothook.md](advanced/gothook.md) / detection bypass: [advanced/detection-bypass-snippets.md](advanced/detection-bypass-snippets.md)
