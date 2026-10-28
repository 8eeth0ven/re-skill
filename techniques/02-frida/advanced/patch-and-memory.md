# frida advanced · patch and memory operations

> Topic: patchCode/Arm64Writer (nop and ret)

## 3. patchCode / Arm64Writer (nop and ret a function)

When to use: you do not want to hook, you only want a function to return immediately (nop/ret a packer's detection function out of the way). See [frida-api-reference.md](../frida-api-reference.md) 2.8 for the equivalent `Memory.patchCode` formulation.

```javascript
function retFunc(parg2) {
    // Make the target memory writable
    Memory.protect(parg2, 4, 'rwx');
    // Write a 'ret' instruction with Arm64Writer
    var writer = new Arm64Writer(parg2);
    writer.putRet();
    writer.flush();
    writer.dispose();
    console.log("ret " + parg2 + " success");
}
```

```javascript
function nopFunc(parg2) {
    // Make the target memory writable
    Memory.protect(parg2, 4, 'rwx');
    // Write a 'nop' instruction with Arm64Writer
    var writer = new Arm64Writer(parg2);
    writer.putNop();
    writer.flush();
    writer.dispose();
    console.log("nop " + parg2 + " success");
}
```


## Related docs

- Memory API: [frida-api-reference.md](../frida-api-reference.md)
