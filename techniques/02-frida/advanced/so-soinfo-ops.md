# frida advanced · so and soinfo operations

> Topic: dumpSoFromSoInfo (parsing) + waitForModule (waiting for a dynamically loaded so)

## 5. dumpSoFromSoInfo (so repair dump)

For the full implementation of reconstructing an SO file from soinfo (post-dump segment write-back / symbol-table repair) see [so-repair-dump.md](../../03-unpacking/so-repair-dump.md); not duplicated here.

## 6. waitForModule: wait for a dynamically loaded so

```javascript
function waitForModule(moduleName) {
    return new Promise((resolve, reject) => {
        const checkInterval = setInterval(() => {
            const baseAddr = Module.findBaseAddress(moduleName);
            if (baseAddr !== null) {
                clearInterval(checkInterval);
                resolve(baseAddr);
            }
        }, 1000); // 检查频率为每秒一次
    });
}
```


## Related docs

- solist traversal / soinfo offset table / GotHook: [gothook.md](gothook.md) (same directory)
- Full dumpSoFromSoInfo implementation: [so-repair-dump.md](../../03-unpacking/so-repair-dump.md)
