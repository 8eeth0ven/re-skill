# frida 高级·so 与 soinfo 操作

> 主题:dumpSoFromSoInfo(解析) + waitForModule(动态 so 等待)

## 五、dumpSoFromSoInfo(so 修复 dump)

从 soinfo 重构 SO 文件的完整实现(dump 后段回填/符号表修复)另见 [../../03-脱壳dump/so修复dump.md](../../03-脱壳dump/so修复dump.md),此处不重复。

## 六、waitForModule:等待动态加载的 so

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


## 相关文档

- solist 遍历/soinfo 偏移表/GotHook:[gothook.md](gothook.md)(同目录)
- dumpSoFromSoInfo 完整实现:[../../03-脱壳dump/so修复dump.md](../../03-脱壳dump/so修复dump.md)
