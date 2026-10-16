# frida 高级·patch 与内存操作

> 主题:patchCode/Arm64Writer(nop 与 ret)

## 三、patchCode / Arm64Writer(nop 与 ret 函数)

什么时候用:不想 hook 只想让某个函数直接返回(nop/ret 掉壳的检测函数)。`Memory.patchCode` 的等价写法见 [frida-API详解.md](../frida-API详解.md) 2.8。

```javascript
function retFunc(parg2) {
    // 修改内存保护，使其可写
    Memory.protect(parg2, 4, 'rwx');
    // 使用 Arm64Writer 写入 'ret' 指令
    var writer = new Arm64Writer(parg2);
    writer.putRet();
    writer.flush();
    writer.dispose();
    console.log("ret " + parg2 + " success");
}
```

```javascript
function nopFunc(parg2) {
    // 修改内存保护，使其可写
    Memory.protect(parg2, 4, 'rwx');
    // 使用 Arm64Writer 写入 'nop' 指令
    var writer = new Arm64Writer(parg2);
    writer.putNop();
    writer.flush();
    writer.dispose();
    console.log("nop " + parg2 + " success");
}
```


## 相关文档

- Memory API:[frida-API详解.md](../frida-API详解.md)
