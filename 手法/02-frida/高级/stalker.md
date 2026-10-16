# frida 高级·Stalker

> 主题:Stalker(指令级跟踪)

## 一、Stalker

### 1.1 stalker 原理

原理把原本的汇编代码复制过来,在每一行汇编代码下面膨胀代码,使得代码变大了很多,以实现回调函数。

在一开始的时候终止线程运行,然后通过 pc 知道下一个命令在哪获取到第一个基本块,创建到一个内存区域里面去,把原本的代码修改为跳转过去,执行内存块的代码,执行之后在块的结尾,也就是 b 或者 bl 之前,跳转到 stalker 创建的块里面去,然后在里面拿到跳转的位置再创建一个新的代码块,判断需要跳转到哪个代码块里面去。

使用 stalker 之后相关的块基本上 bl 都不是执行的原本的 bl 了,而是我们 stalker 修改了之后的 bl,跳转到了 stalker 的相关位置去,而不是原本的直接执行了。

### 1.2 基础使用:打印每一个块的汇编代码

方便知道哪些块被调用了,被调用的顺序。常规 hook 代码:

```javascript
Interceptor.attach(JNI_OnLoad, {
    onEnter: function (args) {
        var curTid = Process.getCurrentThreadId();
        Stalker.follow(curTid, {
            transform: function (iterator) {
                let instruction = iterator.next();
                const baseFirstAddress = instruction.address;
                const isModuleCode = baseFirstAddress.compare(startBase) >= 0 &&
                    baseFirstAddress.compare(startBase.add(size)) <= 0;
                const module = Process.findModuleByAddress(baseFirstAddress);
                if (isModuleCode) {
                    if (module) {
                        const name = module.name;
                        const offset = baseFirstAddress.sub(module.base);
                        const base = module.base;
                        console.log(`[transform] start: ${baseFirstAddress} name:${name} offset: ${offset} base: ${base}`);
                    } else {
                        console.log(`[transform] start: ${baseFirstAddress}`);
                    }
                }
                do {
                    const curRealAddr = instruction.address;
                    const curOffset = curRealAddr.sub(baseFirstAddress);
                    const curOffsetInt = curOffset.toInt32()
                    const instructionStr = instruction.toString()
                    if (isModuleCode){
                        console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr);
                    }
                    iterator.keep();
                } while ((instruction = iterator.next()) !== null);
                if (isModuleCode){
                    console.log()
                }
            }
        })
    },
    onLeave: function (retval) {
        console.log("结束");
        Stalker.unfollow();
        Stalker.garbageCollect();
    }
}
)
```

### 1.3 测试是否会卡死的代码

先验证目标函数能不能跟(直接创建 block 块,什么都不做):

```javascript
const module = Process.findModuleByName("libDexHelper.so");
Interceptor.attach(module.base.add(0x4b614), {
        onEnter: function (args) {
            var curTid = Process.getCurrentThreadId();
            Stalker.follow(curTid, {
                // 直接创建block块，什么都不做
                transform: function (iterator) {
                    while (true){
                        if (iterator.next() === null){
                            break;
                        }
                        iterator.keep();
                    }
                }
            })
        },
        onLeave: function (retval) {
            console.log("结束");
            Stalker.unfollow();
            Stalker.garbageCollect();
        }
    }
)
```

### 1.4 日志缓冲(Log 类)

如果 log 有问题的情况下,使用缓存的方式(先入队,定时刷出):

```javascript
class Log {
    constructor() {
        this.queue = []
    }

    push(info) {
        this.queue.push(info)
    }

    flush() {
        this.queue = []
    }

    log() {
        if (this.queue.length !== 0) {
            console.log(this.queue.join("\n"))
            this.flush();
        }
    }
}

const log = new Log();
setInterval(() => {
    log.log();
}, 30)
```

### 1.5 js 变量问题时的 transform 写法

如果出现 js 变量问题,可以采用如下方式(避免在 iterator 循环里引用外部闭包变量):

```javascript
transform: function (iterator) {
    let curOffset = 0;
    while (true) {
        const instruction = iterator.next();
        if (instruction === null) {
            break;
        }
        const address = instruction.address;
        const isModuleCode = address.compare(base) >= 0 &&
            address.compare(base.add(size)) <= 0;
        if (isModuleCode) {
            const curRealAddr = instruction.address;
            const curOffsetInt = curOffset;
            const instructionStr = instruction.toString();
            if (curOffset) {
                logBuffer.push("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr);
            } else {
                const offset = curRealAddr.sub(base);
                const name = "libDexHelper.so";
                logBuffer.push(`[transform] start: ${curRealAddr} name:${name} offset: ${offset} base: ${base}`);
                logBuffer.push("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr);
            }
            curOffset += 4;
        }
        iterator.keep();
    }
    if (curOffset) {
        logBuffer.push()
    }
}
```

### 1.6 常用 api

```javascript
// 排除这个区域
Stalker.exclude({base,size});
// 停止对某个基本块的跟踪
Stalker.unfollow();
// 清理 Stalker 使用的内存和资源
Stalker.garbageCollect();
// 强制 Stalker立即清空这个缓冲区
Stalker.flush()
```

### 1.7 事件回调(CModule onEvent)

```javascript
const cm = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>

void onEvent(const GumEvent *event, GumCpuContext *cpu_context, gpointer user_data) {
  printf("成功");
}
`);

Stalker.follow(curTid, {
    events: {
        call: true,
    },
    onEvent: cm.onEvent,
    transform: function (iterator) {
        while (true) {
            if (iterator.next() === null) {
                break;
            }
            iterator.keep();
        }
    }
})
```

### 1.8 events 配置示例(excludeLibs + 事件类型)

```javascript
function excludeLibs(libs) {
  new ModuleMap().values().map(m => {
      const { name, base, size } = m;
      if (libs.includes(name)) return;
      console.log('exclude', JSON.stringify(m));
      Stalker.exclude({base,size});
  });
}

function main() {
  excludeLibs(['frida-agent-64.so', 'libc-2.31.so']);
  const onReceive = blob => {
    const events = Stalker.parse(blob, { annotate: true, stringify: true });
    console.log('onReceive', events.length, events);
  };
  const cm = new CModule(`
    #include <gum/gumstalker.h>
    #include <stdio.h>
    void onEvent(const GumEvent *event, GumCpuContext *cpu_context, gpointer user_data) {
      printf("type %d\n", event->type);
    }
  `);
  Stalker.follow(Process.id, {
    events: {
      call: true, // CALL instructions: yes please
      ret: true, // RET instructions
      exec: false, // all instructions
      block: true, // block executed: coarse execution trace
      compile: false // block compiled: useful for coverage
    },
    // onReceive,
    onEvent: cm.onEvent
  });
}
setTimeout(main, 100);
```

### 1.9 iterator.putCallout 回调

iterator.putCallout 可以在指令之后设置回调,注意这个和 keep 是配合的:

```javascript
iterator.putCallout((context) => {
    console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr,
        "x8="+ context.x8);
})
```

### 1.10 修改寄存器的值

```javascript
context.x8 = 0x12345678;  // 修改 x8 寄存器
context.x0 = 0x9abcdef0;  // 修改 x0 寄存器
context.pc = context.pc.add(4);  // 修改 pc 寄存器，跳过当前指令（示例）
```


## 相关文档

- Memory/NativeFunction/CModule API:[frida-API详解.md](../frida-API详解.md)
