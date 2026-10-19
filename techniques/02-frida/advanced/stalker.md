# frida advanced · Stalker

> Topic: Stalker (instruction-level tracing)

## 1. Stalker

### 1.1 How Stalker works

The idea is to copy the original assembly over and expand code beneath every assembly line, inflating the code a great deal, in order to implement callback functions.

At the start it halts the thread's execution, then uses the pc to learn where the next instruction is and obtain the first basic block, creates it inside a memory region, and rewrites the original code to jump over there; the memory block's code executes, and at the end of the block — right before the b or bl — execution jumps into a block Stalker created, where it obtains the jump target, creates a new code block, and decides which code block to jump into.

Once Stalker is in use, the bl instructions in the relevant blocks are basically never the original bl anymore — they are the bl as rewritten by Stalker, jumping to Stalker's own locations instead of executing directly as before.

### 1.2 Basic usage: print the assembly of every block

Handy for seeing which blocks get called, and in what order. Standard hook code:

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

### 1.3 Code to test whether it will hang

First verify that the target function can be followed (just create the block chunks, do nothing else):

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

### 1.4 Log buffering (Log class)

If logging misbehaves, use a buffered approach (enqueue first, flush on a timer):

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

### 1.5 transform style for JS-variable trouble

If you hit JS variable problems, use the following style (avoids referencing outer closure variables inside the iterator loop):

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

### 1.6 Common APIs

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

### 1.7 Event callbacks (CModule onEvent)

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

### 1.8 events configuration example (excludeLibs + event types)

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

### 1.9 iterator.putCallout callbacks

iterator.putCallout can set a callback after an instruction; note that it works together with keep:

```javascript
iterator.putCallout((context) => {
    console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr,
        "x8="+ context.x8);
})
```

### 1.10 Changing register values

```javascript
context.x8 = 0x12345678;  // 修改 x8 寄存器
context.x0 = 0x9abcdef0;  // 修改 x0 寄存器
context.pc = context.pc.add(4);  // 修改 pc 寄存器，跳过当前指令（示例）
```


## Related docs

- Memory/NativeFunction/CModule API: [frida-api-reference.md](../frida-api-reference.md)
