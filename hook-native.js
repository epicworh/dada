// trace native using
// 1. module name and method name
        // i.e libc.so & open
// 2. module name address offset
        // i.e. libc.so 0x400 (0x400 from libc loading point)

traceNativeMethod('libc.so', "open", false, 'int', "string")

function traceNativeMethod(moduleName, nameOrOffset, backtrace = false, regReturn = NULL, ...argsOps) {

    // must include module name
    if (typeof moduleName === 'undefined') {
        colors.red("Missing module name");
        return -1;
    }

    var introLog = "TID: " + Process.getCurrentThreadId() + "\n"

    if (typeof nameOrOffset === 'string'){
        var targetAddress = Module.findExportByName(moduleName, nameOrOffset);
        introLog = introLog + moduleName + ' ' + nameOrOffset;
    }
    else if (typeof nameOrOffset === 'number'){
        var targetAddress = Module.findBaseAddress(moduleName).add(nameOrOffset);
        introLog = introLog + moduleName + ' 0x' + nameOrOffset.toString(16) ;
    }

    Interceptor.attach(targetAddress, {
        onEnter(args) {
            // intro log
            colors.green(introLog);

            if (backtrace) {
                colors.green(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
            }

            for (let i = 0; i < argsOps.length; i++) {
                var op = argsOps[i];
                var actions = op.split("-");
                var currentPtr = args[i];
                for (let x = 0; x < actions.length; x++) {
                    switch (actions[x]) {
                        case 'int': {
                            colors.blue(currentPtr.toInt32())
                        }
                        case 'string': {
                            colors.blue(currentPtr.readUtf8String())
                        }
                        case 'buffer' : {
                            colors.blue(hexdump(currentPtr, { length: 256, ansi: true }));
                        }
                        case 'readpointer' : {
                            currentPtr = currentPtr.readPointer();
                        }
                        // TODO, ability to add pointer
                        // case 'addPointer' : {
                        //     currentPtr = currentPtr.add(actions);
                        // }
                    }
                }
            }

        },
        onLeave(ret) {
            var actions = regReturn.split("-");
            var currentPtr = args[i];
            for (let x = 0; x < actions.length; x++) {
                switch (actions[x]) {
                    case 'int': {
                        colors.blue(currentPtr.toInt32())
                    }
                    case 'string': {
                        colors.blue(currentPtr.readUtf8String())
                    }
                    case 'buffer' : {
                        colors.blue(hexdump(currentPtr, { length: 256, ansi: true }));
                    }
                    case 'readpointer' : {
                        currentPtr = currentPtr.readPointer();
                    }
                    // TODO, ability to add pointer
                    // case 'addPointer' : {
                    //     currentPtr = currentPtr.add(actions);
                    // }
                }
            }
        },
    })
}

const colors = {
    colorize: (str, cc) => `\x1b${cc}${str}\x1b[0m`,
    red: str => console.log(colors.colorize(str, '[31m')),
    green: str => console.log(colors.colorize(str, '[32m')),
    yellow: str => console.log(colors.colorize(str, '[33m')),
    blue: str => console.log(colors.colorize(str, '[34m')),
    cyan: str => console.log(colors.colorize(str, '[36m')),
    white: str => console.log(colors.colorize(str, '[37m')),
};
