function getIl2CppString(strPtr) {
    if (strPtr.isNull()) {
        return null;
    }

    var il2cpp_string_chars = new NativeFunction(
        Module.findExportByName('libil2cpp.so', 'il2cpp_string_chars'),
        'pointer',
        ['pointer']
    );

    try {
        var chars_ptr = il2cpp_string_chars(strPtr);
        if (!chars_ptr.isNull()) {
            return chars_ptr.readUtf16String();
        }
    } catch(e) {
        console.log('[-] Error in getIl2CppString:', e);
    }
    return null;
}

function getMethodName(methodInfo) {
    var il2cpp_method_get_name = new NativeFunction(
        Module.findExportByName('libil2cpp.so', 'il2cpp_method_get_name'),
        'pointer',
        ['pointer']
    );

    var il2cpp_method_get_class = new NativeFunction(
        Module.findExportByName('libil2cpp.so', 'il2cpp_method_get_class'),
        'pointer',
        ['pointer']
    );

    var il2cpp_class_get_name = new NativeFunction(
        Module.findExportByName('libil2cpp.so', 'il2cpp_class_get_name'),
        'pointer',
        ['pointer']
    );
    try {
        if (methodInfo.isNull()) return null;

        // 获取方法名
        var namePtr = il2cpp_method_get_name(methodInfo);
        var methodName = namePtr.readUtf8String();

        // 获取类名
        var classPtr = il2cpp_method_get_class(methodInfo);
        if (!classPtr.isNull()) {
            var classNamePtr = il2cpp_class_get_name(classPtr);
            var className = classNamePtr.readUtf8String();
            return className + '.' + methodName;
        }

        return methodName;
    } catch(e) {
        return null;
    }
}

function printDetailedBacktrace(context) {
    console.log('[+] Detailed Stack trace:');
    var trace = Thread.backtrace(context, Backtracer.ACCURATE);

    trace.forEach((addr, idx) => {
        // 获取符号信息
        var symbol = DebugSymbol.fromAddress(addr);
        // 尝试获取方法名
        var methodName = getMethodName(addr);

        console.log(`[${idx}] ${addr} => ${symbol.toString()}${methodName ? ' (' + methodName + ')' : ''}`);
    });
}

function hookSomeFunc(il2cpp, func_addr_offset) {
    console.log("[+] libil2cpp.so base address:", il2cpp);
    console.log("[+] function offset:", func_addr_offset);

    // 0xEDEB1C
    // Module_Mahjong_Data_Config_QuestionDefine__GetDynamicQuestionConfig 0xF3DED8
    // Module_Mahjong_Data_MahjongDataManager__GetQuestion 0xF27E90
    // Module_Mahjong_Data_MahjongPlayData__ParseQuestion(__int64 a1, char a2) 0xF37CB8
    // Module_Mahjong_Data_MahjongDefine__GetCardName(int a1) 0xF376C0
    // Module_Mahjong_Data_MahjongPlayData__ReplaceResourceId(int a1, __int64 a2, __int64 a3, __int64 a4) 0xF3AC44
    // Module_Mahjong_Data_MahjongPlayData__GenerateResourceId(__int64 a1, int a2, char a3) 0xF385EC
    Interceptor.attach(il2cpp.add(func_addr_offset), {
        onEnter: function(args) {
            console.log('[+] Enter:');


//            const resourceId = args[0].toInt32();
//            console.log('[+] resourceId:', resourceId);
//            const isHard = args[0].toInt32();
//            console.log('[+] isHard:', isHard);
//
//            const layer1 = args[1].toInt32();
//            console.log('[+] layer1:', layer1);
//
//            const layer2 = args[2].toInt32();
//            console.log('[+] layer2:', layer2);
//
//            const layer3 = args[3].toInt32();
//            console.log('[+] layer3:', layer3);
//
//            const questionDir = getIl2CppString(args[4]);
//            console.log('[+] questionDir:', questionDir);
        },

        onLeave: function(retval) {
//            console.error('[+] Some func retval : ' + retval);
//            console.error('[+] Some func retval : ' + getIl2CppString(retval));
//            // 处理返回的 ValueTuple<string, string>
//            if (!retval.isNull()) {
//                // ValueTuple 的两个字段是连续存储的
//                const tuplePtr = retval;
//
//                // 读取第一个 string
//                const item1Ptr = tuplePtr.readPointer();
//                const item1 = getIl2CppString(retval);
//
//                // 读取第二个 string
//                const item2Ptr = tuplePtr.add(Process.pointerSize).readPointer();
//                const item2 = getIl2CppString(item2Ptr);
//
//                console.log('[+] Return ValueTuple:');
//                console.log('    Item1:', item1);
//                console.log('    Item2:', item2);
//            }

                // 解析返回的Dictionary结构
                if (!retval.isNull()) {
                    // 获取Dictionary的数据
                    const dict = retval;

                    try {
                        // 遍历并打印Dictionary内容
                        console.log("Dictionary content:");

                        // 这里需要根据Unity的内存布局来解析Dictionary
                        // 以下是示例代码，可能需要根据具体情况调整
                        const count = Memory.readInt(dict.add(0x20)); // Dictionary的count字段偏移
                        console.log(`Dictionary count: ${count}`);

                        // 获取entries数组
                        const entries = Memory.readPointer(dict.add(0x18));

                        for (let i = 0; i < count; i++) {
                            const entry = entries.add(i * 0x18); // 每个entry的大小
                            const key = Memory.readInt(entry);
                            const valuePtr = Memory.readPointer(entry.add(0x8));

                            // 读取List<int>的内容
                            const listCount = Memory.readInt(valuePtr.add(0x18));
                            const listItems = Memory.readPointer(valuePtr.add(0x10));

                            let values = [];
                            for (let j = 0; j < listCount; j++) {
                                values.push(Memory.readInt(listItems.add(j * 4)));
                            }

                            console.log(`Key: ${key}, Values: [${values.join(", ")}]`);
                        }
                    } catch (e) {
                        console.log("Error parsing dictionary:", e);
                    }
                } else {
                    console.log("Return value is null");
                }
        }
    });
}

function hook(func_addr_offset) {
    Java.perform(function() {
        var Activity = Java.use('com.unity3d.player.UnityPlayerActivity');
        Activity.onCreate.implementation = function(bundle) {
            var onCreate = this.onCreate(bundle);

            console.log("[+] Start hooking func_addr_offset: " + func_addr_offset);

            var il2cpp = Module.findBaseAddress('libil2cpp.so');
            if (!il2cpp) {
                console.log("[-] Failed to find libil2cpp.so");
                send({status: "done"});
                return onCreate;
            }

            try {
                hookSomeFunc(il2cpp, func_addr_offset);
            } catch (e) {
                console.log("[-] Error hook func:", e);
                send({status: "done"});
            }

            return onCreate;
        }
    });
}

