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

function writeToFile(buffer, file, packageName) {
    const fileName = `/data/data/${packageName}/files/dump_${file}_${new Date().getTime()}.bin`;
    try {
        const f = new File(fileName, "wb");
        f.write(buffer);
        f.flush();
        f.close();
        console.log('[+] Successfully saved to:', fileName);
        return true;
    } catch (error) {
        console.log('[!] Failed to save file:', error);
        return false;
    }
}

function dumpConf() {
    Interceptor.attach(il2cpp.add(0xEDB2F4), {
        onEnter: function(args) {
            const file = getIl2CppString(args[1]);
            const dataCount = args[2].toInt32();
            console.log('[+] Enter: CreateConfig, file:', getIl2CppString(args[1]), ', dataCount:', dataCount);

            // args[0] 是 bytes 数组的指针
            const bytesPtr = args[0];
            console.log('[+] bytesPtr:', bytesPtr);

            if (!bytesPtr.isNull()) {
                try {
                    // 读取长度
                    const length = Memory.readInt(bytesPtr.add(24));
                    console.log('[+] Array length:', length);

                    // 尝试直接从 bytesPtr 开始读取数据
                    const buffer = Memory.readByteArray(bytesPtr, length);

                    // 获取包名
                    const packageName = "com.vitastudio.mahjong";

                    // 保存文件
                    writeToFile(buffer, file, packageName);

                    // 打印前32个字节用于验证
                    let hexString = '';
                    new Uint8Array(buffer).slice(0, 32).forEach(byte => {
                        hexString += byte.toString(16).padStart(2, '0') + ' ';
                    });
                    console.log('[+] First 32 bytes:', hexString);

                } catch (error) {
                    console.log('[!] Error:', error);
                }
            }
        }
    });
}

function hookCardFaceFunc(il2cpp) {
    console.log("[+] libil2cpp.so base address:", il2cpp);

    Interceptor.attach(il2cpp.add(0xF385EC), {
        onEnter: function(args) {
            const level = args[1].toInt32();
            const isStatic = args[2].toInt32();

            console.log('[+] Enter: GenerateResourceId, level:', level, ', isStatic:', isStatic);
        }
    });

    // RVA: 0xF0D8AC Offset: 0xF0D8AC VA: 0xF0D8AC
    // public void UpdateCardFace() { }
    // this._cellData = 0xA0
    // CellData.CardId = 0x18
//    Interceptor.attach(il2cpp.add(0xF0D8AC), {
//        onEnter: function(args) {
//            const thisPtr = this.context.x0;
//            // 读取 this._cellData (偏移 0xA0)
//            const cellDataPtr = thisPtr.add(0xA0).readPointer();
//
//            // 读取 _cellData.CardId (偏移 0x18)
//            const cardId = cellDataPtr.add(0x18).readInt();
//
//            console.log('[+] Enter: get_CardId:', cardId);
//        }
//    });

    // dumpConf();


    // RVA: 0xF376C0 Offset: 0xF376C0 VA: 0xF376C0
    // public static string GetCardName(int resourceId) { }
//    Interceptor.attach(il2cpp.add(0xF376C0), {
//        onEnter: function(args) {
//            const resourceId = args[0].toInt32();
//            console.log('[+] Enter: GetCardName, resourceId:', resourceId);
//        },
//
//        onLeave: function(retval) {
//            console.error('[+] GetCardName retval:' + getIl2CppString(retval));
//        }
//    });
}

function hook() {
    Java.perform(function() {
        var Activity = Java.use('com.unity3d.player.UnityPlayerActivity');
        Activity.onCreate.implementation = function(bundle) {
            var onCreate = this.onCreate(bundle);

            console.log("[+] Start hooking card face");

            var il2cpp = Module.findBaseAddress('libil2cpp.so');
            if (!il2cpp) {
                console.log("[-] Failed to find libil2cpp.so");
                send({status: "done"});
                return onCreate;
            }

            try {
                hookCardFaceFunc(il2cpp);
            } catch (e) {
                console.log("[-] Error hook func:", e);
                send({status: "done"});
            }

            return onCreate;
        }
    });
}

