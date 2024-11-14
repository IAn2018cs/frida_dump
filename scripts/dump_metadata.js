// 分块读取和写入大文件
function dumpLargeFile(address, size, chunkSize = 1024 * 1024) {
    console.log(`[+] Starting dump of ${size} bytes to ArrayBuffer`);
    console.log(`[+] Using chunk size: ${chunkSize} bytes`);

    // 创建一个足够大的 ArrayBuffer 来存储所有数据
    const resultBuffer = new ArrayBuffer(size);
    const resultArray = new Uint8Array(resultBuffer);
    let totalRead = 0;

    try {
        // 写入正确的魔数和版本号
        const correctHeader = new Uint8Array([
            0xAF, 0x1B, 0xB1, 0xFA,  // 魔数
            0x1D                     // 版本号
        ]);
        resultArray.set(correctHeader, 0);

        // 跳过内存中的前4（被修改的魔数）+ 1（版本号）个字节
        totalRead = 5;

        while (totalRead < size) {
            const remaining = size - totalRead;
            const currentChunk = Math.min(chunkSize, remaining);

            // 读取内存块
            const buffer = Memory.readByteArray(address.add(totalRead), currentChunk);

            // 将数据复制到结果数组中
            resultArray.set(new Uint8Array(buffer), totalRead);

            totalRead += currentChunk;
            if (totalRead % (chunkSize * 10) === 0) {
                console.log(`[+] Progress: ${(totalRead / size * 100).toFixed(2)}%`);
            }
        }

        console.log("[+] Dump completed successfully");
        return resultBuffer;
    } catch (e) {
        console.log("[-] Error during dump:", e);
        throw e;
    }
}

function getMetadataSize(fileHandle) {
    console.log("[+] Calculating metadata size...");

    let fileOffset = 0x10C;  // exportedTypeDefinitionsCount的位置
    let lastCount = 0;
    let lastOffset = 0;

    while (true) {
        try {
            lastCount = Memory.readInt(fileHandle.add(fileOffset));
            console.log(`[+] Checking offset 0x${fileOffset.toString(16)}, count: ${lastCount}`);

            if (lastCount !== 0) {
                lastOffset = Memory.readInt(fileHandle.add(fileOffset - 4));
                console.log(`[+] Found last section - Offset: 0x${lastOffset.toString(16)}, Count: ${lastCount}`);
                break;
            }

            fileOffset -= 8;
            if (fileOffset <= 0) {
                console.log("[-] Failed to calculate metadata size!");
                return 0;
            }
        } catch(e) {
            console.log(`[-] Error reading at offset 0x${fileOffset.toString(16)}:`, e);
            return 0;
        }
    }

    const totalSize = lastOffset + lastCount;
    console.log(`[+] Calculated metadata size: 0x${totalSize.toString(16)} (${totalSize} bytes)`);
    return totalSize;
}

function dumpMetadata(il2cpp, metadata_load_addr_offset) {
    console.log("[+] libil2cpp.so base address:", il2cpp);
    console.log("[+] Metadata load function offset:", metadata_load_addr_offset);

    Interceptor.attach(il2cpp.add(metadata_load_addr_offset), {
        onLeave: function(retval) {
            if (retval.equals(0)) {
                console.log("[-] Initialize function failed");
                send({status: "done"});
                return;
            }
            console.error('[+] LoadMetaDataFile retval : ' + retval);

            try {
                const fileHandle = retval;

                console.log("[+] Metadata pointer:", fileHandle);

                // 读取并验证头部
                const headerBytes = Memory.readByteArray(fileHandle, 32);
                const header = new Uint8Array(headerBytes);
                console.log("[+] Memory header bytes:", Array.from(header).map(b => b.toString(16).padStart(2, '0')).join(' '));

                // 计算文件大小
                const fileSize = getMetadataSize(fileHandle);
                if (fileSize <= 0) {
                    console.log("[-] Invalid file size");
                    send({status: "done"});
                    return;
                }

                const totalSize = fileSize;
                console.log(`[+] Final size with safety margin: 0x${totalSize.toString(16)} (${totalSize} bytes)`);

                try {
                    Memory.protect(fileHandle, totalSize, 'r');
                } catch (e) {
                    console.log("[!] Memory protection change failed:", e);
                }

                const buffer = dumpLargeFile(fileHandle, totalSize);
                send({status: "callback", callback: {base: fileHandle, filename: "dumped-global-metadata.dat"}}, buffer);
                send({status: "done"});
            } catch (e) {
                console.log("[-] Error in onLeave:", e);
                console.log(e.stack);
                send({status: "done"});
            }
        }
    });
}

function hook(metadata_load_addr_offset) {
    Java.perform(function() {
        var Activity = Java.use('com.unity3d.player.UnityPlayerActivity');
        Activity.onCreate.implementation = function(bundle) {
            var onCreate = this.onCreate(bundle);

            console.log("[+] Start hooking metadata_load_addr_offset: " + metadata_load_addr_offset);

            var il2cpp = Module.findBaseAddress('libil2cpp.so');
            if (!il2cpp) {
                console.log("[-] Failed to find libil2cpp.so");
                send({status: "done"});
                return onCreate;
            }

            try {
                dumpMetadata(il2cpp, metadata_load_addr_offset);
            } catch (e) {
                console.log("[-] Error setting up metadata dump:", e);
                send({status: "done"});
            }

            return onCreate;
        }
    });
}

