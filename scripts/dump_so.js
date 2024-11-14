function hook(so_name) {
    Java.perform(function() {
        var Activity = Java.use('com.unity3d.player.UnityPlayerActivity');
        Activity.onCreate.implementation = function(bundle) {
            var onCreate = this.onCreate(bundle);

            var libso = Process.findModuleByName(so_name);
            if (libso == null) {
                console.log("Module not found");
                send({status: "done", msg: "Module not found"});
                return onCreate;
            }

            try {
                console.log(`Module ${so_name} found at ${libso.base}`);
                console.log(`Size: ${libso.size}`);
                const fileName = `${so_name}-${libso.base}.so`;

                var ranges = Process.enumerateRangesSync({
                    protection: 'r--',
                    coalesce: true
                });

                var buffer = new ArrayBuffer(libso.size);
                var view = new Uint8Array(buffer);

                // 填充整个buffer为0
                view.fill(0);

                var copied = false;
                ranges.forEach(function(range) {
                    // 计算相对偏移
                    if (range.base >= libso.base &&
                        range.base < (libso.base.add(libso.size))) {

                        var start = range.base.sub(libso.base);
                        var rangeSize = range.size;

                        // 确保不会超出SO文件的大小
                        if (start.add(rangeSize) > libso.size) {
                            rangeSize = libso.size - start;
                        }

                        console.log(`Copying range: ${range.base} (offset: ${start}), size: ${rangeSize}`);

                        try {
                            var bytes = Memory.readByteArray(range.base, rangeSize);
                            view.set(new Uint8Array(bytes), parseInt(start));
                            copied = true;
                        } catch (e) {
                            console.log(`Failed to read range at ${range.base}: ${e}`);
                        }
                    }
                });

                if (!copied) {
                    console.log("No valid memory ranges found!");
                    send({status: "done", msg: "No valid memory ranges found!"});
                    return onCreate;
                }

                // 验证数据是否有效
                var nonZeroCount = 0;
                for (var i = 0; i < view.length; i++) {
                    if (view[i] !== 0) {
                        nonZeroCount++;
                    }
                }
                console.log(`Non-zero bytes: ${nonZeroCount}`);

                if (nonZeroCount === 0) {
                    console.log("Warning: Dumped file contains only zeros!");
                    send({status: "done", msg: "Warning: Dumped file contains only zeros!"});
                    return onCreate;
                }

                send({status: "callback", callback: {base: libso.base, filename: fileName}}, buffer);
                send({status: "done", msg: "Success"});

                return onCreate;
            } catch (error) {
                console.error('An error occurred:', error.message);
                send({status: "done", msg: `An error occurred: ${error.message}`});
            }

            return onCreate;
        }
    });
}

