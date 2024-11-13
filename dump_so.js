rpc.exports = {
    findmodule: function(so_name) {
        var libso = Process.findModuleByName(so_name);
        return libso;
    },
    dumpmodule: function(so_name) {
        var libso = Process.findModuleByName(so_name);
        if (libso == null) {
            console.log("Module not found");
            return -1;
        }

        try {
            console.log(`Module ${so_name} found at ${libso.base}`);
            console.log(`Size: ${libso.size}`);

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
                return -1;
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
                return -1;
            }

            return buffer;
        } catch (error) {
            console.error('An error occurred:', error.message);
            return -1;
        }
    },
    allmodule: function() {
        return Process.enumerateModules()
    },
    arch: function() {
        return Process.arch;
    }
}