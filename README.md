# Unity frida_dump

## 0. 环境准备

1. Android 手机 root
2. 安装 Frida 服务
3. 安装本项目环境依赖 `pip install -r requirements.txt`

## 1. 导出 Unity 游戏的 so 文件

### 使用方法:

查看参数：
```commandline
python dump_so.py --h    
```
```text
options:
  -h, --help            show this help message and exit
  -p PACKAGE, --package PACKAGE
                        android package name
  -s SO, --so SO        so name e.g. libil2cpp.so
  -o OUTPUT, --output OUTPUT
                        output directory (default: current directory), e.g. "*/{packageName}"
```

运行示例：
```commandline
python dump_so.py -p com.vitastudio.mahjong -o ./output/
```

最终会在 output/package/ 下生成两个 so 文件：
* XXX.so-起始地址.so（直接内存导出的）
* XXX.so-起始地址.fix.so（修复后的）

## 2. 导出 Unity 游戏的 global-metadata 文件

### 使用方法:

1. 使用 IDA Pro 打开第一步导出的修复后的 .so 文件
2. 搜索字符串（Shift + F12）global-metadata
3. 点击搜索结果，找到 aGlobalMetadata 字样
4. 在 aGlobalMetadata 上按 X 键，找到使用的地方
5. 然后按 F5 反编译
6. 找到 `sub_XXXXXX("global-metadata.dat")` 代码
7. 其中 sub_XXXXXX 的 XXXXXX 就是 LoadMetadataFile 方法的偏移地址，记下 0xXXXXXX
8. 开始运行 `dump_metadata.py`

查看参数：
```commandline
python dump_metadata.py --h    
```
```text
options:
  -h, --help            show this help message and exit
  -p PACKAGE, --package PACKAGE
                        android package name
  -a ADDR, --addr ADDR  LoadMetadataFile function addr offset, e.g. 0xCB90B0
  -o OUTPUT, --output OUTPUT
                        output directory (default: current directory), e.g. "*/{packageName}"
```

运行示例：
```commandline
python dump_metadata.py -p 'com.vitastudio.mahjong' -a '0xCEB484' -o ./output/
```

最终会在 output/package/ 下生成 dumped-global-metadata.dat 文件：
* dumped-global-metadata.dat（直接内存导出的 metadata，修复了头信息中的魔数，版本号固定成了 29/0x1D）


## 3. 使用 [Il2CppDumper](https://github.com/Perfare/Il2CppDumper/tree/master) 导出结构信息

### 使用方法:

```commandline
.\Il2CppDumper.exe <第一步中修复的 so 文件> <第二步中导出的 metadata 文件> <output-directory>
```

执行后会提示输入 so 文件的起始地址，这里直接输入 0 就行
```text
Input il2cpp dump address or input 0 to force continue:
0
```


## 感谢

* [https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)
* [https://github.com/lasting-yang/frida_dump](https://github.com/lasting-yang/frida_dump)
* [https://hexed.it/](https://hexed.it/)