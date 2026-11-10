# peek — 手写 PE 解析器

纯 C++ 实现的 Windows PE 文件解析 / 体检工具。零第三方依赖。

**规则：所有代码由本人在指导下手写，Claude 只做路线规划与 code review。**

## 目标形态

```
peek notepad.exe
```

输出：架构（x86 / x86-64）、文件类型（PE32 / PE32+）、子系统、入口点 → 节表（地址 / 大小 / 偏移 / 香农熵）→ 导入表（DLL + 函数名，含按序号导入）。

## 里程碑

- [x] **M0 读文件 + 认 MZ** — 打开任意文件，打印大小，判断是否 PE
- [x] **M1 DOS 头 + 可选头** — 架构、时间戳、入口点、ImageBase、PE32/PE32+
- [x] **M2 节表** — 遍历节，名字/地址/大小/权限位；RVA→文件偏移
- [x] **M3a 数据目录 + 导入表 DLL 列表** — 定位导入表，列出依赖的 DLL
- [x] **M3b 导入函数名** — 走 thunk 数组，输出函数名，支持 PE32/PE32+ 与按序号导入
  - 验收：`System32\notepad.exe` 315 项、`System32\cmd.exe` 287 项、`SysWOW64\notepad.exe` 312 项，与 `objdump -p` 逐项逐序一致
- [x] **M3c 每节香农熵** — 每节熵值，识别可能加壳
  - 验收：两个 notepad 的每节熵值与参考值完全一致；模拟加壳样本 `.text` 熵达 7.9989
- [ ] **M4 扩展（可选）** — 彩色报告、JSON 输出、导出表、单测

## 验证

导入表与 `objdump -p` 逐项逐序比对，DLL 数与函数名完全一致（含按序号导入）：

| 文件 | 架构 | DLL | 导入函数 |
|---|---|---|---|
| System32\notepad.exe | x86-64 | 50 | 315 |
| System32\cmd.exe | x86-64 | 43 | 287 |
| SysWOW64\cmd.exe | x86 | 43 | 284 |
| System32\calc.exe | x86-64 | 7 | 34 |
| System32\charmap.exe | x86-64 | 22 | 294 |
| System32\Magnify.exe | x86-64 | 23 | 548 |
| System32\Taskmgr.exe | x86-64 | 84 | 1111 |
| C:\Windows\explorer.exe | x86-64 | 133 | 794 |
| System32\kernel32.dll | x86-64 | 104 | 1274 |
| System32\user32.dll | x86-64 | 44 | 1118 |
| System32\advapi32.dll | x86-64 | 35 | 656 |
| System32\ntdll.dll | x86-64 | 0 | 0（本身不依赖任何 DLL） |

熵值参考（System32\notepad.exe）：`.text` 6.2382、`.rdata` 5.5819、`.data` 1.6243、`.rsrc` 6.9680。

坏样本回归：

| 样本 | 行为 |
|---|---|
| 非 PE 文件 | 报"文件不是 PE"，退出码 1 |
| `e_lfanew` 篡改为 `0xFFFFFFFD` | 报"超出文件"，退出码 1，不崩溃 |
| 导入目录 RVA 改为 `0xFFFFFFF0` | 报"未找到导入表"，退出码 1，不输出垃圾 |
| `.text` 填充随机字节（模拟加壳） | 该节熵 7.9989，正常报出 |

## 开发环境：Visual Studio

1. 新建项目 → **控制台应用 (C++)** → 名称 `peek` → 位置选本目录
2. 按 F5 = 编译 + 运行
3. 传命令行参数：**项目 → 属性 → 配置属性 → 调试 → 命令行参数**
4. 改完属性记得先关掉正在运行的黑窗口，否则会提示"无法写入文件"

备用命令行（MinGW）：

```bash
g++ -std=c++23 -Wall -Wextra -Wpedantic -g -D_GLIBCXX_ASSERTIONS peek.cpp -o peek.exe
```

MinGW 不支持 ASan/UBSan；想开就把同一份代码丢给 VS 的 MSVC（`/fsanitize=address`）。

## 全程原则

1. **不信任输入**：每个偏移先校验 `offset + size <= file_size` 再读。
2. **拿坏样本自测**：截断/篡改的文件不能让你崩。
3. **每阶段的验收标准必须全过**，才进下一阶段。

## 对照工具

- `objdump -h <file>` — 节表
- `objdump -p <file>` — 头 + 导入表
- [PE-bear](https://github.com/hasherezade/pe-bear) — 图形化逐字段对照
