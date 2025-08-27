from pwn import *
def disassemble_from_offset(file_data, base_address, offset, lines=10):
    """
    从指定偏移开始反汇编指定行数的代码
    
    Args:
        file_data: 二进制文件数据
        base_address: 基地址
        offset: 要开始反汇编的偏移量
        lines: 要反汇编的行数
    """
    # 计算实际内存地址
    current_address = base_address + offset
    
    # 从偏移量开始获取数据
    code_to_disassemble = file_data[offset:]
    
    # 反汇编代码
    try:
        disassembled = disasm(code_to_disassemble, vma=current_address, arch='amd64')
        
        # 按行分割并获取前lines行
        lines_list = disassembled.split('\n')[:lines]
        
        # 打印结果
        print(f"从地址 0x{current_address:x} (偏移量 {offset}) 开始的反汇编:")
        for line in lines_list:
            print(line)
        print()
    except Exception as e:
        print(f"在偏移量 {offset} 处反汇编时出错: {e}")

def main():
    # 二进制文件名
    filename = 'main'
    
    # main函数起始地址
    main_start = 0x1200
    
    try:
        # 读取整个二进制文件
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        # 计算main函数在文件中的偏移量
        # 假设文件是从地址0开始加载的
        main_offset = main_start
        
        # 确保偏移量不超过文件大小
        if main_offset >= len(file_data):
            print(f"错误: main函数偏移量(0x{main_offset:x})超出文件大小(0x{len(file_data):x})")
            return
        
        # 计算main函数区域的大小 (0x1300 - 0x1200 = 0x100)
        main_size = 0x1381-0x1204
        
        # 确保不超出文件边界
        if main_offset + main_size > len(file_data):
            main_size = len(file_data) - main_offset
            print(f"警告: main函数区域超出文件边界，调整为0x{main_size:x}字节")
        
        # 提取main函数的数据
        main_data = file_data[main_offset:main_offset+main_size]
        
        # 遍历每个字节偏移
        for offset in range(0, main_size):
            disassemble_from_offset(main_data, main_start, offset, lines=10)
            
    except FileNotFoundError:
        print(f"错误: 找不到文件 '{filename}'")
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    main()
