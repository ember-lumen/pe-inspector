#include <iostream>
#include <fstream>
#include <vector>
#include<algorithm>
#include <cmath>      
#include <iomanip>    
using namespace std;
bool read_2byte(const vector<unsigned char>& buf,long long size,long long index,unsigned int& ret_2bit) {
    if (index + 1 > size - 1) {
        cout << "超出文件" << endl;
        return false;
    }
    unsigned int b0 = static_cast<unsigned int>(buf[index]);
    unsigned int b1 = static_cast<unsigned int>(buf[index + 1]);
    ret_2bit = b0 | (b1 << 8);
    return true;
}
bool read_4byte(const vector<unsigned char>& buf, long long size, long long index,unsigned long long& ret_4bit) {
    if (index + 3 > size - 1) {
        cout << "超出文件" << endl;
        return false;
    }
    unsigned int b0 = static_cast<unsigned int>(buf[index]);
    unsigned int b1 = static_cast<unsigned int>(buf[index + 1]);
    unsigned int b2 = static_cast<unsigned int>(buf[index + 2]);
    unsigned int b3 = static_cast<unsigned int>(buf[index + 3]);
    ret_4bit = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    return true;
}
bool read_8byte(const vector<unsigned char>& buf, long long size, long long index, unsigned long long& ret_8bit) {
    if (index + 7 > size - 1) {
        cout << "超出文件" << endl;
        return false;
    }
    unsigned long long b0 = static_cast<unsigned long long>(buf[index]);
    unsigned long long b1 = static_cast<unsigned long long>(buf[index + 1]);
    unsigned long long b2 = static_cast<unsigned long long>(buf[index + 2]);
    unsigned long long b3 = static_cast<unsigned long long>(buf[index + 3]);
    unsigned long long b4 = static_cast<unsigned long long>(buf[index + 4]);
    unsigned long long b5 = static_cast<unsigned long long>(buf[index + 5]);
    unsigned long long b6 = static_cast<unsigned long long>(buf[index + 6]);
    unsigned long long b7 = static_cast<unsigned long long>(buf[index + 7]);
    ret_8bit = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
    return true;
}
struct Section {
    string name;
    unsigned long long virtual_size;      //内存大小
    unsigned long long virtual_address;   //内存地址
    unsigned long long raw_size;          //文件大小
    unsigned long long raw_ptr;           //文件起点
    unsigned long long characteristics;
};
//rva转文件偏移(RVA = Relative Virtual Address，相对虚拟地址)  距离镜像基址多远
bool rva_to_offset(const vector<Section>& sec, unsigned int rva,unsigned long long& out) {  //out:文件坐标
    unsigned long long valid_size;
    for (int i = 0; i < sec.size(); i++) {
        if (sec[i].raw_size == 0) {
            continue;
        }
        valid_size = max(sec[i].raw_size, sec[i].virtual_size);
        if (rva >= sec[i].virtual_address && rva < sec[i].virtual_address + valid_size) {
            out = rva - sec[i].virtual_address + sec[i].raw_ptr;
            return true;
        }
    }
    return false;
}
//读取c字符串
bool read_cstr(const vector<unsigned char>& buf, long long size,unsigned long long index,string& out) {
    if (index > size-1) {
        return false;
    }
    int cnt = 0;
    out.clear();
        for (unsigned long long i = index; i<size ; i++) {
            if (buf[i] == 0x00) {
                break;
            }
            if (cnt == 256) {
                return false;
            }
            out.push_back(buf[i]);
            cnt++;
        }
        return true;
}
//计算熵
double cal_entropy(const vector<unsigned char>& buf, unsigned long long start, unsigned long long len) {
    unsigned long long cnt[256] = {};
    for (long long i = start; i < start + len; i++) {
        cnt[buf[i]]++;
    }
    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (cnt[i] == 0) {
            continue;
        }// 跳过没出现过的字节，否则 log2(0) 炸
        double p = static_cast<double>(cnt[i]) / len;   // ← 必须转 double
        H -= p * log2(p);
    }
    return H;
}
int main(int argc,char** argv)
{
    //cout << "程序      "<< argv[0] << endl;
    if (argc < 2) {
        cout << "文件传入失败" << endl;
        return 1;
    }
    cout << "文件      " << argv[1] << endl;
    ifstream fin(argv[1], ios::in | ios::binary);
    if (!fin.is_open()) {
        cout << "文件打开失败" << endl;
        return 1;
    }
    fin.seekg(0, ios::end);
    streampos size = fin.tellg();
    cout << "大小      " << size <<" 字节" << endl << endl;
    fin.seekg(0, ios::beg);
    if (size < 2) {
        cout << "文件不是 PE " << endl;
        return 1;
    }
    long long long_size = static_cast<long long>(size);
    vector<unsigned char> buf(long_size);
    fin.read(reinterpret_cast<char*>(buf.data()), buf.size());
    streamsize size_got = fin.gcount();
    if (size_got != static_cast<streamsize>(buf.size())) {
        cout << "文件读取不全" << endl;
        return 1;
    }
    int num_buf0 = static_cast<int>(buf[0]);
    int num_buf1 = static_cast<int>(buf[1]);
    /*cout << argv[1] << "文件第一个字节是" << buf[0] << '/' << num_buf0 << endl;
    cout << argv[1] << "文件第二个字节是" << buf[1] << '/'<<num_buf1<< endl;*/
    if (num_buf0 == 77 && num_buf1 == 90) {
        //cout << "文件是 PE " << endl << endl;
    }
    else {
        cout << "文件不是 PE " << endl;
        return 1;
    }
    unsigned long long e_lfanew;
    if (!read_4byte(buf, long_size, 0x3C, e_lfanew)) {
        cout << "读取 e_lfanew 失败" << endl;
        return 1;
    }//拼成DOS头
    long long pe_off = static_cast<long long>(e_lfanew);
    //cout << "e_lfanew = " << e_lfanew << " (0x" << hex << e_lfanew << dec << ")" << endl;
    if (pe_off + 3 > long_size - 1) {
        cout << " 超出文件" << endl;
        return 1;
    }
    unsigned int b0_1 = static_cast<unsigned int>(buf[pe_off]);
    unsigned int b1_1 = static_cast<unsigned int>(buf[pe_off + 1]);
    unsigned int b2_1 = static_cast<unsigned int>(buf[pe_off + 2]);
    unsigned int b3_1 = static_cast<unsigned int>(buf[pe_off + 3]);
    //获取PE头
    cout << "[PE 头]" << endl;
    /*cout << "  " << buf[pe_off] << "->" << b0_1 << " ";
    cout << buf[pe_off + 1] << "->" << b1_1 << " ";
    cout << buf[pe_off +2] << "->" << b2_1 << " ";
    cout << buf[pe_off + 3] << "->" << b3_1 << endl ;*/
    if (!(b0_1 == 80 && b1_1 == 69 && b2_1 == 0 && b3_1 == 0)) {
        cout << "打印 PE 签名错误" << endl;
        return 1;
    }

    long long base = pe_off;
    unsigned int Machine;
    if (!read_2byte(buf, long_size, base+4, Machine)) {
        cout << "读取 Machine 失败" << endl;
        return 1;
    }
    unsigned int NumberOfSections;
    if (!read_2byte(buf, long_size, base + 6, NumberOfSections)) {
        cout << "读取 NumberOfSections 失败" << endl;
        return 1;
    }
    unsigned long long TimeDateStamp;
    if (!read_4byte(buf, long_size, base + 8, TimeDateStamp)) {
        cout << "读取 TimeDateStamp 失败" << endl;
        return 1;
    }
    unsigned int Magic;
    if (!read_2byte(buf, long_size, base + 24, Magic)) {
        cout << "读取 Magic 失败" << endl;
        return 1;
    }
    unsigned long long AddressOfEntryPoint;
    if (!read_4byte(buf, long_size, base + 24 + 16, AddressOfEntryPoint)) {
        cout << "读取 AddressOfEntryPoint 失败" << endl;
        return 1;
    }
    unsigned int Subsystem;
    if (!read_2byte(buf, long_size, base + 24 + 68, Subsystem)) {
        cout << "读取 Subsystem 失败" << endl;
        return 1;
    }
    /*Machine              架构      0x014C：x86（32 位） / 0x8664：x86-64 / 0xAA64：ARM64
    NumberOfSections       节的数量
    TimeDateStamp          时间戳
    Magic                  文件类型  0x10B： PE32（32 位）/ 0x20B： PE32+（64 位）	
    AddressOfEntryPoint    入口点    程序启动后第一条指令的地址。注意它是 RVA，不是文件偏移。
    Subsystem              子系统    1：Native（驱动级别）/2：GUI（图形界面）/ 3：Console（控制台）/ 10：EFI 应用
    */
    /*cout << "  Machine = " << Machine << " (0x" << hex << Machine << dec << ")" << endl;
    cout << "  NumberOfSections = " << NumberOfSections << " (0x" << hex << NumberOfSections << dec << ")" << endl;
    cout << "  TimeDateStamp = " << TimeDateStamp << " (0x" << hex << TimeDateStamp << dec << ")" << endl;
    cout << "  Magic = " << Magic << " (0x" << hex << Magic << dec << ")" << endl;
    cout << "  AddressOfEntryPoint = " << AddressOfEntryPoint << " (0x" << hex << AddressOfEntryPoint << dec << ")" << endl;
    cout << "  Subsystem = " << Subsystem << " (0x" << hex << Subsystem << dec << ")" << endl << endl;*/
    cout << "  架构          ";
    if (Machine == 0x014C) {
        cout << "x86（32 位）" << endl;
    }
    else if (Machine == 0x8664) {
        cout << "x86-64" << endl;
    }
    else if(Machine==0XAA64){
        cout << "ARM64" << endl;
    }
    cout << "  节的数量      " << NumberOfSections << endl;
    cout << "  时间戳        " << TimeDateStamp << endl;
    cout << "  文件类型      " ;
    if (Magic == 0x10B) {
        cout << "PE32（32 位）" << endl;
    }
    else if (Magic == 0x20B) {
        cout << "PE32+（64 位）" << endl;
    }
    cout << "  入口点        " << AddressOfEntryPoint <<endl;
    cout << "  子系统        ";
    if (Subsystem == 1) {
        cout << "Native（驱动级别）" << endl;
    }
    else if (Subsystem == 2) {
        cout << "GUI（图形界面）" << endl;
    }
    else if (Subsystem == 3) {
        cout << "Console（控制台）" << endl;
    }
    else if (Subsystem == 10) {
        cout << "EFI 应用" << endl;
    }
    cout << endl;
    unsigned int SizeOfOptionalHeader;
    if (!read_2byte(buf, long_size, base + 20, SizeOfOptionalHeader)) {
        cout << "读取 SizeOfOptionalHeader 失败" << endl;
        return 1;
    }
    long long section_table = pe_off + 24 + SizeOfOptionalHeader;//节表起点
    /*cout << "节表起点为";
    cout << section_table << endl;*/
    //section_table + NumberOfSections * 40  不能超过文件大小
    if (section_table + NumberOfSections * 40 > long_size - 1) {
        cout << "超出文件" << endl;
        return 1;
    }
    vector<Section> sec;
    for (int i = 0; i < NumberOfSections; i++) {
        long long curr = section_table + i * 40;
        Section s;
        for (int k1 = 0; k1 < 8; k1++) {
            if (buf[curr + k1] == 0) {
                break;                        // 遇到 0，立刻跳出这个循环
            }
            s.name.push_back(buf[curr + k1]);
        }
        if (!read_4byte(buf, long_size, curr + 8, s.virtual_size)) {
            cout << "读取sec "<<i<<" 的"<< "virtual_size 失败" << endl;
            return 1;
        }
        if (!read_4byte(buf, long_size, curr + 12, s.virtual_address)) {
            cout << "读取sec " << i << " 的" << "virtual_address 失败" << endl;
            return 1;
        }
        if (!read_4byte(buf, long_size, curr + 16, s.raw_size)) {
            cout << "读取sec " << i << " 的" << "raw_size 失败" << endl;
            return 1;
        }
        if (!read_4byte(buf, long_size, curr + 20, s.raw_ptr)) {
            cout << "读取sec " << i << " 的" << "raw_ptr 失败" << endl;
            return 1;
        }
        if (!read_4byte(buf, long_size, curr + 36, s.characteristics)) {
            cout << "读取sec " << i << " 的" << "characteristics 失败" << endl;
            return 1;
        }
        sec.push_back(s);
    }
    cout << "[节表]" << endl;
    for (int i = 0; i < sec.size();i++) {
        cout <<"  " << sec[i].name << "  vsize=0x" << hex << sec[i].virtual_size
            << "  va=0x" << sec[i].virtual_address
            << "  raw=0x" << sec[i].raw_size
            << "  ptr=0x" << sec[i].raw_ptr
            << "  ch=0x" << sec[i].characteristics << dec ;
        if (sec[i].raw_size == 0) {
            cout << "entropy = -" << endl;
        }
        else if (sec[i].raw_ptr + sec[i].raw_size > long_size) {
            cout << "entropy = 越界" << endl;
        }
        else {
            double H = cal_entropy(buf, sec[i].raw_ptr, sec[i].raw_size);
            cout << fixed << setprecision(4) <<" entropy = " << H << endl;
        }
    }
    cout << endl;
    unsigned long long file_begin;
    if (Magic == 0x20B) {
        file_begin = base + 24 + 112;
    }
    else if (Magic == 0x10B) {
        file_begin = base + 24 + 96;
    }
    else {
        cout << "获取数据目录失败" << endl;
        return 1;
    }
    /*cout << "数据目录为";
    cout << file_begin << endl;*/

    unsigned long long rva;
    if (read_4byte(buf,long_size, file_begin + 8, rva)) {
        //cout <<"导入目录表的RVA为" << "0x" << hex << rva << dec << endl;
    }

    unsigned long long file_offset;
    if (rva_to_offset(sec, rva, file_offset)) {
        //cout <<"导入表起点为" << "0x" << hex << file_offset << dec << endl;
    }
    else {
        cout << "未找到导入表" << endl;
        return 1;
    }
 
    unsigned long long curr = file_offset;
    int cnt=0;
    while (cnt < 1024) {
        if (curr + 20 > long_size) {
            cout << "超出文件" << endl;
            break;
        }   
        unsigned long long oft_rva;                   //OriginalFirstThunk (通过函数转换后存的是值，之前是地址)
        read_4byte(buf, long_size, curr, oft_rva);
        unsigned long long name_rva;                  //DLL 名字的 RVA
        read_4byte(buf, long_size, curr + 12, name_rva);

        if (oft_rva == 0 && name_rva == 0) {
            break;
        }

        if (cnt == 0) { 
            cout << "[导入表]" << endl;
        }
        else {
            cout << endl;
        }
        unsigned long long name_off;                              //打印dll的名字
        if (rva_to_offset(sec, name_rva, name_off)) {
            string dll_name;
            if (read_cstr(buf, long_size, name_off, dll_name)) {
                cout << "  ";
                for (int i = 0; i < dll_name.size(); i++) {
                    cout << dll_name[i];  //打印字符串，只打出一个名字
                }
                cout << endl ;
            }
        }

        unsigned long long thunk_rva = oft_rva;                        //打印每个dll里面的函数名称
        if (thunk_rva == 0) {
            read_4byte(buf, long_size, curr + 16, thunk_rva);  // curr+16是地址，把"值"读出来
        }
        unsigned long long thunk_off;
        if (rva_to_offset(sec, thunk_rva, thunk_off)) {
            unsigned long long wide;
            if (Magic == 0x10B) {
                wide = 4;
            }
            else {
                wide = 8;
            }
            unsigned long long flag_mask = wide == 4 ? 0x80000000ULL : 0x8000000000000000ULL;
            unsigned long long ord_mask = wide == 4 ? 0x7FFFFFFFULL : 0x7FFFFFFFFFFFFFFFULL;

            while (1) {
                if (thunk_off + wide > long_size) {
                    break;
                }
                unsigned long long func_num;
                if (wide == 4) {
                    read_4byte(buf, long_size, thunk_off, func_num);
                }
                if (wide == 8) {
                    read_8byte(buf, long_size, thunk_off, func_num);
                }
                if (func_num == 0) {
                    break;
                }
                if ((func_num & flag_mask) != 0) {
                    unsigned long long ord_num = func_num & ord_mask;
                    cout << "    ";
                    cout << '[' << ord_num << ']' << endl;                //打印序数
                }
                else {
                    unsigned long long func_off;
                    if (rva_to_offset(sec, func_num, func_off)) {
                        string func_name;
                        if (read_cstr(buf, long_size, func_off+2, func_name)) {
                            cout << "    ";
                            for (int i = 0; i < func_name.size(); i++) {
                                cout << func_name[i];                          //打印字符串，只打出一个名字
                            }
                            cout << endl ;
                        }
                    }

                }
                thunk_off += wide;
            }
        }
        curr += 20;
        cnt++;
    }

}
 

