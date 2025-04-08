# exit -> 任意地址

[参考地址](https://cloud.tencent.com/developer/article/2063702)

fini_array函数指针无法被修改，经查阅资料，在exit()过程中会调用**_dl_fini**, 伪造.fini_array到可控内存

(0x403e18+0x1e8=0x404000)

在0x404000的地方填上要调用的地址，

r15在正常情况下都等于0，要改为0x1e8

![202302141647331676364453](https://tinyfat.oss-cn-shanghai.aliyuncs.com/uPic/202302141647331676364453.png)

![202302141652011676364721](https://tinyfat.oss-cn-shanghai.aliyuncs.com/uPic/202302141652011676364721.png)


调试发现r15为，_dl_fini函数时，栈顶（rsp）内容
![202302141652161676364736](https://tinyfat.oss-cn-shanghai.aliyuncs.com/uPic/202302141652161676364736.png)

格式化字符串的时候，可以算出偏移量$58, 写入0x1e8即可