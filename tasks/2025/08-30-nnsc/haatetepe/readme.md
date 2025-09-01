# 漏洞
“GET”请求头，超过16字节可以溢出覆盖url
```
  strcpy(method_str, header[0]);
  req->method = parse_method(method_str);
  strcpy(req->path, path);
```

# getshell
![](https://r2.20161023.xyz/pic/20250830171500950.png)