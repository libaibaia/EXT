# EXT
# BurpSuite插件

- 检测ACCESSKEYID泄露及fastjson漏洞检测
  - 配置文件需要更改一下
![image](https://user-images.githubusercontent.com/108923559/221423179-c7373415-4eef-4652-953a-f8e46b9f8a34.png)


- 这里使用的dnslog平台是http://dnslog.pw
- 配置文件中修改红框中的内容即可
![image](https://user-images.githubusercontent.com/108923559/221423215-2ea8c460-a3fd-450d-a010-9e63c5a95db8.png)


- 修改为打包，当然也可以直接改jar包的配置文件
- 检测结果，目前主要还是基于字典的形式检测，然后fastjson如果有dnslog响应的话是威胁类型是高，图里面是之前没修改的
- 主被动方式都支持，如果不想检测在插件里面关闭即可
![image](https://user-images.githubusercontent.com/108923559/221423248-29684741-868d-4d72-9b52-eee57b01f4ef.png)

