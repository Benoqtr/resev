# resev
内部使用抢羽毛球

# windows

## 抓包
```
irm https://raw.githubusercontent.com/Benoqtr/resev/main/getID.ps1 | iex
```
执行后，打开企业微信或微信和体育馆交互一下会自动抓id

## 抢馆
```
irm https://raw.githubusercontent.com/Benoqtr/resev/main/install.ps1 | iex
```

# notice
为防止意外，脚本有过期时间，停止维护后，过期后无法使用

# Linux
linux不提供抓包，下载仓库的fast_reservation后
```
chmod +x fast_reservation
./fast_reservation
```
