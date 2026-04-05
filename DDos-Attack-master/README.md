# DDos-Attack-master（已接入 vortex，仅供合法实验）

原仓库脚本为 **Python 2** 且依赖 `figlet`、无限循环，已改写为 **Python 3** 命令行工具，供 **vortex** 的 `udpstress` 调用。

## 法律与伦理

仅对你**拥有书面授权**的系统使用（自有服务、合同范围内的渗透测试、课程指定靶机等）。  
对未授权目标进行压力测试在多数司法辖区**违法**。使用者自负法律责任。

## 依赖

仅 Python 3.8+ 标准库，无需 `pip install`。

## 单独运行

```bash
cd DDos-Attack-master
python3 ddos-attack.py -t 127.0.0.1 -p 9999 -d 5 --pps 200
```

## 在 vortex 里

```text
vortex> udpstress 192.168.1.50 8080 15
vortex> udpstress -- -t 10.0.0.1 -p 53 -d 3 --pps 100
```

参数说明见 `python3 ddos-attack.py -h`。
