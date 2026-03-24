# TFTP Server

一个用 C 语言实现的最小 TFTP 服务端，默认监听 `69/udp`，也支持通过命令行指定其他端口用于本地调试和压测。

## 功能

- 使用默认 TFTP 端口 `69/udp`
- 支持通过命令行覆盖监听端口
- 支持 `RRQ` 下载
- 支持 `WRQ` 上传，并允许覆盖已存在文件
- 仅支持 `octet` 模式
- 使用 `fork()` 为每个传输请求分配独立会话
- 默认根目录为 `./data`

## 构建

```bash
cmake -S . -B build
cmake --build build
```

生成可执行文件：

```bash
./build/tftp_server
```

注意：绑定 `69/udp` 通常需要 root 权限，因此一般需要这样运行：

```bash
sudo ./build/tftp_server
```

如果不想直接用 `root` 启动，也可以给二进制添加绑定低位端口能力：

```bash
sudo setcap 'cap_net_bind_service=+ep' ./build/tftp_server
./build/tftp_server
```

也可以指定服务端根目录：

```bash
sudo ./build/tftp_server /srv/tftp
```

本地无 root 权限时，可以改用高位端口：

```bash
./build/tftp_server ./data 1069
```

## 测试

下载文件：

```bash
tftp 127.0.0.1 1069
tftp> binary
tftp> get test.txt
```

上传文件：

```bash
tftp 127.0.0.1 1069
tftp> binary
tftp> put local.txt
```

如果服务端目录中已经存在同名文件，新的上传内容会覆盖旧文件。

本地压测脚本：

```bash
python3 tests/stress_tftp.py --server-binary ./build/tftp_server --port 1069
```

## Docker

构建镜像：

```bash
docker build -t tftp-server .
```

使用默认端口 `69/udp` 运行：

```bash
docker run --rm -p 69:69/udp -v "$(pwd)/data:/srv/tftp" tftp-server
```

如果需要改端口，可以覆盖启动参数：

```bash
docker run --rm -p 1069:1069/udp -v "$(pwd)/data:/srv/tftp" tftp-server /srv/tftp 1069
```

## 目录说明

- 服务端会在根目录下读写文件
- 为了安全，拒绝包含 `..`、绝对路径、反斜杠的文件名
