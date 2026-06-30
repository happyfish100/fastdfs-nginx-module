

# fastdfs-nginx-module

FastDFS Nginx 模块

## 项目简介

fastdfs-nginx-module 是一个 Nginx 模块，用于直接通过 Nginx 访问 FastDFS 存储系统中的文件。该模块作为 Nginx 与 FastDFS 存储之间的桥梁，支持 HTTP 协议访问 FastDFS 中的文件，无需通过 FastDFS Client。

## 功能特性

- **HTTP 协议访问**：通过 Nginx HTTP 协议访问 FastDFS 存储的文件
- **支持断点续传**：支持 HTTP Range 请求，可实现断点续传和分段下载
- **FLV 流媒体支持**：内置 FLV 流媒体支持，适用于视频点播场景
- **代理模式**：支持代理模式，可将请求转发到后端 FastDFS 存储服务器
- **重定向模式**：支持重定向模式，直接返回 FastDFS 存储服务器地址
- **多组支持**：支持多个存储组配置
- **自定义 HTTP 头**：支持自定义 HTTP 响应头
- **文件下载回调**：支持文件下载回调处理

## 环境要求

- Nginx 1.x 版本
- FastDFS 5.x 版本
- libfastcommon

## 安装配置

### 1. 编译安装

```bash
# 配置 Nginx 并指定模块路径
./configure --add-module=/path/to/fastdfs-nginx-module/src

# 编译安装
make
make install
```

### 2. 配置 Nginx

在 Nginx 配置文件中添加 FastDFS 模块配置：

```nginx
location /M00 {
    fastdfs;
    
    # 配置文件路径
    mod_fastdfs.conf;
}
```

### 3. 配置 mod_fastdfs.conf

复制并修改配置文件：

```bash
cp mod_fastdfs.conf /etc/fdfs/mod_fastdfs.conf
```

主要配置项：

```ini
# 连接超时时间
connect_timeout=10

# 网络超时时间
network_timeout=30

# FastDFS tracker 服务器地址
tracker_server=192.168.0.100:22122

# 存储组名称
group_name=group0

# 是否输出响应头
http.server_charset=UTF-8

# 防盗链配置
anti_steal_check=no

# FLV 支持
flv_support=yes
flv_extension=flv
```

## 配置说明

### 响应模式

模块支持两种响应模式：

- **代理模式 (proxy)**：Nginx 代理请求到 FastDFS 存储服务器
- **重定向模式 (redirect)**：返回存储服务器地址，由客户端直接访问

### HTTP 头支持

- Content-Type
- Content-Length
- Content-Range
- Accept-Ranges
- Content-Disposition
- Location

### 路径格式

访问路径格式：`/group_name/M00/xxx/xxx/xxx`

或使用存储 ID：`/M00/xxx/xxx/xxx`

## 使用示例

### 访问文件

```
http://your-domain/group_name/M00/00/00/abc.jpg
```

### FLV 视频播放

```
http://your-domain/group_name/M00/00/00/video.flv
```

### 断点续传

使用 HTTP Range 请求：

```
GET /group_name/M00/00/00/video.flv HTTP/1.1
Range: bytes=0-1023
```

## 相关链接

- FastDFS 官网：https://github.com/happyfish100/fastdfs
- FastDFS Wiki：https://github.com/happyfish100/fastdfs/wiki

## 许可证

GPL v3 License

## 问题反馈

如有问题，请在 GitHub 或 Gitee 提交 Issue。