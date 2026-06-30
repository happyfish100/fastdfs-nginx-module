# fastdfs-nginx-module

FastDFS Nginx Module

## Project Overview

fastdfs-nginx-module is an Nginx module designed to enable direct access to files stored in FastDFS via Nginx. This module acts as a bridge between Nginx and FastDFS storage, allowing HTTP protocol access to files in FastDFS without requiring the FastDFS Client.

## Features

- **HTTP Protocol Access**: Access files stored in FastDFS via Nginx using the HTTP protocol.
- **Resume Support**: Supports HTTP Range requests for resumable downloads and segmented downloading.
- **FLV Streaming Support**: Built-in FLV streaming support suitable for video-on-demand scenarios.
- **Proxy Mode**: Supports proxy mode to forward requests to backend FastDFS storage servers.
- **Redirect Mode**: Supports redirect mode to return the direct address of the FastDFS storage server.
- **Multi-Group Support**: Supports configuration of multiple storage groups.
- **Custom HTTP Headers**: Supports customization of HTTP response headers.

## System Requirements

- Nginx version 1.x
- FastDFS version 6.x
- libfastcommon and libserverframe

## Installation & Configuration

### 1. Compile and Install

```bash
# Configure Nginx and specify the module path
./configure --add-module=/path/to/fastdfs-nginx-module/src

# Compile and install
make
make install
```

### 2. Configure Nginx

Add the FastDFS module configuration to the Nginx configuration file:

```nginx
location /M00 {
    fastdfs;
    
    # Specify configuration file path
    mod_fastdfs.conf;
}
```

### 3. Configure mod_fastdfs.conf

Copy and modify the configuration file:

```bash
cp mod_fastdfs.conf /etc/fdfs/mod_fastdfs.conf
```

Key configuration items:

```ini
# Connection timeout
connect_timeout=10

# Network timeout
network_timeout=30

# FastDFS tracker server address
tracker_server=192.168.0.100:22122

# Storage group name
group_name=group0

# Response character set
http.server_charset=UTF-8

# Anti-leech configuration
anti_steal_check=no

# FLV support
flv_support=yes
flv_extension=flv
```

## Configuration Details

### Response Modes

The module supports two response modes:

- **Proxy Mode**: Nginx proxies requests to the FastDFS storage server.
- **Redirect Mode**: Returns the storage server’s address, allowing the client to access it directly.

### Supported HTTP Headers

- Content-Type
- Content-Length
- Content-Range
- Accept-Ranges
- Content-Disposition
- Location

### Path Format

Access path format: `/group_name/M00/xxx/xxx/xxx`

Or using storage ID: `/M00/xxx/xxx/xxx`

## Usage Examples

### Access a File

```
http://your-domain/group_name/M00/00/00/abc.jpg
```

### Play FLV Video

```
http://your-domain/group_name/M00/00/00/video.flv
```

### Resume Download

Use HTTP Range request:

```
GET /group_name/M00/00/00/video.flv HTTP/1.1
Range: bytes=0-1023
```

## Related Links

- FastDFS Official Website: https://github.com/happyfish100/fastdfs
- FastDFS Wiki: https://github.com/happyfish100/fastdfs/wiki

## License

GPL v3 License

## Feedback

For any issues, please submit an Issue on GitHub or Gitee.
