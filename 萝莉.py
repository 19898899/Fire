import colorsys
import json
import random
import re
import sys
import threading
import time
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from base64 import b64decode, b64encode
from urllib.parse import urlparse, quote, unquote
import base64
import hashlib
import os
import uuid
import urllib.parse
sys.path.append('..')
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from base.spider import Spider


class HttpParamEncryptor:
    """HTTP参数加密工具类"""

    def __init__(self):
        # AES配置
        self.aes_key = "NQYT3eSsXG52WPDS".encode('utf-8')
        self.aes_iv = "e89225cfbbimgkcu".encode('utf-8')

    def aes_encrypt(self, plain_text):
        """AES加密"""
        try:
            plain_bytes = plain_text.encode('utf-8')
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
            padded_bytes = pad(plain_bytes, AES.block_size)
            encrypted_bytes = cipher.encrypt(padded_bytes)
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
            return encrypted_b64
        except Exception as e:
            print(f"AES加密失败: {e}")
            return ""

    def aes_decrypt(self, encrypted_b64):
        """AES解密 - 用于解密API响应"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            decrypted_bytes = unpad(decrypted_bytes, AES.block_size)
            result = decrypted_bytes.decode('utf-8')
            return result
        except Exception as e:
            print(f"❌ 解密失败: {e}")
            return None

    def generate_sign(self, encrypted_data, timestamp):
        """生成签名 - 先SHA256再MD5"""
        try:
            sign_str = f"data={encrypted_data}&timestamp={timestamp}NQYT3eSsXG52WPDS"
            sha256_hex = hashlib.sha256(sign_str.encode('utf-8')).hexdigest()
            md5_hex = hashlib.md5(sha256_hex.encode('utf-8')).hexdigest()
            return md5_hex
        except Exception as e:
            print(f"签名生成失败: {e}")
            return ""

    def encrypt_params(self, params_dict):
        """完整参数加密流程"""
        try:
            timestamp = int(time.time() * 1000)
            params_json = json.dumps(
                params_dict, ensure_ascii=False, separators=(',', ':'))
            encrypted_data = self.aes_encrypt(params_json)

            if not encrypted_data:
                return ""

            sign = self.generate_sign(encrypted_data, timestamp)
            encoded_data = urllib.parse.quote(encrypted_data, safe='')

            payload_dict = {
                "timestamp": str(timestamp),
                "data": encoded_data,
                "sign": sign
            }

            payload = f"timestamp={payload_dict['timestamp']}&data={payload_dict['data']}&sign={payload_dict['sign']}"
            return payload

        except Exception as e:
            print(f"参数加密失败: {e}")
            return ""

    def generate_device_id(self):
        """生成设备ID - 模拟Java代码的算法"""
        try:
            # 1. 生成UUID并去除短横线 (对应Java: UUID.randomUUID().toString().replace("-", ""))
            raw_uuid = str(uuid.uuid4()).replace("-", "")
            print(f"原始UUID: {raw_uuid}")

            # 2. SHA-256哈希 (对应Java: C5006x.m14370d)
            sha256_hash = hashlib.sha256(raw_uuid.encode('utf-8')).hexdigest()
            print(f"SHA-256哈希: {sha256_hash}")

            # 3. MD5哈希 (对应Java: C4995t0.m14297a)
            md5_hash = hashlib.md5(sha256_hash.encode('utf-8')).hexdigest()
            print(f"最终设备ID (MD5): {md5_hash}")

            return md5_hash

        except Exception as e:
            print(f"设备ID生成失败: {e}")
            # 降级方案：直接生成MD5
            fallback = hashlib.md5(
                str(time.time()).encode('utf-8')).hexdigest()
            return fallback


class Spider(Spider):

    saved_oauth_id = None

    def init(self, extend="{}"):

        self.domin = 'https://sapi01.eihpijd.xyz'
        # 代理只用于图片，API请求不使用代理
        self.image_proxies = {
            'http': 'http://127.0.0.1:9978',
            'https': 'http://127.0.0.1:9978'
        }
        self.proxies = {}  # API请求不使用代理
        # 请求头
        self.headers = {
            'User-Agent': "okhttp-okgo/jeasonlzy",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded",
            'accept-language': "zh-CN,zh;q=0.8"
        }
        self.encryptor = HttpParamEncryptor()

        # API配置
        random_seed = f"{time.time()}-{random.random()}"
        if Spider.saved_oauth_id:
            dynamic_oauth_id = Spider.saved_oauth_id
        else:
            dynamic_oauth_id = self.encryptor.generate_device_id()
            Spider.saved_oauth_id = dynamic_oauth_id
        self.base_params = {
            "bundle_id": "me.utzvd.hyngcj",
            "oauth_type": "android",
            "oauth_id": dynamic_oauth_id,
            "version": "4.2.0",
            "build_affcode": "gw",
            "token": ""
        }

        try:
            config_params = {
                "theme": ""
            }
            self.make_api_request('/api.php/api/home/getconfig', config_params)
        except Exception:
            # 延迟加载分类，避免初始化时的大量API请求
            pass

        self.category_config = {}
        self._categories_loaded = False

    def getName(self):
        return "51吸瓜API版"

    def isVideoFormat(self, url):
        return True

    def manualVideoCheck(self):
        return False

    def destroy(self):
        pass

    def homeContent(self, filter):
        """首页内容 - 使用API获取"""
        result = {}
        
        print(f"🔍 调试信息: 开始加载首页内容")
        print(f"🔍 分类配置数量: {len(self.category_config)}")
        
        # 获取分类
        classes = self.get_categories()
        print(f"🔍 获取到的分类数量: {len(classes)}")
        
        # 设置过滤器
        filters = {}
        for tid, cfg in self.category_config.items():
            series = cfg.get('series') or []
            if series:
                options = [{'n': '全部', 'v': ''}]
                for s in series:
                    options.append({'n': s.get('name', ''), 'v': str(s.get('id'))})
                filters[tid] = [{'key': 'series_id', 'name': '分类', 'value': options}]
        
        # 选择默认分类
        default_tid = None
        for tid, cfg in self.category_config.items():
            if cfg.get('name') == '推荐':
                default_tid = tid
                break
        
        # 如果没有推荐分类，选择第一个可用的分类
        if not default_tid and self.category_config:
            default_tid = list(self.category_config.keys())[0]
        
        print(f"🔍 选择的默认分类ID: {default_tid}")
        
        videos = []
        if default_tid:
            cfg = self.category_config.get(default_tid, {})
            print(f"🔍 默认分类配置: {cfg}")
            
            api_path = cfg.get('api') or '/api.php/api/navigation/theme'
            params = cfg.get('params', {}).copy()
            params.setdefault('theme', '')
            params.setdefault('page', '1')
            
            print(f"🔍 请求API: {api_path}")
            print(f"🔍 请求参数: {params}")
            
            videos = self.get_video_list(page="1", params=params, api_path=api_path)
            print(f"🔍 获取到的视频数量: {len(videos)}")
        else:
            print("❌ 错误: 没有找到可用的默认分类")
        
        result['class'] = classes
        if filters:
            result['filters'] = filters
        result['list'] = videos
        
        print(f"✅ 首页内容加载完成: {len(classes)}个分类, {len(videos)}个视频")
        return result
    def homeVideoContent(self):
        """首页视频内容（给部分壳子用）"""
        # 复用 homeContent 的默认分类逻辑，只返回视频列表部分
        try:
            data = self.homeContent(False)
            return data.get('list', []) if isinstance(data, dict) else []
        except Exception:
            return []

    def categoryContent(self, tid, pg, filter, extend):
        """分类内容"""
        result = {}

        tid = str(tid)
        cfg = self.category_config.get(tid)
        if not cfg:
            result['list'] = []
            result['page'] = pg
            result['pagecount'] = 1
            result['limit'] = 90
            result['total'] = 0
            return result
        series_id = None
        sort = None
        if extend:
            series_id = extend.get('series_id') or extend.get('id')
            sort = extend.get('sort')
        api_path = cfg.get('api') or '/api.php/api/navigation/theme'
        if series_id:
            api_path = '/api.php/api/navigation/seriesMvList'
            params = {
                'theme': '',
                'page': str(pg),
                'id': str(series_id)
            }
            if sort:
                params['sort'] = sort
        else:
            params = cfg.get('params', {}).copy()
            params['page'] = str(pg)
            params.setdefault('theme', '')
        videos = self.get_video_list(
            page=str(pg), params=params, api_path=api_path)

        result['list'] = videos
        result['page'] = pg
        result['pagecount'] = 99999
        result['limit'] = 90
        result['total'] = 999999
        return result

    def detailContent(self, ids):
        """详情内容"""
        video_id = ids[0]
        print(f"🔍 获取视频详情，ID: {video_id}")

        params = {
            "theme": "",
            "id": video_id
        }
        print(f"🔍 详情API请求参数: {params}")
        response_data = self.make_api_request('/api.php/api/mv/detail', params)
        print(f"🔍 详情API响应: {response_data}")
        
        if not response_data:
            print(f"❌ 详情API响应为空")
            return {'list': []}

        # 修复：数据在 data.row 中，不是直接在根级别
        row = {}
        if isinstance(response_data, dict):
            data_section = response_data.get('data', {})
            if isinstance(data_section, dict):
                row = data_section.get('row', {})
        
        print(f"🔍 解析的视频详情数据: {row}")
        
        vod = self.parse_video_detail(row, video_id)
        print(f"🔍 最终返回的详情数据: {vod}")
        
        return {'list': [vod]}

    def searchContent(self, key, quick, pg="1"):
        """搜索内容"""
        params = {
            "page": str(pg),
            "theme": key
        }
        videos = self.get_video_list(page=str(pg), params=params)
        
        # 添加分页信息
        result = {
            'list': videos,
            'page': pg,
            'pagecount': 99999,  # 设置一个较大的值表示有很多页
            'limit': 90,
            'total': 999999
        }
        return result

    def playerContent(self, flag, id, vipFlags):
        """播放内容"""
        # 解析播放地址
        if '_dm_' in id:
            did, pid = id.split('_dm_')
        else:
            did, pid = id, id

        p = 0 if re.search(r'\.(m3u8|mp4|flv|ts|mkv|mov|avi|webm)', pid) else 1

        if not p:
            pid = f"{self.getProxyUrl()}&pdid={quote(id)}&type=m3u8"

        # 返回标准格式的播放信息
        result = {
            'header': json.dumps(self.headers),  # header需要是JSON字符串
            'url': pid
        }
        return result

    def localProxy(self, param):
        """本地代理处理"""
        try:
            xtype = param.get('type', '')
            if 'm3u8' in xtype:
                path, url = unquote(param['pdid']).split('_dm_')
                data = requests.get(url, headers=self.headers,
                                    proxies=self.proxies, timeout=10).text
                lines = data.strip().split('\n')
                times = 0.0
                for i in lines:
                    if i.startswith('#EXTINF:'):
                        times += float(i.split(':')[-1].replace(',', ''))
                thread = threading.Thread(
                    target=self.some_background_task, args=(path, int(times)))
                thread.start()
                return [200, 'text/plain', data]
            elif 'xdm' in xtype:
                url = f"{self.host}{unquote(param['path'])}"
                res = requests.get(url, headers=self.headers,
                                   proxies=self.proxies, timeout=10).json()
                dms = []
                for k in res:
                    text = k.get('text')
                    children = k.get('children')
                    if text:
                        dms.append(text.strip())
                    if children:
                        for j in children:
                            ctext = j.get('text')
                            if ctext:
                                ctext = ctext.strip()
                                if "@" in ctext:
                                    dms.append(ctext.split(' ', 1)[-1].strip())
                                else:
                                    dms.append(ctext)
                return self.xml(dms, int(param['times']))

            # 图片解密处理
            print(f"🔍 图片代理处理参数: {param}")
            url = self.d64(param['url'])
            print(f"🔍 解码后的URL: {url}")
            match = re.search(r"loadBannerDirect\('([^']*)'", url)
            if match:
                url = match.group(1)
                print(f"🔍 提取的真实URL: {url}")
            print(f"🔍 开始请求图片...")
            
            # 先不使用代理尝试请求图片
            try:
                # 添加更合适的图片请求头
                img_headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Referer': 'https://sapi01.eihpijd.xyz/',
                    'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
                    'Accept-Language': 'zh-CN,zh;q=0.9'
                }
                direct_res = requests.get(url, headers=img_headers, timeout=15)
                print(f"🔍 直接请求图片状态码: {direct_res.status_code}")
                print(f"🔍 直接请求内容长度: {len(direct_res.content)}")
                print(f"🔍 直接请求Content-Type: {direct_res.headers.get('Content-Type')}")
                
                if direct_res.status_code != 200:
                    print(f"🔍 图片请求失败，状态码: {direct_res.status_code}")
                    return [500, 'text/html', f'图片请求失败: {direct_res.status_code}']
                
                if len(direct_res.content) == 0:
                    print(f"🔍 图片内容为空")
                    return [500, 'text/html', '图片内容为空']
                
                # 检查是否需要解密 - 有些图片可能不需要解密
                content_type = direct_res.headers.get('Content-Type', '')
                print(f"🔍 原始Content-Type: {content_type}")
                
                # 尝试直接返回原始图片（不解密）
                if content_type.startswith('image/'):
                    print(f"🔍 尝试直接返回原始图片...")
                    # 检查是否是有效的图片格式
                    if (direct_res.content.startswith(b'\xFF\xD8\xFF') or  # JPEG
                        direct_res.content.startswith(b'\x89PNG') or      # PNG
                        direct_res.content.startswith(b'GIF87') or       # GIF
                        direct_res.content.startswith(b'GIF89') or       # GIF
                        direct_res.content.startswith(b'RIFF')):         # WebP
                        print(f"🔍 检测到有效图片格式，直接返回")
                        if direct_res.content.startswith(b'\xFF\xD8\xFF'):
                            return [200, 'image/jpeg', direct_res.content]
                        elif direct_res.content.startswith(b'\x89PNG'):
                            return [200, 'image/png', direct_res.content]
                        elif direct_res.content.startswith(b'GIF87') or direct_res.content.startswith(b'GIF89'):
                            return [200, 'image/gif', direct_res.content]
                        elif direct_res.content.startswith(b'RIFF'):
                            return [200, 'image/webp', direct_res.content]
                
                # 如果直接返回失败，尝试AES解密
                print(f"🔍 开始对图片进行AES解密...")
                decrypted_img = self.aesimg(direct_res.content)
                print(f"🔍 AES解密完成，解密后长度: {len(decrypted_img)}")
                
                if len(decrypted_img) == 0:
                    print(f"🔍 解密后内容为空，返回原始内容")
                    return [200, content_type or 'application/octet-stream', direct_res.content]
                
                # 检查解密后的数据格式并设置正确的Content-Type
                if decrypted_img.startswith(b'\xFF\xD8\xFF'):
                    print(f"🔍 解密成功！检测到JPEG图片")
                    return [200, 'image/jpeg', decrypted_img]
                elif decrypted_img.startswith(b'\x89PNG'):
                    print(f"🔍 解密成功！检测到PNG图片")
                    return [200, 'image/png', decrypted_img]
                elif decrypted_img.startswith(b'GIF87a') or decrypted_img.startswith(b'GIF89a'):
                    print(f"🔍 解密成功！检测到GIF图片")
                    return [200, 'image/gif', decrypted_img]
                elif decrypted_img.startswith(b'RIFF') and len(decrypted_img) > 12 and decrypted_img[8:12] == b'WEBP':
                    print(f"🔍 解密成功！检测到WebP图片")
                    return [200, 'image/webp', decrypted_img]
                else:
                    print(f"🔍 解密完成但格式未知，返回原始内容")
                    # 如果解密后格式未知，返回原始内容
                    return [200, content_type or 'application/octet-stream', direct_res.content]
                        
            except Exception as e:
                print(f"🔍 直接请求失败: {e}")
                print(f"🔍 错误详情: {type(e).__name__}")
                import traceback
                traceback.print_exc()
            
            # 如果直接请求失败，再尝试使用图片代理（但仅用于HTTP）
            if url.startswith('http://'):
                print(f"🔍 尝试使用图片代理请求HTTP图片...")
                try:
                    res = requests.get(url, headers=self.headers, proxies=self.image_proxies, timeout=10)
                    print(f"🔍 代理请求图片状态码: {res.status_code}")
                    print(f"🔍 代理请求内容长度: {len(res.content)}")
                    
                    # 对代理请求的图片也进行AES解密
                    print(f"🔍 对代理请求的图片进行AES解密...")
                    decrypted_img = self.aesimg(res.content)
                    print(f"🔍 解密后内容长度: {len(decrypted_img)}")
                    
                    # 检查解密后的数据格式
                    if decrypted_img.startswith(b'\xFF\xD8\xFF'):
                        print(f"🔍 解密成功！检测到JPEG图片")
                        return [200, 'image/jpeg', decrypted_img]
                    elif decrypted_img.startswith(b'\x89PNG'):
                        print(f"🔍 解密成功！检测到PNG图片")
                        return [200, 'image/png', decrypted_img]
                    else:
                        print(f"🔍 解密完成但格式未知，返回解密数据")
                        return [200, 'application/octet-stream', decrypted_img]
                            
                except Exception as e:
                    print(f"🔍 图片代理请求也失败: {e}")
            else:
                print(f"🔍 HTTPS图片不使用代理，避免CONNECT错误")
            
            print(f"🔍 所有请求都失败，返回空内容")
            return [500, 'text/html', '']

        except Exception as e:
            print(f"代理处理错误: {e}")
            return [500, 'text/html', '']

    def make_api_request(self, api_path, params):
        """发送API请求"""
        try:
            all_params = self.base_params.copy()
            if params:
                all_params.update(params)
            
            encrypted_params = self.encryptor.encrypt_params(all_params)
            if not encrypted_params:
                return None
            
            url = f"{self.domin}{api_path}"
            print(f"🔍 API请求URL: {url}")
            print(f"🔍 请求参数: {all_params}")
            
            # API请求不使用代理，避免CONNECT错误
            response = requests.post(
                url,
                data=encrypted_params,
                headers=self.headers,
                timeout=30,
                verify=False  # 禁用SSL验证
            )
            if response.status_code != 200:
                print(f"API请求失败，状态码: {response.status_code}")
                return None
            response_data = response.json()
            errcode = response_data.get("errcode", -1)
            if errcode != 0:
                print(f"API返回错误: errcode={errcode}")
                return None
            encrypted_data = response_data.get("data", "")
            if encrypted_data:
                decrypted_data = self.encryptor.aes_decrypt(encrypted_data)
                if decrypted_data:
                    import json
                    return json.loads(decrypted_data)
            return None
        except Exception as e:
            print(f"API请求异常: {e}")
            return None

    def get_video_list(self, page="1", params=None, api_path=None):
        """获取视频列表"""
        if api_path is None:
            api_path = '/api.php/api/navigation/theme'
        extra_params = {}
        if params is not None:
            extra_params.update(params)
        else:
            extra_params['page'] = page
            extra_params['theme'] = ''
        response_data = self.make_api_request(api_path, extra_params)
        if not response_data:
            return []
        # theme 接口的新结构: { data: { list: [ {id,title,list:[video...]} ] } }
        if isinstance(response_data, dict) and api_path.endswith('/navigation/theme'):
            items = []
            data_block = response_data.get('data') or {}
            # 优先使用 data.list 结构
            blocks = data_block.get('list') or response_data.get('list') or []
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                sub_list = block.get('list') or []
                if isinstance(sub_list, list):
                    items.extend(sub_list)
            return self.parse_video_list(items)
        return self.parse_video_list(response_data)

    def parse_video_list(self, data):
        """解析视频列表数据"""
        videos = []
        if isinstance(data, list):
            video_list = data
        elif isinstance(data, dict):
            video_list = data.get('videos', []) or data.get(
                'list', []) or data.get('data', [])
        else:
            video_list = []
        for item in video_list:
            if isinstance(item, dict):
                raw_pic = item.get('cover_thumb_url', '') or item.get('thumb', '')
                vod_pic = ''
                if raw_pic:
                    try:
                        print(f"🔍 原始图片URL: {raw_pic}")
                        encoded_url = self.e64(raw_pic)
                        print(f"🔍 编码后URL: {encoded_url}")
                        proxy_url = f"{self.getProxyUrl()}&url={encoded_url}"
                        print(f"🔍 代理URL: {proxy_url}")
                        vod_pic = proxy_url
                    except Exception as e:
                        print(f"❌ 图片URL处理失败: {e}")
                        vod_pic = raw_pic
                
                # 获取年份 - 从创建时间中提取
                created_str = item.get('created_str', '')
                vod_year = ''
                if created_str and len(created_str) >= 4:
                    vod_year = created_str[:4]
                
                video = {
                    'vod_id': str(item.get('id', '')),
                    'vod_name': item.get('title', '未知标题'),
                    'vod_pic': vod_pic,
                    'vod_remarks': item.get('duration_str', '') or item.get('created_str', ''),
                    'vod_year': vod_year,
                    'vod_tag': 'file',  # 默认为file类型，点击跳转详情页
                    'style': {"type": "rect", "ratio": 2.3}
                }
                video = {k: v for k, v in video.items() if v}
                if video.get('vod_id') and video.get('vod_name'):
                    videos.append(video)
        return videos

    def load_categories(self):
        """加载导航大分类及其系列小分类（使用本地写死的数据，不再请求 navigation/index 接口）"""
        try:
            # 直接使用拦截到的 /api.php/api/navigation/index 解密数据，避免每次发起请求
            data = [
                {
                    "current": False,
                    "id": -1,
                    "name": "关注",
                    "style": 0,
                    "has_rank": 0,
                    "api": "/api/navigation/list_follows",
                    "params": {"type": "1"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": -1,
                    "name": "精选",
                    "style": 10,
                    "has_rank": 0,
                    "api": "/api/navigation/list_short_mv",
                    "params": {"type": "1"},
                    "h5_url": ""
                },
                {
                    "current": True,
                    "id": 1,
                    "name": "推荐",
                    "style": 1,
                    "has_rank": 1,
                    "api": "/api/navigation/theme",
                    "params": {"id": 1, "type": "1"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 16,
                    "name": "17岁",
                    "style": 3,
                    "has_rank": 0,
                    "api": "",
                    "params": {"id": 16},
                    "h5_url": "https://865.nzcnxez.xyz/index.php?m=index&a=seventeen&token=bhnHK-9905"
                },
                {
                    "current": False,
                    "id": -1,
                    "name": "发现",
                    "style": 2,
                    "has_rank": 0,
                    "api": "/api/navigation/found",
                    "params": {"type": "1"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 4,
                    "name": "福利姬",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 4, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 7,
                    "name": "动漫次元",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 7, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 10,
                    "name": "乱伦禁爱",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 10, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 3,
                    "name": "网黄嫩模",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 3, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 2,
                    "name": "原创传媒",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 2, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 6,
                    "name": "国产直播",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 6, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 9,
                    "name": "制服诱惑",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 9, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 5,
                    "name": "日本AV",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 5, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 8,
                    "name": "异国风情",
                    "style": 1,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 8, "sort": "new"},
                    "h5_url": ""
                },
                {
                    "current": False,
                    "id": 16,
                    "name": "17岁",
                    "style": 3,
                    "has_rank": 0,
                    "api": "/api/navigation/theme",
                    "params": {"id": 16, "sort": "new"},
                    "h5_url": ""
                }
            ]

            if not data:
                return
            if not isinstance(data, list):
                return
            # 先构建大分类配置（保持原有过滤规则）
            for item in data:
                api = item.get('api') or ''
                if not api:
                    continue
                # 过滤不需要的入口
                if api in ['/api/navigation/found', '/api/navigation/list_follows']:
                    continue
                if item.get('h5_url'):
                    continue
                raw_id = item.get('id', -1)
                if raw_id == -1:
                    tid = f"api_{api}"
                else:
                    tid = str(raw_id)
                api_path = api
                if api_path.startswith('/api/'):
                    api_path = '/api.php' + api_path
                cfg = {
                    'name': item.get('name', ''),
                    'api': api_path,
                    'params': item.get('params', {}) or {}
                }
                self.category_config[tid] = cfg
            # 简化分类加载，避免大量API请求
            # 只为推荐分类加载系列数据，其他分类使用空系列
            for tid, cfg in list(self.category_config.items()):
                api_path = cfg.get('api') or ''
                params = cfg.get('params', {}).copy()
                
                # 只为推荐分类（id=1）加载系列数据
                if api_path.endswith('/navigation/theme') and params.get('id') == 1:
                    print(f"🔍 为推荐分类加载系列数据...")
                    params.setdefault('theme', '')
                    params.setdefault('page', '1')
                    theme_data = self.make_api_request(api_path, params)
                    series = []
                    if isinstance(theme_data, dict):
                        for block in theme_data.get('list', []):
                            sid = block.get('id')
                            title = block.get('title')
                            if sid and title:
                                series.append({'id': sid, 'name': title})
                    cfg['series'] = series
                    print(f"🔍 推荐分类加载了 {len(series)} 个系列")
                else:
                    # 其他分类使用空系列，避免API请求
                    cfg['series'] = []
        except Exception as e:
            print(f"加载分类失败: {e}")

    def _ensure_categories_loaded(self):
        """确保分类已加载（按需加载）"""
        if not self._categories_loaded:
            print(f"🔍 按需加载分类配置...")
            self.load_categories()
            self._categories_loaded = True

    def get_categories(self):
        """根据已加载的导航生成分类列表"""
        self._ensure_categories_loaded()
        categories = []
        for tid, cfg in self.category_config.items():
            name = cfg.get('name')
            if not name:
                continue
            categories.append({
                'type_id': tid,
                'type_name': name
            })
        return categories

    def parse_video_detail(self, data, video_id):
        """解析视频详情"""
        print(f"🔍 开始解析视频详情，video_id: {video_id}")
        print(f"🔍 原始数据: {data}")
        
        # 获取标题
        vod_name = data.get('title', '未知标题')
        
        # 获取图片URL并处理代理
        raw_pic = data.get('cover_thumb_url', '') or data.get('thumb', '')
        vod_pic = ''
        if raw_pic:
            try:
                encoded_url = self.e64(raw_pic)
                vod_pic = f"{self.getProxyUrl()}&url={encoded_url}"
            except Exception:
                vod_pic = raw_pic
        
        # 获取备注信息 - 使用时长作为备注
        vod_remarks = data.get('duration_str', '')
        
        # 获取年份 - 从创建时间中提取年份
        created_str = data.get('created_str', '')
        vod_year = ''
        if created_str and len(created_str) >= 4:
            vod_year = created_str[:4]
        
        # 获取地区信息 - 如果API中有地区字段
        vod_area = data.get('area', '')
        
        # 获取类型名称 - 从标签列表中获取第一个作为类型
        tags_list = data.get('tags_list', [])
        type_name = tags_list[0] if tags_list else ''
        
        # 获取演员信息
        vod_actor = data.get('actors', '')
        
        # 获取导演信息
        vod_director = data.get('director', '')
        
        # 获取内容描述 - 组合多个字段信息
        content_parts = []
        
        # 添加标签信息
        if tags_list:
            content_parts.append(f"标签: {', '.join(tags_list)}")
        
        # 添加演员信息
        if vod_actor:
            content_parts.append(f"演员: {vod_actor}")
        
        # 添加描述信息
        description = data.get('description', '')
        if description:
            content_parts.append(f"简介: {description}")
        
        # 添加时长信息
        if vod_remarks:
            content_parts.append(f"时长: {vod_remarks}")
        
        # 添加评分信息
        rating = data.get('rating', 0)
        if rating:
            content_parts.append(f"评分: {rating}")
        
        # 添加点赞数
        like = data.get('like', 0)
        if like:
            content_parts.append(f"点赞: {like}")
        
        # 添加视频类型信息
        is_free_str = data.get('is_free_str', '')
        if is_free_str:
            content_parts.append(f"类型: {is_free_str}")
        
        # 组合所有内容
        vod_content = ' | '.join(content_parts) if content_parts else ''
        print(f"🔍 组合的内容信息: {vod_content}")
        
        # 处理播放地址
        play_url = data.get('play_url', '')
        print(f"🔍 获取到的原始play_url: {play_url}")
        
        if play_url:
            # 替换域名：将 https://10play. 替换为 https://long.
            # 使用正则表达式匹配 https://数字+play. 的模式
            import re
            processed_url = re.sub(r'https://\d+play\.', 'https://long.', play_url)
            print(f"🔍 处理后的播放地址: {processed_url}")
            
            # 设置播放地址格式
            vod_play_url = f"正片${video_id}_dm_{processed_url}"
        else:
            vod_play_url = ''
        
        # 处理剧集列表
        episodes = data.get('episodes', [])
        print(f"🔍 获取到的episodes: {episodes}")
        if episodes:
            play_list = []
            for idx, episode in enumerate(episodes, 1):
                episode_url = episode.get('url', '')
                if episode_url:
                    # 同样替换剧集URL的域名
                    processed_episode_url = re.sub(r'https://\d+play\.', 'https://long.', episode_url)
                    play_list.append(f"第{idx}集${video_id}_dm_{processed_episode_url}")
            if play_list:
                vod_play_url = '#'.join(play_list)
                print(f"🔍 设置剧集播放地址: {vod_play_url}")
        
        vod = {
            'vod_id': video_id,
            'vod_name': vod_name,
            'vod_pic': vod_pic,
            'vod_remarks': vod_remarks,
            'vod_year': vod_year,
            'vod_area': vod_area,
            'type_name': type_name,
            'vod_actor': vod_actor,
            'vod_director': vod_director,
            'vod_content': vod_content,
            'vod_play_from': '51吸瓜',
            'vod_play_url': vod_play_url
        }
        
        print(f"🔍 最终解析的vod数据: {vod}")
        return vod

    # 保留原有的工具方法
    def some_background_task(self, path, times):
        try:
            time.sleep(1)
            purl = f"{self.getProxyUrl()}&path={quote(path)}&times={times}&type=xdm"
            self.fetch(
                f"http://127.0.0.1:9978/action?do=refresh&type=danmaku&path={quote(purl)}")
        except Exception as e:
            print(e)

    def xml(self, dms, times):
        try:
            tsrt = f'共有{len(dms)}条弹幕来袭！！！'
            danmustr = f'<?xml version="1.0" encoding="UTF-8"?>\n<i>\n\t<chatserver>chat.xtdm.com</chatserver>\n\t<chatid>88888888</chatid>\n\t<mission>0</mission>\n\t<maxlimit>99999</maxlimit>\n\t<state>0</state>\n\t<real_name>0</real_name>\n\t<source>k-v</source>\n'
            danmustr += f'\t<d p="0,5,25,16711680,0">{tsrt}</d>\n'
            for i in range(len(dms)):
                base_time = (i / len(dms)) * times
                dm0 = base_time + random.uniform(-3, 3)
                dm0 = round(max(0, min(dm0, times)), 1)
                dm2 = self.get_color()
                dm4 = re.sub(r'[<>&\u0000\b]', '', dms[i])
                tempdata = f'\t<d p="{dm0},1,25,{dm2},0">{dm4}</d>\n'
                danmustr += tempdata
            danmustr += '</i>'
            return [200, "text/xml", danmustr]
        except Exception as e:
            print(e)
            return [500, 'text/html', '']

    def get_color(self):
        if random.random() < 0.1:
            h = random.random()
            s = random.uniform(0.7, 1.0)
            v = random.uniform(0.8, 1.0)
            r, g, b = colorsys.hsv_to_rgb(h, s, v)
            r = int(r * 255)
            g = int(g * 255)
            b = int(b * 255)
            decimal_color = (r << 16) + (g << 8) + b
            return str(decimal_color)
        else:
            return '16777215'

    def e64(self, text):
        try:
            text_bytes = text.encode('utf-8')
            encoded_bytes = b64encode(text_bytes)
            return encoded_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64编码错误: {str(e)}")
            return ""

    def d64(self, encoded_text):
        try:
            encoded_bytes = encoded_text.encode('utf-8')
            decoded_bytes = b64decode(encoded_bytes)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64解码错误: {str(e)}")
            return ""

    def aesimg(self, word):
        """图片AES解密 - 增强版"""
        try:
            key = b'f5d965df75336270'
            iv = b'97b60394abc2fbe1'
            print(f"🔍 开始AES解密，原始长度: {len(word)}")
            
            if not word:
                print(f"🔍 错误：输入数据为空")
                return b''
            
            # 检查数据长度
            if len(word) % 16 != 0:
                padding_needed = 16 - (len(word) % 16)
                print(f"🔍 数据长度不是16的倍数，需要填充: {padding_needed} 字节")
                # 尝试PKCS7填充
                word = word + bytes([padding_needed] * padding_needed)
                print(f"🔍 填充后长度: {len(word)}")
            
            # 确保数据长度至少为16字节
            if len(word) < 16:
                print(f"🔍 错误：数据长度太短，无法进行AES解密")
                return word
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(word)
            print(f"🔍 AES解密（去填充前）长度: {len(decrypted)}")
            
            # 尝试去填充
            try:
                decrypted = unpad(decrypted, AES.block_size)
                print(f"🔍 去填充后长度: {len(decrypted)}")
            except Exception as pad_error:
                print(f"🔍 去填充失败: {pad_error}")
                # 尝试手动去除PKCS7填充
                if len(decrypted) > 0:
                    last_byte = decrypted[-1]
                    if last_byte <= 16:  # PKCS7填充的最大值
                        try:
                            decrypted = decrypted[:-last_byte]
                            print(f"🔍 手动去除填充后长度: {len(decrypted)}")
                        except:
                            print(f"🔍 手动去除填充失败，使用原始数据")
            
            # 检查解密结果是否有效
            if len(decrypted) == 0:
                print(f"🔍 解密后数据为空")
                return b''
            
            # 检查是否是有效的图片格式
            if (decrypted.startswith(b'\xFF\xD8\xFF') or  # JPEG
                decrypted.startswith(b'\x89PNG') or      # PNG
                decrypted.startswith(b'GIF87') or       # GIF
                decrypted.startswith(b'GIF89') or       # GIF
                decrypted.startswith(b'RIFF')):         # WebP
                print(f"🔍 解密成功，检测到有效图片格式")
                return decrypted
            else:
                print(f"🔍 解密完成但未检测到有效图片格式")
                print(f"🔍 解密后前32字节: {decrypted[:32]}")
                return decrypted
            
        except Exception as e:
            print(f"❌ 图片AES解密失败: {e}")
            print(f"❌ 错误类型: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return word  # 返回原始数据
