#coding=utf-8
#!/usr/bin/python
from re import sub
from requests import get
from urllib.parse import unquote
from threading import Thread, Event
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from importlib.machinery import SourceFileLoader
from http.server import BaseHTTPRequestHandler, HTTPServer

cache = {}
class ProxyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        urlParts = urlparse(self.path)
        queryQarams = parse_qs(urlParts.query)
        do = queryQarams['do'][0]
        try:
            key = queryQarams['key'][0]
        except:
            key = ''
        try:
            value = queryQarams['value'][0]
        except:
            value = ''
        if do == 'set':
            cache[key] = value
            self.send_response(200)
            self.end_headers()
        if do == 'get':
            self.send_response(200)
            self.end_headers()
            if key in cache:
                self.wfile.write(cache[key].encode())
        elif do == 'delete':
            cache.pop(key, None)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def do_POST(self):
        urlParts = urlparse(self.path)
        queryQarams = parse_qs(urlParts.query)
        key = queryQarams['key'][0]
        try:
            contentLength = int(self.headers.get('Content-Length', 0))
            value = self.rfile.read(contentLength).decode().replace('+', ' ')
            value = sub(r'value=(.*?)', '', unquote(value))
        except:
            value = ''
        cache[key] = value
        self.send_response(200)
        self.end_headers()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def serveForever(event):
    try:
        while not event.is_set():
            ThreadedHTTPServer(('0.0.0.0', 9978), ProxyServer).handle_request()
        ThreadedHTTPServer(('0.0.0.0', 9978), ProxyServer).server_close()
    except Exception as erro:
        print(erro)
    finally:
        ThreadedHTTPServer(('0.0.0.0', 9978), ProxyServer).server_close()

def get_plugin_path(fileName):
    """动态获取插件文件路径"""
    # 获取当前文件的绝对路径（spid/base/local.py）
    import os
    current_file = os.path.abspath(__file__)
    
    # 获取spid目录的路径（向上两级）
    spid_dir = os.path.dirname(os.path.dirname(current_file))
    
    # 构建插件文件路径
    plugin_path = os.path.join(spid_dir, 'plugin', f'{fileName}.py')
    
    # 检查文件是否存在
    if not os.path.exists(plugin_path):
        # 如果不存在，尝试在当前目录的plugin文件夹中查找
        current_dir = os.path.dirname(current_file)
        plugin_path = os.path.join(current_dir, 'plugin', f'{fileName}.py')
        
        if not os.path.exists(plugin_path):
            # 如果还是不存在，尝试查找文件名末尾带空格的情况
            plugin_path_with_space = os.path.join(spid_dir, 'plugin', f'{fileName} .py')
            if os.path.exists(plugin_path_with_space):
                return plugin_path_with_space
            
            # 尝试当前目录下带空格的情况
            plugin_path_with_space = os.path.join(current_dir, 'plugin', f'{fileName} .py')
            if os.path.exists(plugin_path_with_space):
                return plugin_path_with_space
                
            raise FileNotFoundError(f"找不到插件文件: {plugin_path}")
    
    return plugin_path

def loadFromDisk(fileName):
    plugin_path = get_plugin_path(fileName)
    name = fileName.split('/')[-1].split('.')[0]

    sp = SourceFileLoader(name, plugin_path ).load_module().Spider()
    return sp

def run(fileName, proxy=False):
    event = Event()
    if proxy:
        thread = Thread(target=serveForever, args=(event,), name='localProxy')
        thread.start()
    sp = loadFromDisk(fileName)
#

    # sp = loadFromDisk(f'C:/Users/hello/Desktop/PySide6-codes-master/pyside文件夹/行不行/1章/spid/plugin/{fileName}.py')  #载入本地脚本
    sp.init('') # 初始化
    try:
        # formatJo = sp.decode('')
      
        # formatJo = sp.searchContent("山河枕", False, '1') # 搜索

        print("🔍 ===== 测试首页内容 =====")
        formatJo = sp.homeContent(True)  # 主页
        print(f"🔍 首页加载完成，分类数量: {len(formatJo.get('class', []))}")
        print(f"🔍 首页过滤器: {formatJo.get('filters', {})}")
        
        # 详细检查分类列表
        classes = formatJo.get('class', [])
        print(f"🔍 ===== 详细检查分类列表 =====")
        for i, cls in enumerate(classes):
            print(f"🔍 分类 {i+1}: ID={cls.get('type_id')}, 名称={cls.get('type_name')}")
        
        # 检查是否包含小马拉大车
        xiao_ma_found = any(cls.get('type_name') == '小马拉大车' for cls in classes)
        print(f"🔍 小马拉大车分类是否在列表中: {xiao_ma_found}")
        
        if xiao_ma_found:
            print(f"🔍 ✅ 小马拉大车分类已添加到首页分类列表")
        else:
            print(f"🔍 ❌ 小马拉大车分类未在首页分类列表中找到")
            print(f"🔍 所有分类名称: {[cls.get('type_name') for cls in classes]}")
        
        # 检查过滤器中是否包含ID 13
        filters = formatJo.get('filters', {})
        id_13_found = '13' in filters
        print(f"🔍 ID 13过滤器是否存在: {id_13_found}")
        if id_13_found:
            print(f"🔍 ID 13过滤器选项数量: {len(filters['13'][0].get('value', []))}")
        else:
            print(f"🔍 现有过滤器ID: {list(filters.keys())}")
        
        print("\n🔍 ===== 专门测试小马拉大车分类 =====")
        
        # 只测试小马拉大车分类
        print(f"\n🔍 --- 测试分类: 小马拉大车 (ID: 13) ---")
        
        # 测试分类内容（第1页，无过滤器）
        result = sp.categoryContent('13', "1", False, {})
        print(f"🔍 小马拉大车分类返回视频数量: {len(result.get('list', []))}")
        print(f"🔍 完整返回结果结构: {list(result.keys())}")
        
        # 详细检查过滤器
        if result.get('filters'):
            print(f"🔍 ✅ 过滤器数据存在!")
            filters = result['filters']
            print(f"🔍 过滤器类型: {type(filters)}")
            print(f"🔍 过滤器内容: {filters}")
            for tid, filter_list in filters.items():
                print(f"🔍   分类ID {tid} 的过滤器:")
                for filter_item in filter_list:
                    key = filter_item.get('key', '')
                    name = filter_item.get('name', '')
                    values = filter_item.get('value', [])
                    print(f"🔍     {name} ({key}): {len(values)} 个选项")
                    options = [f"{opt.get('n', '')}:{opt.get('v', '')}" for opt in values[:5]]
                    print(f"🔍     过滤器选项: {options}")
        else:
            print(f"🔍 ❌ 没有过滤器数据")
            print(f"🔍 result['filters'] = {result.get('filters')}")
        
        if result.get('list'):
            print(f"🔍 ✅ 小马拉大车分类有数据！")
            print(f"🔍 前3个视频:")
            for i, video in enumerate(result.get('list', [])[:3]):
                print(f"🔍   {i+1}. {video.get('vod_name', '未知')} (ID: {video.get('vod_id', '未知')})")
        else:
            print(f"🔍 ❌ 小马拉大车分类没有数据")
        
        # 显示请求体信息
        print(f"\n🔍 ===== 小马拉大车分类请求体信息 =====")
        print(f"🔍 使用的API参数: ID=13, sort=new")
        print(f"🔍 实际发送的请求体会在API请求日志中显示")
        
        # 直接测试API请求
        print(f"\n🔍 ===== 直接测试小马拉大车API请求 =====")
        api_path = '/api.php/api/navigation/theme'
        params = {"id": 5, "sort": "new", "theme": "", "page": "1"}  # 注意：这里使用ID=5
        print(f"🔍 API路径: {api_path}")
        print(f"🔍 请求参数: {params}")
        
        # 这里会显示详细的请求日志
        response_data = sp.make_api_request(api_path, params)
        if response_data:
            print(f"🔍 ✅ API请求成功，返回数据类型: {type(response_data)}")
            if isinstance(response_data, dict):
                data_section = response_data.get('data', {})
                if isinstance(data_section, dict):
                    list_data = data_section.get('list', [])
                    print(f"🔍 解析到 {len(list_data)} 个数据块")
                    total_videos = 0
                    for i, block in enumerate(list_data[:3]):
                        if isinstance(block, dict):
                            sub_list = block.get('list', [])
                            total_videos += len(sub_list)
                            print(f"🔍   数据块{i+1}: {len(sub_list)} 个视频")
                    print(f"🔍 总计约 {total_videos} 个视频")
                else:
                    print(f"🔍 数据结构: {list(response_data.keys()) if isinstance(response_data, dict) else '非字典类型'}")
        else:
            print(f"🔍 ❌ API请求失败或无数据")
        
        # 测试多个可能的ID，找到真正的小马拉大车和强奸分类
        print(f"\n🔍 ===== 测试不同API ID找到正确分类 =====")
        
        # 测试一些可能有效的ID
        test_ids = [
            {"id": 11, "name": "测试ID 11"},
            {"id": 12, "name": "测试ID 12"}, 
            {"id": 13, "name": "测试ID 13"},
            {"id": 15, "name": "测试ID 15"},
            {"id": 16, "name": "测试ID 16"},
            {"id": 17, "name": "测试ID 17"},
            {"id": 18, "name": "测试ID 18"},
            {"id": 19, "name": "测试ID 19"},
            {"id": 20, "name": "测试ID 20"}
        ]
        
        for test_info in test_ids:
            test_id = test_info["id"]
            test_name = test_info["name"]
            print(f"\n🔍 --- {test_name} ---")
            
            api_path = '/api.php/api/navigation/theme'
            params = {"id": test_id, "sort": "new", "theme": "", "page": "1"}
            print(f"🔍 测试ID {test_id}")
            
            response_data = sp.make_api_request(api_path, params)
            if response_data:
                print(f"🔍 ✅ ID {test_id} 有数据")
                if isinstance(response_data, dict):
                    data_section = response_data.get('data', {})
                    if isinstance(data_section, dict):
                        list_data = data_section.get('list', [])
                        total_videos = 0
                        for block in list_data[:3]:
                            if isinstance(block, dict):
                                sub_list = block.get('list', [])
                                total_videos += len(sub_list)
                        print(f"🔍   ID {test_id} 约 {total_videos} 个视频")
                        
                        # 获取第一个视频的标题来判断内容类型
                        if list_data and isinstance(list_data[0], dict):
                            first_block = list_data[0]
                            sub_list = first_block.get('list', [])
                            if sub_list and isinstance(sub_list[0], dict):
                                first_video = sub_list[0]
                                title = first_video.get('title', '')
                                print(f"🔍   示例标题: {title[:50]}...")
            else:
                print(f"🔍 ❌ ID {test_id} 无数据")

        print("\n🔍 ===== 测试详情页 =====")
        # 直接测试详情页，避免获取视频列表时的SSL错误
        print("🔍 直接测试详情页...")
        # 使用一个固定的视频ID来测试
        test_video_id = "119206"
        print(f"🔍 使用视频ID: {test_video_id}")
        
        detail_result = sp.detailContent([test_video_id])  # 详情
        print(f"🔍 详情页结果: {detail_result}")
        
        # 从详情页获取播放地址来测试播放
        if detail_result and detail_result.get('list'):
            vod_data = detail_result['list'][0]
            vod_play_url = vod_data.get('vod_play_url', '')
            if vod_play_url:
                print(f"🔍 获取到播放地址: {vod_play_url}")
                
                # 解析播放地址格式: 正片$119206_dm_https://long.lbfeil.cn/static/...
                if '$' in vod_play_url:
                    parts = vod_play_url.split('$')
                    if len(parts) >= 2:
                        play_title = parts[0]  # 正片
                        play_id = parts[1]     # 119206_dm_https://...
                        print(f"🔍 播放标题: {play_title}")
                        print(f"🔍 播放ID: {play_id}")
                        
                        # 测试播放内容
                        print("🔍 测试播放内容...")
                        player_result = sp.playerContent("51吸瓜", play_id, [])
                        print(f"🔍 播放结果: {player_result}")
                    else:
                        print("❌ 播放地址格式错误")
                else:
                    print("❌ 播放地址中没有$分隔符")
            else:
                print("❌ 详情页没有播放地址")
        else:
            print("❌ 详情页数据为空")
                
        # formatJo = sp.playerContent("", '/mp4/20241104/645364799885189120/58/3d3cd5b932b3fa9ce5746ff5f7985457.mp4', {})  # 播放
        # formatJo = sp.playerContent("阿里4k", '/play/272539-32-1821406.html', {})  # 播放

        # 测试分页和过滤功能
        print("\n🔍 测试分页功能...")
        # 测试分类内容第1页
        category_result_1 = sp.categoryContent('1', '1', True, {})
        print(f"🔍 分类第1页结果: {len(category_result_1.get('list', []))} 个视频")
        print(f"🔍 分页信息: page={category_result_1.get('page')}, pagecount={category_result_1.get('pagecount')}")
        
        # 测试分类内容第2页
        category_result_2 = sp.categoryContent('1', '2', True, {})
        print(f"🔍 分类第2页结果: {len(category_result_2.get('list', []))} 个视频")
        
        print("\n🔍 测试过滤功能...")
        # 测试带过滤的分类内容
        category_filtered = sp.categoryContent('1', '1', True, {'series_id': '220'})
        print(f"🔍 过滤结果: {len(category_filtered.get('list', []))} 个视频")
        
        print("\n🔍 测试搜索分页...")
        # 测试搜索第1页
        search_result_1 = sp.searchContent("熟女", False, '1')
        print(f"🔍 搜索第1页: {len(search_result_1.get('list', []))} 个视频")
        print(f"🔍 搜索分页信息: page={search_result_1.get('page')}, pagecount={search_result_1.get('pagecount')}")
        
        # 测试搜索第2页
        search_result_2 = sp.searchContent("熟女", False, '2')
        print(f"🔍 搜索第2页: {len(search_result_2.get('list', []))} 个视频")

        # 测试图片代理
        test_url = "https://new.phwpqw.cn/new/xiao/20220705/2022070517502716393.jpeg"
        print(f"🔍 测试URL: {test_url}")
        
        # 手动Base64编码测试URL
        import base64
        encoded_url = base64.b64encode(test_url.encode('utf-8')).decode('utf-8')
        print(f"🔍 编码后的URL: {encoded_url}")
        
        # formatJo = sp.localProxy({"url": encoded_url}) # 本地代理
        
        # 测试详情页
        formatJo = sp.detailContent(['119206'])  # 详情
        #  formatJo = sp.gettoken()
        print(formatJo)

        '''
        
        '''

    except Exception as erro:
        print(erro)
    finally:
        event.set()
        try:
            get('http://127.0.0.1:9978/cache?do=none')
        except:
            pass

if __name__ == '__main__':
    """
    run(PY爬虫文件名, 是否启用本地代理)
    再去run函数中修改函数参数
    """
    run('51西瓜', True)

 
 

# 🌐 API URL: https://sapi03.eihpijd.xyz/api.php/api/navigation/index
# 📦 请求参数:

# 'oauth_id': '9951eb738d87ce3f4bb3cfe2ce614113', 'version': '4.2.0', 'build_affcode': 'gw', 'token': '', 'theme': '', 'type': '1'}




