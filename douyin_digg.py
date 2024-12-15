import requests
import base64
import json
import time
import random
from urllib import parse
from fake_useragent import UserAgent

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from CookieUtil import CookieUtil

def get_file_content(file_path):
    with open(file_path, 'r') as file:
        file_content = file.read()
    return file_content.strip()

def get_ms_token(randomlength=176):
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789='
    length = len(base_str) - 1
    for _ in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str

def get_req_sign(t, k):
    private_key = load_pem_private_key(k.encode(), password=None, backend=default_backend())
    signature = private_key.sign(
        t.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    back = base64.b64encode(signature).decode('utf-8')
    return back

def get_bd_client_data(ticket, ts, privateKey, current_time):
    path = "/aweme/v1/web/commit/item/digg/"

    timestamp_str = str(current_time)
    t = f"ticket={ticket}&path={path}&timestamp={timestamp_str}"
    req_sign = get_req_sign(t, privateKey)

    data = {
        'ts_sign': ts,
        "req_content": "ticket,path,timestamp",
        'req_sign': req_sign,
        'timestamp': current_time
    }

    data_json_str = json.dumps(data, separators=(',', ':'))
    return base64.b64encode(data_json_str.encode('utf-8'))

def get_ree_public_key(cookie_content):
    cookie_dict = CookieUtil.cookies_to_dict(cookie_content)
    bd_client_data = cookie_dict['bd_ticket_guard_client_data']
    print("bd_client_data:\n", bd_client_data)
    url_decoded_string = parse.unquote(bd_client_data)
    print("decoded_string:\n", url_decoded_string)
    byte_string = base64.b64decode(url_decoded_string)
    # 将字节对象解码为原始字符串
    decoded_string = byte_string.decode('utf-8')
    jsonObj = json.loads(decoded_string)
    return jsonObj['bd-ticket-guard-ree-public-key']

def dig_video(user_agent, cookie_content, aweme_id, ticket, ts, private_key):
    current_time = int(time.time())
    bd_data = get_bd_client_data(ticket, ts, private_key, current_time)
    ree_public_key = get_ree_public_key(cookie_content)
    print("bd_data:\n", bd_data)
    print("ree_public_key: \n", ree_public_key)

    headers = {
        'bd-ticket-guard-client-data': bd_data,
        'bd-ticket-guard-iteration-version': '1',
        'bd-ticket-guard-ree-public-key': ree_public_key,
        'bd-ticket-guard-version': '2',
        'bd-ticket-guard-web-version': "2" if ticket.startswith("hash.") else "1",
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'cookie': cookie_content,
        'origin': 'https://www.douyin.com',
        'referer': f'https://www.douyin.com/video/{aweme_id}',
        'user-agent': user_agent,
        'x-secsdk-csrf-token': 'DOWNGRADE',
    }

    params = {
        'device_platform': 'webapp',
        'aid': '6383',
        'channel': 'channel_pc_web',
        'pc_client_type': '1',
        'msToken': get_ms_token(),
        'a_bogus': get_ms_token(44)
    }

    data = {
        'aweme_id': aweme_id,
        'item_type': '0',
        'type': '1',
    }

    response = requests.post('https://www.douyin.com/aweme/v1/web/commit/item/digg/', params=params, headers=headers,data=data)
    print("dig_video: \n", response.text)

if __name__ == "__main__":
    ua = UserAgent(platforms=['pc'], os=["windows", "macos"])
    user_agent = ua.chrome

    cookie_file_name = f"cookie.txt"
    cookie_content = get_file_content(cookie_file_name)

    # 以下三个参数在登录抖音后从浏览器的local storage中获取，获取方式如下:
    # JSON.parse(JSON.parse(window.localStorage['security-sdk/s_sdk_crypt_sdk'])['data'])['ec_privateKey']
    # JSON.parse(JSON.parse(window.localStorage['security-sdk/s_sdk_sign_data_key/web_protect'])['data'])['ts_sign']
    # JSON.parse(JSON.parse(window.localStorage['security-sdk/s_sdk_sign_data_key/web_protect'])['data'])['ticket']

    ticket = "XXXXX"
    ts = "XXXXX"
    private_key = "XXXXX"

    aweme_id = "7433373109639548214"

    dig_video(user_agent, cookie_content, aweme_id, ticket, ts, private_key)