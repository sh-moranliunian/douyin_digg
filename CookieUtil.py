from http.cookies import SimpleCookie

class CookieUtil:

    @staticmethod
    def cookies(session_cookies, lastest_cookie):
        old_cookies = CookieUtil.cookies_from_headers(session_cookies)
        CookieUtil.merge_cookies(old_cookies, lastest_cookie)
        return old_cookies

    @staticmethod
    def cookies_from_headers(session_cookies):
        cookies = {}
        for i in session_cookies:
            cookies[i.name.strip()] = i.value.strip()

        return cookies

    @staticmethod
    def cookies_to_string(cookies):
        return "; ".join([f"{key}={value}" for key, value in cookies.items()])

    @staticmethod
    def merge_cookies(old_cookies, new_cookies):
        for key, value in old_cookies.items():
            new_cookies.setdefault(key, value)

    @staticmethod
    def cookies_to_dict(cookie_str):
        cookie_dict = {}
        pairs = cookie_str.split('; ')

        for pair in pairs:
            key_value = pair.split('=', 1)  # 只分割第一个 '='
            if len(key_value) == 2:
                cookie_dict[key_value[0]] = key_value[1]

        return cookie_dict

